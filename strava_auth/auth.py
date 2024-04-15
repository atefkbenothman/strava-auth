import json
import os
import time
import urllib.parse

import requests

from strava_auth.logger import get_logger
from strava_auth.login import StravaWebLoginFlow


class StravaAuthenticationError(Exception):
  pass


class StravaAuthenticator:
  DEFAULT_SCOPES = "read,activity:read"
  AUTHORIZE_BASE_URL = "https://www.strava.com/oauth/authorize"
  AUTHORIZE_RESPONSE_TYPE = "code"
  AUTHORIZE_APPROVAL_PROMPT = "force"
  AUTHORIZE_REDIRECT_URI = "http://localhost:9191/"  # set a random url to redirect to
  EXCHANGE_BASE_URL = "https://www.strava.com/oauth/token"
  EXCHANGE_GRANT_TYPE = "authorization_code"
  REFRESH_GRANT_TYPE = "refresh_token"

  def __init__(
    self, client_id: str, client_secret: str, required_scopes: str | None = None, log_level: str | None = None, cache_file: str = "strava-auth-cache.json"
  ):
    self.client_id = client_id
    self.client_secret = client_secret
    self.required_scopes = required_scopes if required_scopes else self.DEFAULT_SCOPES
    self.access_token: str | None = None
    self.expires_at: int | None = None
    self.refresh_token: str | None = None
    self.athlete: dict | None = None
    self.log_level = log_level
    self.logger = get_logger(log_level)
    self.cache_file = cache_file

  def save_to_cache(self, file_name: str, access_token: str, refresh_token: str, expires_at: int, athlete: dict) -> None:
    """
    Save the access and refresh tokens into a file.
    """
    self.logger.info("Saving tokens to cache")
    cache_data = {"access_token": access_token, "refresh_token": refresh_token, "expires_at": expires_at, "athlete": athlete}
    try:
      with open(file_name, "w") as f:
        json.dump(cache_data, f, indent=2)
    except IOError as e:
      self.logger.error(f"Error saving tokens to cache: {e}")

  def load_from_cache(self, file_name: str) -> bool:
    """
    Load tokens from cache if cache file exists.
    """
    if os.path.exists(file_name):
      try:
        with open(file_name, "r") as f:
          cache_data = json.load(f)
          access_token = cache_data.get("access_token", None)
          refresh_token = cache_data.get("refresh_token", None)
          athlete = cache_data.get("athlete", None)
          expires_at = cache_data.get("expires_at", None)

          if time.time() < expires_at:
            self.access_token = access_token
            self.refresh_token = refresh_token
            self.athlete = athlete
            self.expires_at = expires_at
            return True

          else:
            self.logger.info("Access token has expired. Refreshing new token")
            try:
              # token has expired, use refresh token to get new access token
              data = self.refresh_access_token(self.client_id, self.client_secret, refresh_token)
            except StravaAuthenticationError as e:
              self.logger.error(e)
              return False
            else:
              access = data.get("access_token", None)
              expires = data.get("expires_at", None)
              refresh = data.get("refresh_token", None)

              self.access_token = access
              self.refresh_token = refresh
              self.expires_at = expires_at
              self.athlete = athlete

              # cache the tokens
              self.save_to_cache(self.cache_file, access, refresh, expires, athlete)
              return True

      except (IOError, ValueError) as e:
        self.logger.error(f"Error loading cached tokens: {e}")

    return False

  def set_required_scopes(self, scopes: str) -> str:
    """
    Set the required scopes need to use the application.
    """
    if scopes == "":
      raise ValueError("scope must not be empty")
    self.required_scopes = scopes
    return self.required_scopes

  def generate_strava_authorize_url(self, client_id: str, required_scopes: str) -> str:
    """
    Generate the authorization url used to authenticate to Strava.
    """
    self.logger.info("Generating Strava authorization url")

    self.logger.debug(f"{client_id=}")
    self.logger.debug(f"{required_scopes=}")

    if client_id == "" or required_scopes == "" or " " in client_id or " " in required_scopes:
      raise ValueError("client_id and required_scopes cannot be empty and cannot contain spaces")

    params = {
      "client_id": client_id,
      "response_type": self.AUTHORIZE_RESPONSE_TYPE,
      "redirect_uri": self.AUTHORIZE_REDIRECT_URI,
      "approval_prompt": self.AUTHORIZE_APPROVAL_PROMPT,
      "scope": required_scopes,
    }
    queries = urllib.parse.urlencode(params)
    authorization_url = f"{self.AUTHORIZE_BASE_URL}?{queries}"

    self.logger.debug(f"{authorization_url=}")

    return authorization_url

  def extract_code_and_scope(self, authorization_response_url: str) -> tuple[str, str]:
    """
    Extract the code and scope query params from the returned url.
    """
    self.logger.info("Extracting code and scope from query params")

    self.logger.debug(f"{authorization_response_url=}")

    if authorization_response_url == "" or authorization_response_url.split("?")[0] != self.AUTHORIZE_REDIRECT_URI:
      raise ValueError("authorization_response_url must not be empty and must not be different than the default redirect uri")

    parsed_url = urllib.parse.urlparse(authorization_response_url)
    query_dict = urllib.parse.parse_qs(parsed_url.query)

    code = query_dict.get("code", None)
    scope = query_dict.get("scope", None)

    if code is None or scope is None:
      raise StravaAuthenticationError(f"Failed to extract code and/or scope from the authorization response url: {authorization_response_url,}")

    self.logger.debug(f"{code=}")
    self.logger.debug(f"{scope=}")

    return code[0], scope[0]

  def check_valid_scope(self, scope: str) -> bool:
    """
    Check if a scope is formatted correctly.
    """
    if not scope or "," not in scope:
      return False

    parts = scope.split(",")

    for scp in parts:
      if not scp.strip():
        return False
      if not all(c.isalnum() or c in ("_", ":") for c in scp):
        return False

    return True

  def verify_granted_scopes(self, required_scopes: str, granted_scopes: str) -> bool:
    """
    Verify that the athlete granted the required scopes.
    """
    self.logger.info("Verifying granted scopes")

    self.logger.debug(f"{required_scopes=}")
    self.logger.debug(f"{granted_scopes=}")

    if not self.check_valid_scope(required_scopes) or not self.check_valid_scope(granted_scopes):
      raise ValueError("Scope is not valid")

    valid = all(req_scope in granted_scopes.split(",") for req_scope in required_scopes.split(","))

    if not valid:
      raise StravaAuthenticationError(f"The athlete did not grant the required scopes. Granted scopes: {granted_scopes}")

    self.logger.info("Verified scopes")

    return True

  def exchange_token(self, client_id: str, client_secret: str, authorization_code: str) -> dict:
    """
    Exchange the authorization code for an access token.
    Also return the athlete object.
    """
    self.logger.info("Exchanging authorization code for access token")
    self.logger.debug(f"{authorization_code=}")

    params = {"client_id": client_id, "client_secret": client_secret, "code": authorization_code, "grant_type": self.EXCHANGE_GRANT_TYPE}
    res = requests.post(self.EXCHANGE_BASE_URL, params=params)

    if res.status_code != 200:
      raise StravaAuthenticationError(f"Error exchanging authorization code for access token: {res.status_code} {res.json()}")

    data = res.json()

    self.logger.debug(f"Exchange token response: {data}")

    if data.get("access_token", None) is None:
      raise StravaAuthenticationError(f"Could not extract access token and/or athlete from response: {data}")

    return data

  def refresh_access_token(self, client_id: str, client_secret: str, refresh_token: str) -> dict:
    """
    Refresh the access token using the refresh token.
    """
    self.logger.info("Refreshing access token")

    params = {"client_id": client_id, "client_secret": client_secret, "grant_type": self.REFRESH_GRANT_TYPE, "refresh_token": refresh_token}
    res = requests.post(self.EXCHANGE_BASE_URL, params=params)

    if res.status_code != 200:
      raise StravaAuthenticationError(f"Error refreshing access token using refresh token: {res.status_code} {res.json()}")

    data = res.json()

    self.logger.debug(f"Refresh token response: {data}")

    if data.get("access_token", None) is None:
      raise StravaAuthenticationError(f"Could not extract access token and/or athlete from response: {data}")

    return data

  def authenticate(self, email: str, password: str) -> tuple[str | None, dict | None]:
    """
    Complete the entire Srava OAuth2 flow.
    """
    print("Authenticating with Strava...")
    self.logger.debug(f"Logging set to {self.log_level}")

    # check if cache exists. if it does, read from cache
    if self.load_from_cache(self.cache_file):
      print("Loaded access token from cache")
      return self.access_token, self.athlete

    try:
      # 1. generate authorizaton url
      authorization_url = self.generate_strava_authorize_url(self.client_id, self.required_scopes)

      # 2. authenticate using email and password
      headless = self.log_level != "DEBUG"
      web_login = StravaWebLoginFlow(authorization_url, headless=headless, logger=self.logger)
      authorization_response_url = web_login.login(email, password)

      if authorization_response_url is None:
        raise StravaAuthenticationError("Could not login to Strava using Selenium. Set log_level='DEBUG' to run Selenium in non-headless mode")

      # 3. extract code and scope
      authorization_code, granted_scopes = self.extract_code_and_scope(authorization_response_url)

      # 4. verify granted scopes authorized by athlete
      self.verify_granted_scopes(self.required_scopes, granted_scopes)

      # 5. exchange authorization code for access token
      data = self.exchange_token(self.client_id, self.client_secret, authorization_code)

      access_token = data.get("access_token", None)
      athlete = data.get("athlete", None)
      refresh_token = data.get("refresh_token", None)
      expires_at = data.get("expires_at", None)

      if access_token is None or athlete is None or refresh_token is None or expires_at is None:
        raise StravaAuthenticationError("Could not extract tokens from Strava api response")

      self.access_token = access_token
      self.refresh_token = refresh_token
      self.expires_at = expires_at
      self.athlete = athlete

      # 6. cache the tokens
      self.save_to_cache(self.cache_file, access_token, refresh_token, expires_at, athlete)

    except StravaAuthenticationError as e:
      self.logger.error(str(e))
      return None, None

    else:
      print("Succesfully authenticated")

      self.logger.debug(f"{access_token=}")
      self.logger.debug(f"{refresh_token=}")
      self.logger.debug(f"{expires_at=}")
      self.logger.debug(f"{athlete=}")

      return self.access_token, self.athlete

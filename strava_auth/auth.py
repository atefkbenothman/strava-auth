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

  def __init__(self, client_id: str, client_secret: str, required_scopes: str | None = None, log_level: str | None = None):
    self.client_id = client_id
    self.client_secret = client_secret
    self.required_scopes = required_scopes if required_scopes else self.DEFAULT_SCOPES
    self.access_token: str | None = None
    self.athlete: dict | None = None
    self.log_level = log_level
    self.logger = get_logger(log_level)

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

  def exchange_token(self, client_id: str, client_secret: str, authorization_code: str) -> tuple[str, dict]:
    """
    Exchange the authorization code for an access token.
    Also return the athlete object.
    """
    self.logger.info("Exchanging authorization code for access token")
    self.logger.debug(f"{authorization_code=}")

    params = {"client_id": client_id, "client_secret": client_secret, "code": authorization_code, "grant_type": self.EXCHANGE_GRANT_TYPE}
    res = requests.post(self.EXCHANGE_BASE_URL, params=params)

    if res.status_code != 200:
      raise StravaAuthenticationError("Error exchanging authorization code for access token")

    data = res.json()

    self.logger.debug(f"Exchange API response data={data}")

    access_token = data.get("access_token", None)
    athlete: dict = data.get("athlete", None)

    if access_token is None or athlete is None:
      raise StravaAuthenticationError(f"Could not extract access token and/or athlete from response: {data}")

    return access_token, athlete

  def authenticate(self, email: str, password: str) -> tuple[str | None, dict | None]:
    """
    Complete the entire Srava OAuth2 flow.
    """
    self.logger.debug(f"Logging set to {self.log_level}")
    self.logger.info("Authenticating with Strava...")

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
      access_token, athlete = self.exchange_token(self.client_id, self.client_secret, authorization_code)

    except StravaAuthenticationError as e:
      self.logger.error(str(e))
      return None, None

    else:
      self.access_token = access_token
      self.athlete = athlete

      self.logger.info("Succesfully authenticated")

      self.logger.debug(f"{access_token=}")
      self.logger.debug(f"{athlete=}")

      return self.access_token, self.athlete

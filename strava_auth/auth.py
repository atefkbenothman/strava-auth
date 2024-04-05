import urllib.parse

import requests

from strava_auth.login import login


class StravaAuthenticationError(Exception):
  pass


class StravaAuthenticator:
  DEFAULT_SCOPES = "read,activity:read"

  AUTHORIZE_BASE_URL = "https://www.strava.com/oauth/authorize"
  AUTHORIZE_RESPONSE_TYPE = "code"
  AUTHORIZE_APPROVAL_PROMPT = "force"
  AUTHORIZE_REDIRECT_URI = "http://localhost:9191"  # choose a random url to redirect to

  EXCHANGE_BASE_URL = "https://www.strava.com/oauth/token"
  EXCHANGE_GRANT_TYPE = "authorization_code"

  def __init__(self, client_id: str, client_secret: str, required_scopes: str | None = None):
    self.client_id = client_id
    self.client_secret = client_secret
    self.required_scopes = required_scopes if required_scopes else self.DEFAULT_SCOPES
    self.access_token: str | None = None
    self.athlete: dict | None = None

  def set_required_scopes(self, scopes: str) -> str:
    """
    Set the required scopes need to use the application.
    """
    self.required_scopes = scopes
    return self.required_scopes

  def generate_strava_authorize_url(self, client_id: str, required_scopes: str) -> str:
    """
    Generate the authorization url used to authenticate to Strava.
    """
    print("generating strava authorization url...")

    params = {
      "client_id": client_id,
      "response_type": self.AUTHORIZE_RESPONSE_TYPE,
      "redirect_uri": self.AUTHORIZE_REDIRECT_URI,
      "approval_prompt": self.AUTHORIZE_APPROVAL_PROMPT,
      "scope": required_scopes,
    }
    queries = urllib.parse.urlencode(params)

    return self.AUTHORIZE_BASE_URL + "?" + queries

  def extract_code_and_scope(self, authorization_response_url: str) -> tuple[str, str]:
    """
    Extract the code and scope query params from the returned url.
    """
    print("extracting code and scope from query params...")

    parsed_url = urllib.parse.urlparse(authorization_response_url)
    query_dict = urllib.parse.parse_qs(parsed_url.query)

    code = query_dict.get("code", None)
    scope = query_dict.get("scope", None)

    if code is None or scope is None:
      raise StravaAuthenticationError(f"Failed to extract code and/or scope from the authorization response url: {authorization_response_url}")

    return code[0], scope[0]

  def verify_granted_scopes(self, required_scopes: str, granted_scopes: str) -> None:
    """
    Verify that the athlete granted the required scopes.
    """
    print("verifying granted scopes...")

    valid = all(req_scope in granted_scopes.split(",") for req_scope in required_scopes.split(","))

    if not valid:
      raise StravaAuthenticationError(f"The athlete did not grant the required scopes. Granted scopes: {granted_scopes}")

    return

  def exchange_token(self, client_id: str, client_secret: str, authorization_code: str) -> tuple[str, dict]:
    """
    Exchange the authorization code for an access token.
    Also return the athlete object.
    """
    print("exchanging authorization code for access token...")

    params = {"client_id": client_id, "client_secret": client_secret, "code": authorization_code, "grant_type": self.EXCHANGE_GRANT_TYPE}
    res = requests.post(self.EXCHANGE_BASE_URL, params=params)

    if res.status_code != 200:
      raise StravaAuthenticationError("Error exchanging authorization code for access token")

    data = res.json()

    access_token = data.get("access_token", None)
    athlete: dict = data.get("athlete", None)

    if access_token is None or athlete is None:
      raise StravaAuthenticationError(f"Could not extract access token and/or athlete from response: {data}")

    return access_token, athlete

  def authenticate(self, email: str, password: str) -> tuple[str | None, dict | None]:
    """
    Complete the entire Srava OAuth2 flow.
    """
    print("begin authenticating...")

    # 1. generate authorizaton url
    authorization_url = self.generate_strava_authorize_url(self.client_id, self.required_scopes)

    # 2. authenticate using email and password
    authorization_response_url = login(authorization_url, email, password)

    # 3. extract code and scope
    authorization_code, granted_scopes = self.extract_code_and_scope(authorization_response_url)

    # 4. verify granted scopes authorized by athlete
    self.verify_granted_scopes(self.required_scopes, granted_scopes)

    # 5. exchange authorization code for access token
    access_token, athlete = self.exchange_token(self.client_id, self.client_secret, authorization_code)

    self.access_token = access_token
    self.athlete = athlete

    print("succesfully authenticated!")

    return self.access_token, self.athlete

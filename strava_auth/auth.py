import urllib.parse

import requests

from strava_auth.login import login


def generate_strava_authorize_url(client_id: str, required_scopes: str) -> str:
  """
  Generate the authorization url to authenticate with Strava.
  """
  print("generating strava authorization url...")
  base_url = "https://www.strava.com/oauth/authorize"
  redirect_uri = "http://localhost:9191"  # choose a random url to redirect to
  response_type = "code"
  approval_prompt = "force"
  params = {
    "client_id": client_id,
    "response_type": response_type,
    "redirect_uri": redirect_uri,
    "approval_prompt": approval_prompt,
    "scope": required_scopes,
  }
  queries = urllib.parse.urlencode(params)
  return f"{base_url}?{queries}"


def retrieve_authorization_url(
  authorization_url: str, email: str, password: str
) -> str:
  """
  Authenticate using credentials and retrieve redirected authorization url.
  """
  print("retrieving authorzation url...")
  authorization_response_url = login(authorization_url, email, password)
  return authorization_response_url


def extract_code_and_scope(authorization_response_url: str) -> tuple[str, str]:
  """
  Extract the code and and scope query params from the returned url.
  """
  parsed_url = urllib.parse.urlparse(authorization_response_url)
  query_dict = urllib.parse.parse_qs(parsed_url.query)
  code = query_dict.get("code", None)
  scope = query_dict.get("scope", None)
  if code is None or scope is None:
    raise ValueError(
      f"Unable to extract code and scope from: {authorization_response_url}"
    )
  return code[0], scope[0]


def verify_granted_scopes(required_scopes: str, scopes: str) -> None:
  """
  Verify that the athlete granted the required scopes.
  """
  req_scopes = required_scopes.split(",")
  is_valid = all(req_scope in scopes.split(",") for req_scope in req_scopes)
  if not is_valid:
    raise ValueError("The athlete did not grant the required scopes")


def exchange_code_for_token(
  client_id: str, client_secret: str, code: str
) -> tuple[str, dict]:
  """
  Exchange the authorization code for a refresh token and access token.
  """
  base_url = "https://www.strava.com/oauth/token"
  grant_type = "authorization_code"
  params = {
    "client_id": client_id,
    "client_secret": client_secret,
    "code": code,
    "grant_type": grant_type,
  }
  res = requests.post(base_url, params=params)

  if res.status_code != 200:
    raise ValueError("Exchange: response type not 200")

  data = res.json()

  access_token = data.get("access_token", None)
  athlete: dict = data.get("athlete", None)

  if access_token is None or athlete is None:
    raise ValueError("Could not extract access token or athlete")

  return access_token, athlete


def authorize(
  email: str, password: str, client_id: str, client_secret: str, required_scopes: str
) -> tuple[str | None, dict | None]:
  """
  Complete the enitre Strava OAuth2 flow.
  """
  print("Authorizing with Strava...")

  # 1. generate authorization url
  authorization_url = generate_strava_authorize_url(client_id, required_scopes)

  # 2. authenticate using email and password
  authorization_response_url = retrieve_authorization_url(
    authorization_url, email, password
  )

  # 3. extract code and scope
  code, granted_scopes = extract_code_and_scope(authorization_response_url)

  # 4. verify granted scopes authorized by athlete
  verify_granted_scopes(required_scopes, granted_scopes)

  # 5. exchange code for token
  access_token, athlete = exchange_code_for_token(client_id, client_secret, code)

  print("Succesfully authenticated with Strava")

  return access_token, athlete

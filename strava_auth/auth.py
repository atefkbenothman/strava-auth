import urllib.parse

from strava_auth.login import login


def generate_strava_authorize_url(client_id: str, required_scopes: str) -> str:
  """
  Generate the authorization url to authenticate with Strava.
  """
  print("generating strava authorization url...")
  base_url = "https://www.strava.com/oauth/authorize"
  redirect_uri = "http://localhost:9191"  # choose a random url to redirect to
  params = {
    "client_id": client_id,
    "response_type": "code",
    "redirect_uri": redirect_uri,
    "approval_prompt": "force",
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

  print(f"{authorization_response_url=}")

  return "accesstoken", {"athlete": "test"}

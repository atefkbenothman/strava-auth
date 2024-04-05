from strava_auth.auth import StravaAuthenticator


def test_generate_strava_authorize_url_default_scopes():
  client_id = "abc"
  client_secret = "123"
  authenticator = StravaAuthenticator(client_id=client_id, client_secret=client_secret)
  default_scopes = "read,activity:read"
  assert authenticator.required_scopes == default_scopes


def test_generate_strava_authorize_url_custom_scopes():
  client_id = "abc"
  client_secret = "123"
  custom_scopes = "read,profile:read_all"
  authenticator = StravaAuthenticator(
    client_id=client_id, client_secret=client_secret, required_scopes=custom_scopes
  )
  assert authenticator.required_scopes == custom_scopes

from strava_auth.auth import authorize


def test_authorize():
  access_token, athlete = authorize()
  assert access_token == "accesstoken"
  assert athlete["athlete"] == "test"

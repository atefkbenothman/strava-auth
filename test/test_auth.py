from strava_auth.auth import authorize


def test_authorize():
  access_token, athlete = authorize("123", "123", "123", "123", "123")
  assert access_token == "accesstoken"
  assert athlete["athlete"] == "test"

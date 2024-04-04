import unittest

from strava_auth.auth import authorize


class TestAuth(unittest.TestCase):
  def test_authorize(self):
    access_token, athlete = authorize()
    assert access_token == "accesstoken"
    assert athlete["athlete"] == "test"


if __name__ == "__main__":
  unittest.main()

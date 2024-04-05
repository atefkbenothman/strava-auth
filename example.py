#!/usr/bin/env python3.11
import os

import requests

from strava_auth.auth import authorize

email = os.getenv("STRAVA_AUTH_EMAIL")
password = os.getenv("STRAVA_AUTH_PASSWORD")
client_id = os.getenv("STRAVA_AUTH_CLIENT_ID")
client_secret = os.getenv("STRAVA_AUTH_CLIENT_SECRET")

access_token, athlete = authorize()

if access_token is None or athlete is None:
  print("Could not authenticate with Strava. Set verbose to True to get more info.")
  exit(0)

print(f"{access_token=}")
print(f"{athlete=}")

headers = {"Authorization": "Bearer " + access_token}
res = requests.get("https://www.strava.com/api/v3/athlete/activities", headers=headers)
data = res.json()
print(f"{data=}")

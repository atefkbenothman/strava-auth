#!/usr/bin/env python3.11
import os

import requests
from dotenv import load_dotenv

from strava_auth.auth import authorize

load_dotenv()

email = os.getenv("STRAVA_AUTH_EMAIL")
password = os.getenv("STRAVA_AUTH_PASSWORD")
client_id = os.getenv("STRAVA_AUTH_CLIENT_ID")
client_secret = os.getenv("STRAVA_AUTH_CLIENT_SECRET")

required_scopes = "read_all,activity:read_all,profile:read_all"

access_token, athlete = authorize(
  email=email,
  password=password,
  client_id=client_id,
  client_secret=client_secret,
  required_scopes=required_scopes,
)

if access_token is None or athlete is None:
  print("Could not authenticate with Strava. Set verbose to True to get more info.")
  exit(0)

athlete_id = athlete["id"]
athlete_name = athlete["firstname"] + athlete["lastname"]

print(f"{access_token=}")
print(f"{athlete=}")

# headers = {"Authorization": "Bearer " + access_token}
# res = requests.get("https://www.strava.com/api/v3/athlete/activities", headers=headers)
# data = res.json()
# print(f"{data=}")

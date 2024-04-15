#!/usr/bin/env python3.11
import os

import requests
from dotenv import load_dotenv

from strava_auth.auth import StravaAuthenticator

# Setup environment variables
load_dotenv()

email = os.getenv("STRAVA_AUTH_EMAIL")
password = os.getenv("STRAVA_AUTH_PASSWORD")
client_id = os.getenv("STRAVA_AUTH_CLIENT_ID")
client_secret = os.getenv("STRAVA_AUTH_CLIENT_SECRET")

if email is None or password is None or client_id is None or client_secret is None:
  print("Environment variables not set properly.")
  exit(0)

# Set required scopes for your application
# Read more here: https://developers.strava.com/docs/authentication/
required_scopes = "read_all,activity:read_all,profile:read_all"

# Authenticate
authenticator = StravaAuthenticator(client_id, client_secret, required_scopes=required_scopes, log_level="INFO", cache_file="strava-auth-cache.json")
access_token, athlete = authenticator.authenticate(email, password)

if access_token is None or athlete is None:
  # could not authenticate with Strava. Set log_level="DEBUG" in StravaAuthenticator to get more info
  exit(0)

# Debug
print(f"{access_token=}")
print(f"{athlete=}")

# Make requests to Strava's API
headers = {"Authorization": "Bearer " + access_token, "Content-Type": "application/json"}
res = requests.get("https://www.strava.com/api/v3/athlete/activities", headers=headers)
activities = res.json()
print(f"Num activities: {len(activities)}")

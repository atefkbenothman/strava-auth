# Strava-Auth
![Unit Tests](https://github.com/atefkbenothman/strava-auth/actions/workflows/test.yaml/badge.svg)

Streamline the Strava OAuth2 flow with Selenium, allowing developers to quickly and easily integrate Strava's API into their applications.

**Disclaimer:** For personal use only!


## How does it work?

* User inputs email, password, client_id, and client_secret into a `.env` file
* Behind the scenes, the program uses Selenium to launch a web browser to navigate to the Strava authorization page
* Selenium automatically inputs email and password into the login form
* Program handles the oauth2 code exchange processs
* Returns the newly generated access token and athlete object
* Developers can now use the Strava API with the provided access token

## Installation
```bash
pip install -i https://test.pypi.org/simple/ strava-auth
```

## Example
```python
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

# Set required scopes for your application
# Read more here: https://developers.strava.com/docs/authentication/
required_scopes = "read_all,activity:read_all,profile:read_all"

# Authenticate
authenticator = StravaAuthenticator(client_id, client_secret, required_scopes=required_scopes)
access_token, athlete = authenticator.authenticate(email, password)

if access_token is None or athlete is None:
  print("could not authenticate with strava. set verbose to true to get more info.")
  exit(0)

# Debug
print(f"{access_token=}")
print(f"{athlete=}")
print(f"{authenticator.access_token=}")
print(f"{authenticator.athlete=}")

# Make requests to Strava's API
headers = {"Authorization": "Bearer " + access_token, "Content-Type": "application/json"}
res = requests.get("https://www.strava.com/api/v3/athlete/activities", headers=headers)
activities = res.json()
print(f"num activities: {len(activities)}")
```

## Local Development
1. Clone repository
```bash
git clone https://github.com/atefkbenothman/strava-auth.git
```
2. Setup virtual environment
```bash
python -m venv venv
source venv/bin/activate
```
3. Install dependencies
```bash
pip install -r requirements.txt
```
4. Create a `.env` file with the following secrets:
  * `STRAVA_AUTH_EMAIL`
  * `STRAVA_AUTH_PASSWORD`
  * `STRAVA_AUTH_CLIENT_ID`
  * `STRAVA_AUTH_CLIENT_SECRET`
5. Start making changes to the project!

## Running Tests
Run tests locally using pytest:
```bash
pytest test/test_auth.py            # just the 'auth' suite
pytest --cov=strava_auth test/      # whole test suite
```
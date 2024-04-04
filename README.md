# Strava-Auth

**Disclaimer: For personal use only!**

Streamline the Strava OAuth2 flow with Selenium, allowing developers to quickly and easily integrate Strava's API into their applications.


## How does it work?

* User inputs email, password, client_id, and client_secret into a `.env` file
* Behind the scenes, the program uses Selenium to launch a web browser to navigate to the Strava authorization page
* Selenium automatically inputs email and password into the login form
* Program handles the oauth2 code exchange processs
* Returns the newly generated access token and athlete object
* Developers can now use the Strava API with the provided access token


## Usage
```python
from strava_auth import authorize

email         = os.getenv("STRAVA_AUTH_EMAIL")
password      = os.getenv("STRAVA_AUTH_PASSWORD")
client_id     = os.getenv("STRAVA_AUTH_CLIENT_ID")
client_secret = os.getenv("STRAVA_AUTH_CLIENT_SECRET")

access_token, athlete = authorize(email, password, client_id, client_secret, verbose=True)

# can now start calling the strava api
headers = {
  "Authorizaion": "Bearer " + access_token
}
res = requests.get("https://www.strava.com/api/v3/athlete/activities", headers=headers)
data = res.json()
```

## Local Development
1. Create a `.env` file with the following secrets:
  * `STRAVA_AUTH_EMAIL`
  * `STRAVA_AUTH_PASSWORD`
  * `STRAVA_AUTH_CLIENT_ID`
  * `STRAVA_AUTH_CLIENT_SECRET`
2. Install all dependencies: `pip3 install -r requirements.txt`
import chromedriver_autoinstaller
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class StravaWebLoginFlow:
  EMAIL_ELEMENT_ID = "email"
  PASSWORD_ELEMENT_ID = "password"
  LOGIN_BUTTON_ID = "login-button"
  AUTHORIZE_BUTTON_ID = "authorize"

  def __init__(self, authorization_url: str):
    self.authorization_url = authorization_url

  def login(self, email: str, password: str) -> str | None:
    """
    Automatically input the athlete's email and password into Strava's web login form.
    Copy the redirected authorization url that holds the 'code' and 'scope' query params.

    :return: The redirected authorization url
    """
    print("DEBUG::Logging in with Selenium.")

    # Install Chromedriver if it does not already exist
    chromedriver_autoinstaller.install()

    # Set options
    options = Options()
    # options.add_argument("--headless")
    # options.add_argument("--disable-dev-shm-usage")

    try:
      driver = webdriver.Chrome(options=options)

      driver.get(self.authorization_url)

      # Enter email and password into textbox
      print("DEBUG::Inputting email and password into textbox.")
      email_input = driver.find_element(By.ID, self.EMAIL_ELEMENT_ID)
      password_input = driver.find_element(By.ID, self.PASSWORD_ELEMENT_ID)
      email_input.send_keys(email)
      password_input.send_keys(password)

      # Click Submit
      print("DEBUG::Submitting login form.")
      login_button = driver.find_element(By.ID, self.LOGIN_BUTTON_ID)
      login_button.click()

      # Wait for new redirect page to load
      wait = WebDriverWait(driver, 5)  # wait 10 seconds before timing out
      wait.until(EC.presence_of_element_located((By.ID, self.AUTHORIZE_BUTTON_ID)))

      # Click authorize
      print("DEBUG::Submitting authorize form.")
      authorize_button = driver.find_element(By.ID, self.AUTHORIZE_BUTTON_ID)
      authorize_button.click()

      # Wait for new redirected page to load
      wait = WebDriverWait(driver, 3)

      # Copy the redirect authorization response url
      authorization_response_url = driver.current_url
      print(f"DEBUG::Retrieved authorization response url: {authorization_response_url}")

      print("DEBUG::Succesfully logged in with Selenium.")

      return authorization_response_url

    except (TimeoutException, NoSuchElementException) as e:
      print(f"DEBUG::Error during Strava web login flow: {e}")
      return None

    finally:
      driver.quit()

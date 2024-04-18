import logging

import chromedriver_autoinstaller
from selenium import webdriver
from selenium.common.exceptions import (
  NoSuchElementException,
  TimeoutException,
  WebDriverException,
)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class StravaWebLoginFlow:
  EMAIL_ELEMENT_ID = "email"
  PASSWORD_ELEMENT_ID = "password"
  LOGIN_BUTTON_ID = "login-button"
  AUTHORIZE_BUTTON_ID = "authorize"

  def __init__(
    self,
    authorization_url: str,
    headless: bool = True,
    logger: logging.Logger | None = None,
  ):
    self.authorization_url = authorization_url
    self.headless = headless
    self.logger = logger if logger else logging.getLogger(__name__)

  def login(self, email: str, password: str) -> str | None:
    """
    Automatically input the athlete's email + password into Strava's web login
    form. Copy the redirected authorization url that holds the 'code' and
    'scope' query params.

    :return: The redirected authorization url
    """
    self.logger.info("Logging in with Selenium")

    # Install Chromedriver if it does not already exist
    chromedriver_autoinstaller.install()

    # Set options
    options = Options()
    if self.headless:
      options.add_argument("--headless")
    options.add_argument("--disable-dev-shm-usage")

    try:
      driver = webdriver.Chrome(options=options)

      driver.get(self.authorization_url)

      # Enter email and password into textbox
      self.logger.info("Inputting email and password into textbox")
      email_input = driver.find_element(By.ID, self.EMAIL_ELEMENT_ID)
      password_input = driver.find_element(By.ID, self.PASSWORD_ELEMENT_ID)
      email_input.send_keys(email)
      password_input.send_keys(password)

      # Click Submit
      self.logger.info("Submitting login form")
      login_button = driver.find_element(By.ID, self.LOGIN_BUTTON_ID)
      login_button.click()

      # Wait for new redirect page to load
      wait = WebDriverWait(driver, 5)  # wait 10 seconds before timing out
      wait.until(
        EC.presence_of_element_located((By.ID, self.AUTHORIZE_BUTTON_ID))
      )

      # Click authorize
      self.logger.info("Submitting authorize form")
      authorize_button = driver.find_element(By.ID, self.AUTHORIZE_BUTTON_ID)
      authorize_button.click()

      # Wait for new redirected page to load
      wait = WebDriverWait(driver, 3)

      # Copy the redirect authorization response url
      authorization_response_url = driver.current_url
      self.logger.debug(
        f"Retrieved authorization response url: {authorization_response_url}"
      )

      self.logger.info("Succesfully logged in with Selenium")

      return authorization_response_url

    except (WebDriverException, TimeoutException, NoSuchElementException) as e:
      self.logger.error(f"Error during Strava web login flow: {e}")
      return None

    finally:
      driver.quit()

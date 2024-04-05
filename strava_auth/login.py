import chromedriver_autoinstaller
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def login(authorization_url: str, email: str, password: str) -> str:
  """
  Use the selenium webdriver to automatically input the athlete's email
  and password into the login form.

  :return: The redirected authorization url
  """
  print("logging in...")

  # automatically install chromedriver
  chromedriver_autoinstaller.install()

  options = Options()
  options.add_argument("--headless")
  options.add_argument("--no-sandbox")
  options.add_argument("--disable-dev-shm-usage")

  driver = webdriver.Chrome(options=options)

  print(f"opening url: {authorization_url}")
  driver.get(authorization_url)

  # enter email and password
  print("inputting email and password...")
  email_input = driver.find_element(By.ID, "email")
  email_input.send_keys(email)
  password_input = driver.find_element(By.ID, "password")
  password_input.send_keys(password)

  # click submit
  print("submitting form...")
  submit_button = driver.find_element(By.ID, "login-button")
  submit_button.click()

  # wait for new redirected page to load
  wait = WebDriverWait(driver, 10)
  wait.until(EC.presence_of_element_located((By.ID, "authorize")))

  # click authorize
  print("clicking on authorize...")
  authorize_button = driver.find_element(By.ID, "authorize")
  authorize_button.click()

  wait = WebDriverWait(driver, 3)

  # get authorization response url
  authorization_response_url = driver.current_url
  print(f"auth url: {authorization_response_url}")

  print("done!")

  driver.quit()
  return authorization_response_url

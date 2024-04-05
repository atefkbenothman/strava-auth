import chromedriver_autoinstaller
from selenium import webdriver


def login(authorization_url: str, email: str, password: str) -> str:
  """
  Use the selenium webdriver to automatically input the athlete's email
  and password into the login form.

  :return: The redirected authorization url
  """
  print("logging in...")

  chromedriver_autoinstaller.install()

  driver = webdriver.Chrome()
  driver.get("https://google.com")

  return "abc123"

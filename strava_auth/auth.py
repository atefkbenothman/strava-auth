def authorize() -> tuple[str | None, dict | None]:
  """
  Complete the enitre Strava OAuth2 flow.
  """
  return "accesstoken", {"athlete": "test"}

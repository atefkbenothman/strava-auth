import urllib

import pytest

from strava_auth.auth import StravaAuthenticationError, StravaAuthenticator


@pytest.fixture
def authenticator() -> StravaAuthenticator:
  client_id = "CLIENT_ID"
  client_secret = "CLIENT_SECRET"
  auth = StravaAuthenticator(client_id=client_id, client_secret=client_secret)
  return auth


# ---- initial setup ----


def test_default_scopes_is_set(authenticator):
  assert authenticator.required_scopes == authenticator.DEFAULT_SCOPES


# ---- generate_strava_authorize_url() ----


def test_generate_strava_authorize_url_with_default_scopes(authenticator):
  authorize_url = authenticator.generate_strava_authorize_url(authenticator.client_id, authenticator.DEFAULT_SCOPES)
  parsed_url = urllib.parse.urlparse(authorize_url)
  query_params = urllib.parse.parse_qs(parsed_url.query)
  assert authorize_url.startswith(authenticator.AUTHORIZE_BASE_URL)
  assert len(query_params) == 5
  assert query_params.get("client_id") == [authenticator.client_id]
  assert query_params.get("response_type") == [authenticator.AUTHORIZE_RESPONSE_TYPE]
  assert query_params.get("redirect_uri") == [authenticator.AUTHORIZE_REDIRECT_URI]
  assert query_params.get("approval_prompt") == [authenticator.AUTHORIZE_APPROVAL_PROMPT]
  assert query_params.get("scope") == [authenticator.DEFAULT_SCOPES]


def test_generate_strava_authorize_url_with_custom_scopes(authenticator):
  custom_scopes = "test123,hello,abc"
  authorize_url = authenticator.generate_strava_authorize_url(authenticator.client_id, custom_scopes)
  parsed_url = urllib.parse.urlparse(authorize_url)
  query_params = urllib.parse.parse_qs(parsed_url.query)
  assert len(query_params) == 5
  assert query_params.get("client_id") == [authenticator.client_id]
  assert query_params.get("response_type") == [authenticator.AUTHORIZE_RESPONSE_TYPE]
  assert query_params.get("redirect_uri") == [authenticator.AUTHORIZE_REDIRECT_URI]
  assert query_params.get("approval_prompt") == [authenticator.AUTHORIZE_APPROVAL_PROMPT]
  assert query_params.get("scope") == [custom_scopes]


def test_generate_strava_authorize_url_with_empty_client_id(authenticator):
  with pytest.raises(ValueError):
    authenticator.generate_strava_authorize_url("", authenticator.DEFAULT_SCOPES)


def test_generate_strava_authorize_url_with_empty_scopes(authenticator):
  with pytest.raises(ValueError):
    authenticator.generate_strava_authorize_url(authenticator.client_id, "")


def test_generate_strava_authorize_url_client_id_has_spaces(authenticator):
  client_id_with_spaces = "this is a test"
  with pytest.raises(ValueError):
    authenticator.generate_strava_authorize_url(client_id_with_spaces, authenticator.DEFAULT_SCOPES)


def test_generate_strava_authorize_url_required_scopes_has_spaces(authenticator):
  custom_scope_with_spaces = "this is a test"
  with pytest.raises(ValueError):
    authenticator.generate_strava_authorize_url(authenticator.client_id, custom_scope_with_spaces)


# ---- set_required_scopes() ----


def test_set_required_scopes_with_valid_scopes(authenticator):
  custom_scopes = "a,b,c,d"
  assert authenticator.set_required_scopes(custom_scopes) == custom_scopes
  assert authenticator.required_scopes == custom_scopes


def test_set_required_scopes_with_empty_scope(authenticator):
  empty_scope = ""
  with pytest.raises(ValueError):
    authenticator.set_required_scopes(empty_scope)


# ---- extract_code_and_scope() ----


def test_extract_code_and_scope_with_valid_url(authenticator):
  valid_code = "abc123"
  valid_scope = "helloworld"
  valid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}?code={valid_code}&scope={valid_scope}"
  code, scope = authenticator.extract_code_and_scope(valid_url)
  assert code == valid_code
  assert scope == valid_scope


def test_extract_code_and_scope_with_missing_code(authenticator):
  valid_scope = "helloworld"
  invalid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}?scope={valid_scope}"
  with pytest.raises(StravaAuthenticationError):
    code, scope = authenticator.extract_code_and_scope(invalid_url)


def test_extract_code_and_scope_with_missing_scope(authenticator):
  valid_code = "abc123"
  invalid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}?code={valid_code}"
  with pytest.raises(StravaAuthenticationError):
    code, scope = authenticator.extract_code_and_scope(invalid_url)


def test_extract_code_and_scope_with_empty_url(authenticator):
  empty_url = ""
  with pytest.raises(ValueError):
    code, scope = authenticator.extract_code_and_scope(empty_url)


def test_extract_code_and_scope_with_invalid_domain(authenticator):
  random_url = "http://www.google.com?code=123&scope=hello"
  with pytest.raises(ValueError):
    code, scope = authenticator.extract_code_and_scope(random_url)


def test_extract_code_and_scope_with_empty_query(authenticator):
  invalid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}"
  with pytest.raises(StravaAuthenticationError):
    code, scope = authenticator.extract_code_and_scope(invalid_url)


def test_extract_code_and_scope_with_invalid_query(authenticator):
  invalid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}?test=123"
  with pytest.raises(StravaAuthenticationError):
    code, scope = authenticator.extract_code_and_scope(invalid_url)


# ---- verify_granted_scopes() ----


def test_verify_granted_scopes_with_all_required_scopes(authenticator):
  required_scopes = "read,activity:read,profile:read_all"
  granted_scopes = "read,activity:read,profile:read_all"
  assert authenticator.verify_granted_scopes(required_scopes, granted_scopes) is True


def test_verify_granted_scopes_with_required_scopes_2(authenticator):
  required_scopes = "read_all,activity:read_all,profile:read_all"
  granted_scopes = "read,activity:read_all,profile:read_all,read_all"
  assert authenticator.verify_granted_scopes(required_scopes, granted_scopes) is True


def test_verify_granted_scopes_with_missing_required_scopes(authenticator):
  required_scopes = "read,activity:read,profile:read_all"
  granted_scopes = "read,activity:read"
  with pytest.raises(StravaAuthenticationError):
    authenticator.verify_granted_scopes(required_scopes, granted_scopes)


def test_verify_granted_scopes_with_extra_granted_scopes(authenticator):
  required_scopes = "read,activity:read"
  granted_scopes = "read,activity:read,profile:read_all"
  assert authenticator.verify_granted_scopes(required_scopes, granted_scopes) is True


def test_verify_granted_scopes_with_invalid_scope(authenticator):
  invalid_scope_1 = "helloworld123"
  with pytest.raises(ValueError):
    authenticator.verify_granted_scopes(invalid_scope_1, invalid_scope_1)

  invalid_scope_2 = ","
  with pytest.raises(ValueError):
    authenticator.verify_granted_scopes(invalid_scope_2, invalid_scope_2)

  invalid_scope_3 = ""
  with pytest.raises(ValueError):
    authenticator.verify_granted_scopes(invalid_scope_3, invalid_scope_3)

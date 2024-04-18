# import urllib
# from unittest.mock import Mock

import pytest

# import requests
from strava_auth.auth import StravaAuthenticationError, StravaOAuth2

# from strava_auth.login import StravaWebLoginFlow


@pytest.fixture
def authenticator() -> StravaOAuth2:
  valid_client_id = "CLIENT_ID"
  valid_client_secret = "CLIENT_SECRET"
  auth = StravaOAuth2(valid_client_id, valid_client_secret)
  return auth


# ---- initial setup ----


def test_default_scopes_is_set(authenticator):
  assert authenticator.required_scopes == authenticator.DEFAULT_SCOPES


# # ---- generate_strava_authorize_url() ----


# def test_generate_strava_authorize_url_with_default_scopes(authenticator):
#   authorize_url = authenticator.generate_strava_authorize_url(authenticator.client_id, authenticator.DEFAULT_SCOPES)
#   parsed_url = urllib.parse.urlparse(authorize_url)
#   query_params = urllib.parse.parse_qs(parsed_url.query)
#   assert authorize_url.startswith(authenticator.AUTHORIZE_BASE_URL)
#   assert len(query_params) == 5
#   assert query_params.get("client_id") == [authenticator.client_id]
#   assert query_params.get("response_type") == [authenticator.AUTHORIZE_RESPONSE_TYPE]
#   assert query_params.get("redirect_uri") == [authenticator.AUTHORIZE_REDIRECT_URI]
#   assert query_params.get("approval_prompt") == [authenticator.AUTHORIZE_APPROVAL_PROMPT]
#   assert query_params.get("scope") == [authenticator.DEFAULT_SCOPES]


# def test_generate_strava_authorize_url_with_custom_scopes(authenticator):
#   custom_scopes = "test123,hello,abc"
#   authorize_url = authenticator.generate_strava_authorize_url(authenticator.client_id, custom_scopes)
#   parsed_url = urllib.parse.urlparse(authorize_url)
#   query_params = urllib.parse.parse_qs(parsed_url.query)
#   assert len(query_params) == 5
#   assert query_params.get("client_id") == [authenticator.client_id]
#   assert query_params.get("response_type") == [authenticator.AUTHORIZE_RESPONSE_TYPE]
#   assert query_params.get("redirect_uri") == [authenticator.AUTHORIZE_REDIRECT_URI]
#   assert query_params.get("approval_prompt") == [authenticator.AUTHORIZE_APPROVAL_PROMPT]
#   assert query_params.get("scope") == [custom_scopes]


# def test_generate_strava_authorize_url_with_empty_client_id(authenticator):
#   with pytest.raises(ValueError):
#     authenticator.generate_strava_authorize_url("", authenticator.DEFAULT_SCOPES)


# def test_generate_strava_authorize_url_with_empty_scopes(authenticator):
#   with pytest.raises(ValueError):
#     authenticator.generate_strava_authorize_url(authenticator.client_id, "")


# def test_generate_strava_authorize_url_client_id_has_spaces(authenticator):
#   client_id_with_spaces = "this is a test"
#   with pytest.raises(ValueError):
#     authenticator.generate_strava_authorize_url(client_id_with_spaces, authenticator.DEFAULT_SCOPES)


# def test_generate_strava_authorize_url_required_scopes_has_spaces(authenticator):
#   custom_scope_with_spaces = "this is a test"
#   with pytest.raises(ValueError):
#     authenticator.generate_strava_authorize_url(authenticator.client_id, custom_scope_with_spaces)


# # ---- set_required_scopes() ----


# def test_set_required_scopes_with_valid_scopes(authenticator):
#   custom_scopes = "a,b,c,d"
#   assert authenticator.set_required_scopes(custom_scopes) == custom_scopes
#   assert authenticator.required_scopes == custom_scopes


# def test_set_required_scopes_with_empty_scope(authenticator):
#   empty_scope = ""
#   with pytest.raises(ValueError):
#     authenticator.set_required_scopes(empty_scope)


# # ---- extract_code_and_scope() ----


# def test_extract_code_and_scope_with_valid_url(authenticator):
#   valid_code = "abc123"
#   valid_scope = "helloworld"
#   valid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}?code={valid_code}&scope={valid_scope}"
#   code, scope = authenticator.extract_code_and_scope(valid_url)
#   assert code == valid_code
#   assert scope == valid_scope


# def test_extract_code_and_scope_with_missing_code(authenticator):
#   valid_scope = "helloworld"
#   invalid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}?scope={valid_scope}"
#   with pytest.raises(StravaAuthenticationError):
#     code, scope = authenticator.extract_code_and_scope(invalid_url)


# def test_extract_code_and_scope_with_missing_scope(authenticator):
#   valid_code = "abc123"
#   invalid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}?code={valid_code}"
#   with pytest.raises(StravaAuthenticationError):
#     code, scope = authenticator.extract_code_and_scope(invalid_url)


# def test_extract_code_and_scope_with_empty_url(authenticator):
#   empty_url = ""
#   with pytest.raises(ValueError):
#     code, scope = authenticator.extract_code_and_scope(empty_url)


# def test_extract_code_and_scope_with_invalid_domain(authenticator):
#   random_url = "http://www.google.com?code=123&scope=hello"
#   with pytest.raises(ValueError):
#     code, scope = authenticator.extract_code_and_scope(random_url)


# def test_extract_code_and_scope_with_empty_query(authenticator):
#   invalid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}"
#   with pytest.raises(StravaAuthenticationError):
#     code, scope = authenticator.extract_code_and_scope(invalid_url)


# def test_extract_code_and_scope_with_invalid_query(authenticator):
#   invalid_url = f"{authenticator.AUTHORIZE_REDIRECT_URI}?test=123"
#   with pytest.raises(StravaAuthenticationError):
#     code, scope = authenticator.extract_code_and_scope(invalid_url)


# # ---- verify_granted_scopes() ----


# def test_verify_granted_scopes_with_all_required_scopes(authenticator):
#   required_scopes = "read,activity:read,profile:read_all"
#   granted_scopes = "read,activity:read,profile:read_all"
#   assert authenticator.verify_granted_scopes(required_scopes, granted_scopes) is True


# def test_verify_granted_scopes_with_required_scopes_2(authenticator):
#   required_scopes = "read_all,activity:read_all,profile:read_all"
#   granted_scopes = "read,activity:read_all,profile:read_all,read_all"
#   assert authenticator.verify_granted_scopes(required_scopes, granted_scopes) is True


# def test_verify_granted_scopes_with_missing_required_scopes(authenticator):
#   required_scopes = "read,activity:read,profile:read_all"
#   granted_scopes = "read,activity:read"
#   with pytest.raises(StravaAuthenticationError):
#     authenticator.verify_granted_scopes(required_scopes, granted_scopes)


# def test_verify_granted_scopes_with_extra_granted_scopes(authenticator):
#   required_scopes = "read,activity:read"
#   granted_scopes = "read,activity:read,profile:read_all"
#   assert authenticator.verify_granted_scopes(required_scopes, granted_scopes) is True


# def test_verify_granted_scopes_with_invalid_scope(authenticator):
#   invalid_scope_1 = "helloworld123"
#   with pytest.raises(ValueError):
#     authenticator.verify_granted_scopes(invalid_scope_1, invalid_scope_1)

#   invalid_scope_2 = ","
#   with pytest.raises(ValueError):
#     authenticator.verify_granted_scopes(invalid_scope_2, invalid_scope_2)

#   invalid_scope_3 = ""
#   with pytest.raises(ValueError):
#     authenticator.verify_granted_scopes(invalid_scope_3, invalid_scope_3)

#   invalid_scope_4 = "?@/[],test"
#   with pytest.raises(ValueError):
#     authenticator.verify_granted_scopes(invalid_scope_4, invalid_scope_4)


# # ---- exchange_token() ----


# @pytest.fixture
# def mock_post(mocker) -> Mock:
#   mock_response = Mock(spec=requests.Response)
#   mock_response.status_code = 200
#   valid_access_token = "abc123"
#   valid_athlete = {"id": 1, "firstname": "test", "lastname": "test"}
#   mock_response.json.return_value = {"access_token": valid_access_token, "athlete": valid_athlete}
#   mock = Mock(return_value=mock_response)
#   mocker.patch("requests.post", return_value=mock_response)
#   return mock


# def test_exchange_token_success(authenticator, mock_post):
#   valid_access_token = "abc123"
#   valid_athlete = {"id": 1, "firstname": "test", "lastname": "test"}
#   valid_client_id = "123"
#   valid_client_secret = "abc123"
#   valid_authorization_code = "code"
#   data = authenticator.exchange_token(valid_client_id, valid_client_secret, valid_authorization_code)
#   assert data["access_token"] == valid_access_token
#   assert data["athlete"] == valid_athlete


# def test_exchange_token_invalid_credentials(authenticator, mock_post):
#   mock_post.return_value.status_code = 401
#   invalid_client_id = "invalidclientid"
#   invalid_client_secret = "invalidsecret"
#   valid_authorization_code = "code"
#   with pytest.raises(StravaAuthenticationError):
#     access_token, athlete = authenticator.exchange_token(
#       invalid_client_id, invalid_client_secret, valid_authorization_code
#     )


# def test_exchange_token_missing_data(authenticator, mock_post):
#   mock_post.return_value.status_code = 200
#   mock_post.return_value.json.return_value = {"some_other_field": "some_value"}
#   valid_client_id = "123"
#   valid_client_secret = "abc123"
#   valid_authorization_code = "code"
#   with pytest.raises(StravaAuthenticationError):
#     access_token, athlete = authenticator.exchange_token(valid_client_id, valid_client_secret, valid_authorization_code)


# # ---- authenticate() ----


# @pytest.fixture
# def mock_strava_web_login_flow() -> StravaWebLoginFlow:
#   authorization_url = "https://www.strava.com/oauth/authorize?client_id=client_id&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A9191%2F&approval_prompt=force&scope=read%2Cactivity%3Aread"
#   return StravaWebLoginFlow(authorization_url=authorization_url)


# @pytest.fixture
# def mock_strava_web_login(mocker) -> Mock:
#   authorize_response_url = "http://localhost:9191/?code=valid_code&scope=read,activity:read"
#   mock = mocker.patch.object(StravaWebLoginFlow, "login", return_value=authorize_response_url)
#   return mock


# @pytest.fixture
# def mock_strava_web_login_invalid(mocker) -> Mock:
#   mock = mocker.patch.object(StravaWebLoginFlow, "login", return_value=None)
#   return mock


# @pytest.fixture
# def mock_generate_strava_authorize_url(mocker, authenticator) -> Mock:
#   authorize_url = "https://www.strava.com/oauth/authorize?client_id=client_id&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A9191%2F&approval_prompt=force&scope=read%2Cactivity%3Aread"
#   mock = Mock(return_value=authorize_url)
#   mocker.patch.object(authenticator, "generate_strava_authorize_url", mock)
#   return mock


# @pytest.fixture
# def mock_extract_code_and_scope(mocker, authenticator) -> Mock:
#   mock = Mock(return_value=("valid_code", "read,activity:read"))
#   mocker.patch.object(authenticator, "extract_code_and_scope", mock)
#   return mock


# @pytest.fixture
# def mock_exchange_token(mocker, authenticator) -> Mock:
#   return_data = {
#     "expires_at": 1234567,
#     "refresh_token": "refreshtoken",
#     "access_token": "abc123",
#     "athlete": {"id": 1, "firstname": "test"},
#   }
#   mock = Mock(return_value=return_data)
#   mocker.patch.object(authenticator, "exchange_token", mock)
#   return mock


# @pytest.fixture
# def mock_load_from_cache(mocker, authenticator) -> Mock:
#   mock = Mock(return_value=False)
#   mocker.patch.object(authenticator, "load_from_cache", mock)
#   return mock


# @pytest.fixture
# def mock_save_to_cache(mocker, authenticator) -> Mock:
#   mock = Mock(return_value=None)
#   mocker.patch.object(authenticator, "save_to_cache", mock)
#   return mock


# def test_authenticate_success(
#   authenticator,
#   mock_load_from_cache,
#   mock_generate_strava_authorize_url,
#   mock_extract_code_and_scope,
#   mock_strava_web_login_flow,
#   mock_strava_web_login,
#   mock_exchange_token,
#   mock_save_to_cache,
# ):
#   token, athlete = authenticator.authenticate("abc@123.com", "abc123")
#   assert token == "abc123"
#   assert athlete == {"id": 1, "firstname": "test"}


# def test_authenticate_extract_code_and_scope_failure(
#   authenticator,
#   mock_load_from_cache,
#   mock_generate_strava_authorize_url,
#   mock_extract_code_and_scope,
#   mock_strava_web_login_flow,
#   mock_strava_web_login,
#   mock_exchange_token,
#   mock_save_to_cache,
# ):
#   mock_extract_code_and_scope.side_effect = StravaAuthenticationError("testing...")
#   token, athlete = authenticator.authenticate("abc@123.com", "abc123")
#   assert token is None
#   assert athlete is None


# def test_authenticate_strava_web_login_failure(
#   authenticator,
#   mock_load_from_cache,
#   mock_generate_strava_authorize_url,
#   mock_strava_web_login_flow,
#   mock_strava_web_login_invalid,
# ):
#   token, athlete = authenticator.authenticate("abc@123.com", "abc123")
#   assert token is None
#   assert athlete is None

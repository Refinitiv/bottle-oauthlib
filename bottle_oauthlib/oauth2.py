import bottle
from bottle import HTTPError
import functools
import json
from oauthlib.common import add_params_to_uri
from oauthlib.oauth2 import FatalClientError
from oauthlib.oauth2 import OAuth2Error
import requests
import logging

log = logging.getLogger(__name__)


def extract_params(bottle_request):
    """Extract bottle request informations to oauthlib implementation.
    HTTP Authentication Basic is read but overloaded by payload, if any.

    returns tuple of :
    - url
    - method
    - body (or dict)
    - headers (dict)
    """

    # this returns (None, None) for Bearer Token.
    username, password = bottle_request.auth if bottle_request.auth else (None, None)

    if "application/x-www-form-urlencoded" in bottle_request.content_type:
        client = {}
        if username is not None:
            client["client_id"] = username
        if password is not None:
            client["client_secret"] = password
        return \
            bottle_request.url, \
            bottle_request.method, \
            dict(client, **bottle_request.forms), \
            dict(bottle_request.headers)

    basic_auth = {}
    body = bottle_request.body

    # TODO: Remove HACK of using body for GET requests. Use commented code below
    # once https://github.com/oauthlib/oauthlib/issues/609 is fixed.
    if username is not None:
        basic_auth = {
            "Authorization": requests.auth._basic_auth_str(username, password)
        }
        body = dict(client_id=username, client_secret=password)

    return \
        bottle_request.url, \
        bottle_request.method, \
        body, \
        dict(bottle_request.headers, **basic_auth)


def add_params_to_request(bottle_request, params):
    try:
        bottle_request.oauth
    except AttributeError:
        bottle_request.oauth = {}
    if params:
        for k, v in params.items():
            bottle_request.oauth[k] = v


def set_response(bottle_request, bottle_response, status, headers, body, force_json=False):
    """Set status/headers/body into bottle_response.

    Headers is a dict
    Body is ideally a JSON string (not dict).
    """
    if not isinstance(headers, dict):
        raise TypeError("a dict-like object is required, not {0}".format(type(headers)))

    bottle_response.status = status
    for k, v in headers.items():
        bottle_response.headers[k] = v

    """Determine if response should be in json or not, based on request:
    OAuth2.0 RFC recommands json, but older clients use form-urlencoded.

    Note also that force_json can be set to be compliant with specific
    endpoints like introspect, which always returns json.

    Examples:
    rauth: send Accept:*/* but work only with response in form-urlencoded.
    requests-oauthlib: send Accept:application/json but work with both
    responses types.
    """
    if not body:
        return

    if not isinstance(body, str):
        raise TypeError("a str-like object is required, not {0}".format(type(body)))

    log.debug("Creating bottle response from string body %s...", body)

    try:
        values = json.loads(body)
    except json.decoder.JSONDecodeError:
        # consider body as string but not JSON, we stop here.
        bottle_response.body = body
        log.debug("Body Bottle response body created as is: %r", bottle_response.body)
    else:  # consider body as JSON
        # request want a json as response
        if force_json is True or (
                "Accept" in bottle_request.headers and
                "application/json" == bottle_request.headers["Accept"]):
            bottle_response["Content-Type"] = "application/json;charset=UTF-8"
            bottle_response.body = body
            log.debug("Body Bottle response body created as json: %r", bottle_response.body)
        else:
            from urllib.parse import quote

            bottle_response["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8"
            bottle_response.body = "&".join([
                "{0}={1}".format(
                    quote(k) if isinstance(k, str) else k,
                    quote(v) if isinstance(v, str) else v
                ) for k, v in values.items()
            ])
            log.debug("Body Bottle response body created as form-urlencoded: %r", bottle_response.body)


class BottleOAuth2(object):
    def __init__(self, bottle_server):
        self._bottle = bottle_server
        self._error_uri = None
        self._oauthlib = None

    def initialize(self, oauthlib_server, error_uri=None):
        self._error_uri = error_uri
        self._oauthlib = oauthlib_server

    def create_metadata_response(self):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                uri, http_method, body, headers = extract_params(bottle.request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_metadata_response(
                        uri, http_method, body, headers
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code
                set_response(bottle.request, bottle.response, resp_status,
                             resp_headers, resp_body, force_json=True)

                func_response = f()
                if func_response:
                    return func_response
                return bottle.response
            return wrapper
        return decorator

    def create_token_response(self, credentials=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                # Get any additional creds
                try:
                    credentials_extra = credentials(bottle.request)
                except TypeError:
                    credentials_extra = credentials
                uri, http_method, body, headers = extract_params(bottle.request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_token_response(
                        uri, http_method, body, headers, credentials_extra
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code
                set_response(bottle.request, bottle.response, resp_status,
                             resp_headers, resp_body)

                func_response = f(*args, **kwargs)
                if func_response:
                    return func_response
                return bottle.response
            return wrapper
        return decorator

    def verify_request(self, scopes=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                # Get the list of scopes
                try:
                    scopes_list = scopes(bottle.request)
                except TypeError:
                    scopes_list = scopes

                uri, http_method, body, headers = extract_params(bottle.request)
                valid, req = self._oauthlib.verify_request(uri, http_method, body, headers, scopes_list)

                # For convenient parameter access in the view
                add_params_to_request(bottle.request, {
                    'client': req.client,
                    'user': req.user,
                    'scopes': req.scopes
                })
                if valid:
                    return f(*args, **kwargs)

                # Framework specific HTTP 403
                return HTTPError(403, "Permission denied")
            return wrapper
        return decorator

    def create_introspect_response(self):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                uri, http_method, body, headers = extract_params(bottle.request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_introspect_response(
                        uri, http_method, body, headers
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code
                set_response(bottle.request, bottle.response, resp_status, resp_headers,
                             resp_body, force_json=True)

                func_response = f(*args, **kwargs)
                if func_response:
                    return func_response
                return bottle.response
            return wrapper
        return decorator

    def create_authorization_response(self):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                uri, http_method, body, headers = extract_params(bottle.request)
                scope = bottle.request.params.get('scope', '').split(' ')

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_authorization_response(
                        uri, http_method=http_method, body=body, headers=headers, scopes=scope
                    )
                except FatalClientError as e:
                    if self._error_uri:
                        raise bottle.HTTPResponse(status=302, headers={"Location": add_params_to_uri(
                            self._error_uri, {'error': e.error, 'error_description': e.description}
                        )})
                    raise e
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code
                set_response(bottle.request, bottle.response, resp_status, resp_headers, resp_body)

                func_response = f(*args, **kwargs)
                if func_response:
                    return func_response
                return bottle.response
            return wrapper
        return decorator

    def create_revocation_response(self):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                uri, http_method, body, headers = extract_params(bottle.request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_revocation_response(
                        uri, http_method=http_method, body=body, headers=headers
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code

                set_response(bottle.request, bottle.response, resp_status, resp_headers, resp_body)

                func_response = f(*args, **kwargs)
                if func_response:
                    return func_response
                return bottle.response
            return wrapper
        return decorator

    def create_userinfo_response(self):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                uri, http_method, body, headers = extract_params(bottle.request)

                try:
                    resp_headers, resp_body, resp_status = self._oauthlib.create_userinfo_response(
                        uri, http_method=http_method, body=body, headers=headers
                    )
                except OAuth2Error as e:
                    resp_headers, resp_body, resp_status = e.headers, e.json, e.status_code

                set_response(bottle.request, bottle.response, resp_status, resp_headers,
                             resp_body, force_json=True)

                func_response = f(*args, **kwargs)
                if func_response:
                    return func_response
                return bottle.response
            return wrapper
        return decorator

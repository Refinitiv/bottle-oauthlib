import bottle
from bottle import HTTPError
import functools
import logging
import json
from oauthlib.common import add_params_to_uri
from oauthlib.oauth2 import FatalClientError
from oauthlib.oauth2 import OAuth2Error
import requests
import sys


log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


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
    if username is not None:
        basic_auth = {
            "Authorization": requests.auth._basic_auth_str(username, password)
        }
    return \
        bottle_request.url, \
        bottle_request.method, \
        bottle_request.body, \
        dict(bottle_request.headers, **basic_auth)


def add_params_to_request(bottle_request, params):
    try:
        bottle_request.oauth
    except AttributeError:
        bottle_request.oauth = {}
    if params:
        for k, v in params.items():
            bottle_request.oauth[k] = v


def set_response(bottle_request, bottle_response, status, headers, body):
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

    Examples:
    rauth: send Accept:*/* but work only with response in form-urlencoded.
    requests-oauthlib: send Accept:application/json but work with both
    responses types.
    """
    if not body:
        return

    if not isinstance(body, str):
        raise TypeError("a str-like object is required, not {0}".format(type(body)))

    try:
        values = json.loads(body)
    except json.decoder.JSONDecodeError:
        # consider body as string but not JSON, we stop here.
        bottle_response.body = body
    else:  # consider body as JSON
        # request want a json as response
        if "Accept" in bottle_request.headers and "application/json" == bottle_request.headers["Accept"]:
            bottle_response.body = body
        else:
            from urllib.parse import quote

            bottle_response["Content-Type"] = "application/x-www-form-urlencoded"
            bottle_response.body = "&".join([
                "{0}={1}".format(
                    quote(k) if isinstance(k, str) else k,
                    quote(v) if isinstance(v, str) else v
                ) for k, v in values.items()
            ])


class BottleOAuth2(object):
    def __init__(self, bottle_server):
        self._bottle = bottle_server
        self._oauthlib = None

    def initialize(self, oauthlib_server):
        self._oauthlib = oauthlib_server

    def create_token_response(self, credentials=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                # Get the list of scopes
                try:
                    credentials_extra = credentials(bottle.request)
                except TypeError:
                    credentials_extra = credentials
                uri, http_method, body, headers = extract_params(bottle.request)
                headers, body, status = self._oauthlib.create_token_response(
                    uri, http_method, body, headers, credentials_extra
                )
                set_response(bottle.request, bottle.response, status, headers, body)
                func_response = f()
                if not func_response:
                    return bottle.response
            return wrapper
        return decorator

    def verify_request(self, scopes=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                # Get the list of scopes
                try:
                    scopes_list = scopes(bottle.request)
                except TypeError:
                    scopes_list = scopes

                uri, http_method, body, headers = extract_params(bottle.request)
                valid, r = self._oauthlib.verify_request(uri, http_method, body, headers, scopes_list)

                # For convenient parameter access in the view
                add_params_to_request(bottle.request, {
                    'client': r.client,
                    'user': r.user,
                    'scopes': r.scopes
                })
                if valid:
                    return f()
                else:
                    # Framework specific HTTP 403
                    return HTTPError(403, "Permission denied")
            return wrapper
        return decorator

    def validate_authorization_request(self):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"

                uri, http_method, body, headers = extract_params(bottle.request)
                try:
                    scopes, request_info = self._oauthlib.validate_authorization_request(
                        uri, http_method, body, headers
                    )

                    redirect_uri = request_info["redirect_uri"]

                except FatalClientError as e:
                    log.debug('Fatal client error %r', e, exc_info=True)
                    return bottle.redirect(e.in_uri(self.error_uri))
                except OAuth2Error as e:
                    log.debug('OAuth2Error: %r', e, exc_info=True)
                    return bottle.redirect(e.in_uri(redirect_uri))
                except Exception as e:
                    log.exception(e)
                    return bottle.redirect(add_params_to_uri(
                        self.error_uri, {'error': str(e)}
                    ))

                # For convenient parameter access in the view
                add_params_to_request(bottle.request, {
                    'request_info': request_info,
                    'scopes': scopes
                })
                return f()
            return wrapper
        return decorator

    def create_authorization_response(self, scopes=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"
                uri, http_method, body, headers = extract_params(bottle.request)
                try:
                    scope = scopes(bottle.request)
                    res_headers, res_body, res_status = self._oauthlib.create_authorization_response(
                        uri, http_method=http_method, body=body, headers=headers, scopes=scope
                    )
                    res = f()
                    if not res:
                        return bottle.HTTPResponse(status=res_status, body=res_body, headers=res_headers)

                except FatalClientError as e:
                    log.debug('Fatal client error %r', e, exc_info=True)
                    return bottle.HTTPResponse(status=400, body={'error': str(e)})

                except Exception as e:
                    log.error(e)
                    return bottle.HTTPResponse(status=500, body={'error': str(e)})

                return bottle.response
            return wrapper
        return decorator

    def validate_session_cookie(self, login_uri=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                assert self._oauthlib, "BottleOAuth2 not initialized with OAuthLib"
                if login_uri:
                    # Check if ipdp is present. If no => redirect to given login url
                    ipdp = bottle.request.get_cookie("iPlanetDirectoryPro")
                    from urllib.parse import quote_plus
                    log.debug(f"iPlanetDirectoryPro Cookie: {ipdp}")
                    if not ipdp:
                        return bottle.redirect(login_uri + "?redirect_after_login_uri=" + quote_plus(bottle.request.url), 302)
                return f()
            return wrapper
        return decorator

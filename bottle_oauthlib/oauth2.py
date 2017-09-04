import bottle
from bottle import HTTPError
import functools
import logging
import json
from oauthlib.common import add_params_to_uri
from oauthlib.oauth2 import FatalClientError
from oauthlib.oauth2 import OAuth2Error
import sys


log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


def extract_auth():
    """Extract authentication tuple from request
    Priority for HTTP Authentication Basic, then
    Check if it's stored in Request Payload (for older clients)
    """
    if bottle.request.auth:
        return bottle.request.auth
    if "client_id" in bottle.request.forms:
        if "client_secret" in bottle.request.forms:
            return bottle.request.forms["client_id"], bottle.request.forms["client_secret"]
        return bottle.request.forms["client_id"], None
    return None, None


def extract_params():
    if bottle.request.forms:
        return \
            bottle.request.url, \
            bottle.request.method, \
            dict(bottle.request.forms.items()), \
            dict(bottle.request.headers)
    return \
        bottle.request.url, \
        bottle.request.method, \
        bottle.request.body, \
        dict(bottle.request.headers)


def add_params(params):
    try:
        bottle.request.oauth
    except AttributeError:
        bottle.request.oauth = {}
    for k, v in params.iteritems():
        bottle.request.oauth[k] = v


def set_response(request, response, status, headers, body):
    response.status = status
    for k, v in headers.items():
        response.headers[k] = v

    """Determine if response should be in json or not, based on request:
    RFC prefer json, but older clients doesn't work with it.

    Examples:
    rauth: send */* but work only with form-urlencoded.
    requests-oauthlib: send application/json but work with both.
    """
    json_enabled = "application/json" == request.headers["Accept"]
    if json_enabled:
        response.body = body
    else:
        from urllib.parse import quote

        values = json.loads(body)
        response["Content-Type"] = "application/x-www-form-urlencoded"
        response.body = ";".join([
            "{0}={1}".format(
                quote(k) if isinstance(k, str) else k,
                quote(v) if isinstance(v, str) else v
            ) for k, v in values.items()
        ])


class BottleOAuth2(object):
    def __init__(self, server):
        self._server = server

    def create_token_response(self, credentials=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                # Get the list of scopes
                try:
                    credentials_extra = credentials(bottle.request)
                except TypeError:
                    credentials_extra = credentials
                uri, http_method, body, headers = extract_params()
                headers, body, status = self._server.create_token_response(
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
                # Get the list of scopes
                try:
                    scopes_list = scopes(bottle.request)
                except TypeError:
                    scopes_list = scopes

                uri, http_method, body, headers = extract_params()

                valid, r = self._server.verify_request(
                    uri, http_method, body, headers, scopes_list)

                # For convenient parameter access in the view
                add_params({
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
                uri, http_method, body, headers = extract_params()
                raise Exception("not implemented")

                try:
                    scopes, credentials = self._server.validate_authorization_request(
                        uri, http_method, body, headers
                    )
                    redirect_uri = credentials["redirect_uri"]  # ok ?
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
                add_params({
                    'credentials': credentials,
                    'scopes': scopes
                })
                return f()
            return wrapper
        return decorator

    def create_authorization_response(self):
        def decorator(f):
            @functools.wraps(f)
            def wrapper():
                raise Exception("not implemented")
            return wrapper
        return decorator

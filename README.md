# bottle-oauthlib

[![Jenkins build](https://api.travis-ci.org/thomsonreuters/bottle-oauthlib.svg?branch=master)](https://travis-ci.org/thomsonreuters/bottle-oauthlib)
[![Coverage Status](https://coveralls.io/repos/github/thomsonreuters/bottle-oauthlib/badge.svg?branch=master)](https://coveralls.io/github/thomsonreuters/bottle-oauthlib?branch=master)
[![pip install bottle-oauthlib](https://img.shields.io/pypi/v/bottle-oauthlib.svg)](https://pypi.python.org/pypi/bottle-oauthlib)

## Context

Interested to implement your own OAuth2.0 or OpenID Connect Provider in python ? You're at the right place.

Combine the excellent https://github.com/oauthlib/oauthlib framework and the micro-framework https://github.com/bottlepy/bottle to provide OAuth2.0 authorization in only a couple of minutes.

OAuth2.0 basic knowledge is more than welcomed ! However, for novices users, as a rule of thumb, you must understand the OAuth2.0 is a delegation protocol. Basically, it delegates authorization (through scopes) to an application (client).

Note that you can implement only the delegation part or the authorization server or an application, or all combined. That's your choice.

For more information about OAuth2.0 fundamentals, check https://oauth.net/2/

## Quick start

Define rules into a oauthlib.RequestValidator class. See [oauthlib#implement-a-validator](https://oauthlib.readthedocs.io/en/latest/oauth2/server.html#implement-a-validator):
```python
class MyOAuth2_Validator(oauth2.RequestValidator):
    def authenticate_client_id(self, client_id, ..):
        """validate client_id"""

    def validate_user(self, username, password, client, ..):
        """validate username & password"""

    def validate_scopes(self, client_id, scopes, ..):
        """validate scope against the client"""

    (..)
```

Link it to a preconfigured `oauthlib` Server, then to a `bottle` app: 

```python
import bottle
from bottle_oauthlib.oauth2 import BottleOAuth2
from oauthlib import oauth2

validator = MyOAuth2_Validator()
server = oauth2.Server(validator)

app = bottle.Bottle()
app.auth = BottleOAuth2()
app.auth.initialize(server)
```

Finally, declare `bottle` endpoints to request token:
```python
@app.post('/token')
@app.auth.create_token_response()
def token():
    """an empty controller is enough for most cases"""
```

In addition, you can declare a _resource_ endpoint which verify a token and its optional scopes:
```python
@app.get('/calendar')
@app.auth.verify_request(scopes=['calendar'])
def access_calendar():
    return "Welcome {}, you have permissioned {} to use your calendar".format(
        bottle.request.oauth["user"],
        bottle.request.oauth["client"].client_id
    )
```

See the full example in our code source at [quickstart.py](https://github.com/thomsonreuters/bottle-oauthlib/blob/master/tests/examples/quickstart.py). Don't hesitate to copy it for your own project and its unit tests at [test_quickstart.py](https://github.com/thomsonreuters/bottle-oauthlib/blob/master/tests/test_quickstart.py) to be confident when you upgrade.

If you are not interested in doing a full Provider but only a Resource Server, just use the quickstart example for OAuth2.0 Resource Server. You can either use an Introspection Endpoint or decode JWT and validate yourself the Bearer tokens. Start with the [quickstart_resourceserver.py](https://github.com/thomsonreuters/bottle-oauthlib/blob/master/tests/examples/quickstart_resourceserver.py) and its unit tests at [test_quickstart_resourceserver.py](https://github.com/thomsonreuters/bottle-oauthlib/blob/master/tests/test_quickstart_resourceserver.py).

## Help & support

Feel free to ask question or support by opening a Github issue https://github.com/thomsonreuters/bottle-oauthlib/issues.


## Contribution

Don't hesitate to propose PR, they are more than welcomed. Please, be sure you're compliant with our [Contribution guide](https://github.com/thomsonreuters/bottle-oauthlib/blob/master/docs/CONTRIBUTING.md).


## Copyright

This document is licensed under BSD-3-Clause license. See LICENSE for details.

The code has been opened by (c) Thomson Reuters.

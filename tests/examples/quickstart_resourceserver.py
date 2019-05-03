from oauthlib import oauth2


class Client():
    client_id = None


class OAuth2_ResourceValidator(oauth2.RequestValidator):
    def validate_bearer_token(self, token, scopes_required, request):
        if not token:
            return False

        """We are using a static dict for the sake of the exercice, but we can
        replace it by a JWT decoding or sending a request to an introspect
        endpoint instead, depending your OAuth2 Resource Server validation."""
        tokeninfo = {
            "sub": "john",
            "scope": "mail calendar",
            "client_id": "clientA"
        }

        if not tokeninfo.get("scope", None):
            return False  # pragma: no cover

        scopes = oauth2.rfc6749.utils.scope_to_list(tokeninfo.get("scope"))
        for scope in scopes_required:
            if scope not in scopes:
                return False

        client = Client()
        client.client_id = tokeninfo["client_id"]
        request.user = tokeninfo["sub"]
        request.client = client
        return True


import bottle
app = bottle.Bottle()


from bottle_oauthlib.oauth2 import BottleOAuth2
app.auth = BottleOAuth2(app)

resource = oauth2.ResourceEndpoint(
    default_token='Bearer',
    token_types={
        'Bearer': oauth2.BearerToken(OAuth2_ResourceValidator())
    }
)
app.auth.initialize(resource)


@app.get('/mail')
@app.auth.verify_request(scopes=['mail'])
def access_mail():
    return "Welcome {}, you have permissioned {} to use your mail".format(
        bottle.request.oauth["user"],
        bottle.request.oauth["client"].client_id
    )


@app.get('/mail_and_calendar')
@app.auth.verify_request(scopes=['mail', 'calendar'])
def access_mail_and_calendar():
    return "Welcome {}, you have permissioned {} to use your mail & calendar".format(
        bottle.request.oauth["user"],
        bottle.request.oauth["client"].client_id
    )


@app.get('/photos')
@app.auth.verify_request(scopes=['photos'])
def access_photos():
    # this code is never reached because the user has not the "photos" permission
    return "Welcome {}, you have permissioned {} to use your photos".format(
        bottle.request.oauth["user"],
        bottle.request.oauth["client"].client_id
    )  # pragma: no cover


if __name__ == "__main__":
    app.run()  # pragma: no cover

from oauthlib import oauth2


class Client():
    client_id = None


class OAuth2_PasswordValidator(oauth2.RequestValidator):
    """dict of clients containing list of valid scopes"""
    clients_scopes = {
            "clientA": ["mail", "calendar"],
            "clientB": ["calendar"]
    }
    """dict of username containing password"""
    users_password  = {
        "john": "doe",
        "foo": "bar"
    }
    tokens_info = {
    }

    def client_authentication_required(self, request, *args, **kwargs):
        return False  # Allow public clients

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        if self.clients_scopes.get(client_id):
            request.client = Client()
            request.client.client_id = client_id
            return True
        return False

    def validate_user(self, username, password, client, request, *args, **kwargs):
        if self.users_password.get(username):
            request.user = username
            return password == self.users_password.get(username)
        return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return grant_type in ["password"]

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return all(scope in self.clients_scopes.get(client_id) for scope in scopes)

    def save_bearer_token(self, token_response, request, *args, **kwargs):
        self.tokens_info[token_response["access_token"]] = {
            "client": request.client,
            "user": request.user,
            "scopes": request.scopes
        }

    def validate_bearer_token(self, access_token, scopes_required, request):
        info = self.tokens_info.get(access_token, None)
        if info:
            request.client = info["client"]
            request.user = info["user"]
            request.scopes = info["scopes"]
            return all(scope in request.scopes for scope in scopes_required)
        return False


import bottle
from bottle_oauthlib.oauth2 import BottleOAuth2


app = bottle.Bottle()
app.auth = BottleOAuth2(app)
app.auth.initialize(oauth2.LegacyApplicationServer(OAuth2_PasswordValidator()))


@app.get('/mail')
@app.auth.verify_request(scopes=['mail'])
def access_mail():
    return "Welcome {}, you have permissioned {} to use your mail".format(
        bottle.request.oauth["user"],
        bottle.request.oauth["client"].client_id
    )


@app.get('/calendar')
@app.auth.verify_request(scopes=['calendar'])
def access_calendar():
    return "Welcome {}, you have permissioned {} to use your calendar".format(
        bottle.request.oauth["user"],
        bottle.request.oauth["client"].client_id
    )


@app.post('/token')
@app.auth.create_token_response()
def generate_token():
    pass


if __name__ == "__main__":
    app.run()  # pragma: no cover

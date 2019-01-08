import bottle
from bottle_oauthlib.oauth2 import BottleOAuth2
from oauthlib import oauth2

app = bottle.Bottle()
app.auth = BottleOAuth2(app)
app.authmetadata = BottleOAuth2(app)

oauthlib_server = oauth2.LegacyApplicationServer(oauth2.RequestValidator())
app.authmetadata.initialize(oauth2.MetadataEndpoint([oauthlib_server], claims={
    "issuer": "https://xx",
    "token_endpoint": "https://xx/token",
    "revocation_endpoint": "https://xx/revoke",
    "introspection_endpoint": "https://xx/tokeninfo"
}))


@app.get('/.well-known/oauth-authorization-server')
@app.authmetadata.create_metadata_response()
def metadata():
    pass


if __name__ == "__main__":
    app.run()  # pragma: no cover

from bottle import tob
from .bottle_tools import ServerTestBase
from tests.examples import quickstart
import unittest
from urllib.parse import unquote
from urllib.parse import parse_qs


class test_quickstart(ServerTestBase):
    def setUp(self):
        import importlib
        importlib.reload(quickstart)
        super().setUp(quickstart.app)

    def assertError(self, resp, status, error, content_type="application/x-www-form-urlencoded;charset=UTF-8"):
        self.assertEqual(status, resp['code'], resp['body'])
        errorline = f"error={error}"
        self.assertEqual(tob(errorline), resp['body'][:len(tob(errorline))], resp['body'])
        self.assertEqual(content_type, resp['header']['Content-Type'])
        
    def test_noclient(self):
        resp = self.urlopen("/token", method="POST", post="&".join([
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})
        self.assertError(resp, 401, "invalid_client")

    def test_nogrant(self):
        resp = self.urlopen("/token", method="POST", post="&".join([
            "client_id=clientA",
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})
        self.assertError(resp, 400, "invalid_request")

    def test_nousername(self):
        resp = self.urlopen("/token", method="POST", post="&".join([
            "client_id=clientA",
            "grant_type=foobar",
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})
        self.assertError(resp, 400, "invalid_request")
    
    def test_nopassword(self):
        resp = self.urlopen("/token", method="POST", post="&".join([
            "client_id=clientA",
            "grant_type=foobar",
            "username=john",
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})
        self.assertError(resp, 400, "invalid_request")

    def test_invalidgrant(self):
        resp = self.urlopen("/token", method="POST", post="&".join([
            "client_id=clientA",
            "grant_type=FOOBAR",
            "username=john",
            "password=doe",
            "scope=calendar",
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})

        self.assertError(resp, 400, "unsupported_grant_type")

    def test_invalidscope(self):
        resp = self.urlopen("/token", method="POST", post="&".join([
            "client_id=clientB",
            "grant_type=password",
            "username=john",
            "password=doe",
            "scope=mail",
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})

        self.assertError(resp, 401, "invalid_scope")

    def test_invaliduser(self):
        resp = self.urlopen("/token", method="POST", post="&".join([
            "client_id=clientB",
            "grant_type=password",
            "username=eve",
            "password=doe",
            "scope=mail",
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})

        self.assertError(resp, 401, "invalid_grant&error_description=Invalid%20credentials")

    def test_invalidpassword(self):
        resp = self.urlopen("/token", method="POST", post="&".join([
            "client_id=clientB",
            "grant_type=password",
            "username=john",
            "password=his_birthday",
            "scope=mail",
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})

        self.assertError(resp, 401, "invalid_grant&error_description=Invalid%20credentials")

    def fetchToken(self, client, username, password, scope):
        resp = self.urlopen("/token", method="POST", post="&".join([
            f"client_id={client}",
            "grant_type=password",
            f"username={username}",
            f"password={password}",
            f"scope={scope}",
        ]), env={'CONTENT_TYPE': "application/x-www-form-urlencoded"})

        self.assertEqual(200, resp['code'], resp['body'])
        self.assertEqual("application/x-www-form-urlencoded;charset=UTF-8", resp['header']['Content-Type'])

        body_response = parse_qs(resp['body'].decode('utf-8'))
        for k, v in body_response.items():
            assert len(v) == 1, "multiple values in form-urlencoded is not normal here."
        token_response = dict([(x, unquote(y[0])) for x, y in body_response.items()])
        for k in ["access_token", "expires_in", "token_type", "scope", "refresh_token"]:
            self.assertIn(k, token_response)
        return token_response

    def test_valid(self):
        self.fetchToken("clientA", "john", "doe", "calendar")

    def test_no_token(self):
        resp = self.urlopen("/mail")
        self.assertEqual(403, resp['code'], resp['body'])

    def test_invalid_token(self):
        resp = self.urlopen("/mail", env={'HTTP_AUTHORIZATION': f"Bearer foobar_is_a_random_string"})
        self.assertEqual(403, resp['code'], resp['body'])

    def test_access_mail(self):
        token = self.fetchToken("clientA", "john", "doe", "mail")
        access_token = token["access_token"]
        resp = self.urlopen("/mail", env={'HTTP_AUTHORIZATION': f"Bearer {access_token}"})
        self.assertEqual(200, resp['code'], resp['body'])
        self.assertEqual(tob("Welcome john, you have permissioned clientA to use your mail"), resp['body'])

    def test_access_mail_not_granted(self):
        token = self.fetchToken("clientB", "john", "doe", "calendar")
        access_token = token["access_token"]
        resp = self.urlopen("/mail", env={'HTTP_AUTHORIZATION': f"Bearer {access_token}"})
        self.assertEqual(403, resp['code'], resp['body'])

    def test_access_calendar(self):
        token = self.fetchToken("clientA", "john", "doe", "calendar")
        access_token = token["access_token"]
        resp = self.urlopen("/calendar", env={'HTTP_AUTHORIZATION': f"Bearer {access_token}"})
        self.assertEqual(200, resp['code'], resp['body'])
        self.assertEqual(tob("Welcome john, you have permissioned clientA to use your calendar"), resp['body'])

import bottle
from bottle import tob
from tests.bottle_tools import ServerTestBase
from bottle_oauthlib.oauth2 import BottleOAuth2
from oauthlib.oauth2 import Server
from tests import AttrDict
from unittest import mock
import unittest


class test_not_initialized(ServerTestBase):
    def setUp(self):
        super().setUp()
        self.oauth = BottleOAuth2(self.app)

    def test_create_token_response(self):
        @bottle.route('/foo')
        @self.oauth.create_token_response()
        def test(): return 'bar'

        with self.assertRaises(AssertionError):
            test()

    def test_verify_request(self):
        @bottle.route('/foo')
        @self.oauth.verify_request()
        def test(): return 'bar'

        with self.assertRaises(AssertionError):
            test()

    def test_create_authorization_response(self):
        @bottle.route('/foo')
        @self.oauth.create_authorization_response()
        def test(): return 'bar'

        with self.assertRaises(AssertionError):
            test()

    def test_create_introspect_response(self):
        @bottle.route('/foo')
        @self.oauth.create_introspect_response()
        def test(): return 'bar'

        with self.assertRaises(AssertionError):
            test()


class test_verify_decorators(ServerTestBase):
    def setUp(self):
        super().setUp()
        self.oauth = BottleOAuth2(self.app)
        self.validator = mock.MagicMock()
        self.server = Server(self.validator)
        self.oauth.initialize(self.server)

        self.fake_request = AttrDict(
            client="foo",
            user="bar",
            scopes=['banana', 'pinapple']
        )

    def test_valid_request(self):
        @bottle.route('/foo')
        @self.oauth.verify_request()
        def test():
            self.assertEqual(bottle.request.oauth['client'], 'foo')
            self.assertEqual(bottle.request.oauth['user'], 'bar')
            self.assertEqual(bottle.request.oauth['scopes'], ['banana', 'pinapple'])
            return "authorized_access"

        with mock.patch("oauthlib.oauth2.Server.verify_request", return_value=(True, self.fake_request)) as mocked:
            app_response = self.urlopen("/foo")
            self.assertEqual(app_response['code'], 200, app_response['body'])
            self.assertEqual(app_response['status'], "OK")
            self.assertEqual(app_response['body'], tob("authorized_access"))
        mocked.assert_called_once()

    def test_invalid_request(self):
        @bottle.route('/foo')
        @self.oauth.verify_request()
        def test():
            self.assertTrue(False, "must never be here")

        with mock.patch("oauthlib.oauth2.Server.verify_request", return_value=(False, self.fake_request)) as mocked:
            app_response = self.urlopen("/foo")
            self.assertEqual(app_response['code'], 403, app_response['body'])
        mocked.assert_called_once()


class test_create_decorators(ServerTestBase):
    def setUp(self):
        super().setUp()
        self.oauth = BottleOAuth2(self.app)
        self.validator = mock.MagicMock()
        self.server = Server(self.validator)
        self.oauth.initialize(self.server)

        self.fake_response = ({
            "Content-Type": "application/x-www-form-urlencoded"
        }, "a=b&c=d", "200 FooOK")

    def test_valid_response(self):
        @bottle.route('/foo')
        @self.oauth.create_token_response()
        def test(): return None

        with mock.patch("oauthlib.oauth2.Server.create_token_response", return_value=self.fake_response) as mocked:
            app_response = self.urlopen("/foo")
            self.assertEqual(app_response['code'], 200)
            self.assertEqual(app_response['status'], "FooOK")
            self.assertEqual(app_response['body'], tob("a=b&c=d"))
            self.assertEqual(app_response['header']['Content-Type'], "application/x-www-form-urlencoded")
        mocked.assert_called_once()

    def test_override_response(self):
        @bottle.route('/foo')
        @self.oauth.create_token_response()
        def test(): return "my=custom&body="

        with mock.patch("oauthlib.oauth2.Server.create_token_response", return_value=self.fake_response) as mocked:
            app_response = self.urlopen("/foo")
            self.assertEqual(app_response['code'], 200)
            self.assertEqual(app_response['status'], "FooOK")
            self.assertEqual(app_response['body'], tob("my=custom&body="))
            self.assertEqual(app_response['header']['Content-Type'], "application/x-www-form-urlencoded")
        mocked.assert_called_once()


class test_create_introspect_decorators(ServerTestBase):
    def setUp(self):
        super().setUp()
        self.oauth = BottleOAuth2(self.app)
        self.validator = mock.MagicMock()
        self.server = Server(self.validator)
        self.oauth.initialize(self.server)

        self.fake_response = ({
            "Content-Type": "application/json"
        }, "{'valid': true, 'foo': 'bar'}", "200 FooOK")

    @unittest.skip("remove when introspect branch is merged into oauthlib")
    def test_valid_response(self):
        @bottle.route('/foo')
        @self.oauth.create_introspect_response()
        def test(): return None

        with mock.patch("oauthlib.oauth2.Server.create_introspect_response", return_value=self.fake_response) as mocked:
            app_response = self.urlopen("/foo")
            self.assertEqual(app_response['code'], 200)
            self.assertEqual(app_response['status'], "FooOK")
            self.assertEqual(app_response['body'], tob("a=b&c=d"))
            self.assertEqual(app_response['header']['Content-Type'], "application/x-www-form-urlencoded")
        mocked.assert_called_once()

    @unittest.skip("remove when introspect branch is merged into oauthlib")
    def test_override_response(self):
        @bottle.route('/foo')
        @self.oauth.create_introspect_response()
        def test(): return "{'valid': false}"

        with mock.patch("oauthlib.oauth2.Server.create_introspect_response", return_value=self.fake_response) as mocked:
            app_response = self.urlopen("/foo")
            self.assertEqual(app_response['code'], 200)
            self.assertEqual(app_response['status'], "FooOK")
            self.assertEqual(app_response['body'], tob("{'valid': false}"))
            self.assertEqual(app_response['header']['Content-Type'], "application/json")
        mocked.assert_called_once()
 

class test_create_authorization_decorators(ServerTestBase):
    def setUp(self):
        super().setUp()
        self.oauth = BottleOAuth2(self.app)
        self.validator = mock.MagicMock()
        self.server = Server(self.validator)
        self.oauth.initialize(self.server)

        self.fake_response = ({
            "Content-Type": "application/x-www-form-urlencoded"
        }, "a=b&c=d", "200 FooOK")

    def test_valid_response(self):
        @bottle.route('/foo')
        @self.oauth.create_authorization_response()
        def test(): return None

        with mock.patch("oauthlib.oauth2.Server.create_authorization_response", return_value=self.fake_response) as mocked:
            app_response = self.urlopen("/foo", method="GET", query="scope=admin%20view%20write")
            self.assertEqual(app_response['code'], 200)
            self.assertEqual(app_response['status'], "FooOK")
            self.assertEqual(app_response['body'], tob("a=b&c=d"))
            self.assertEqual(app_response['header']['Content-Type'], "application/x-www-form-urlencoded")
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args[1]["scopes"], ['admin', 'view', 'write'])

    def test_override_response(self):
        @bottle.route('/foo')
        @self.oauth.create_authorization_response()
        def test(): return "my=custom&body="

        with mock.patch("oauthlib.oauth2.Server.create_authorization_response", return_value=self.fake_response) as mocked:
            app_response = self.urlopen("/foo")
            self.assertEqual(app_response['code'], 200)
            self.assertEqual(app_response['status'], "FooOK")
            self.assertEqual(app_response['body'], tob("my=custom&body="))
            self.assertEqual(app_response['header']['Content-Type'], "application/x-www-form-urlencoded")
        mocked.assert_called_once()


class test_create_revocation_decorators(ServerTestBase):
    def setUp(self):
        super().setUp()
        self.oauth = BottleOAuth2(self.app)
        self.validator = mock.MagicMock()
        self.server = Server(self.validator)
        self.oauth.initialize(self.server)

        self.fake_response = ({}, "", "200 fooOK")

    def test_valid_response(self):
        @bottle.route('/revoke')
        @self.oauth.create_revocation_response()
        def test(): return None

        with mock.patch("oauthlib.oauth2.Server.create_revocation_response", return_value=self.fake_response) as mocked:
            app_response = self.urlopen("/revoke")
            self.assertEqual(app_response['code'], 200)
            self.assertEqual(app_response['status'], "fooOK")
        mocked.assert_called_once()



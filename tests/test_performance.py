import bottle
from bottle_oauthlib import oauth2
from tests import AttrDict
import unittest


loop_iterations = 10000


class extract_params_auth(unittest.TestCase):
    def assertAuth(self, request):
        _, _, forms, headers = oauth2.extract_params(request)
        self.assertEqual(forms["client_id"], "foobar")
        self.assertEqual(forms["client_secret"], "barsecret")

    def test_loop_attrdict(self):
        request = AttrDict({
            "method": "GET",
            "url": "/sample_url",
            "content_type": "application/x-www-form-urlencoded; charset=utf-8",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
            },
            "forms": {},
            "body": "{}",
            "auth": ("foobar", "barsecret")
        })
        for i in range(0, loop_iterations):
            self.assertAuth(request)

    def test_loop_bottle_request(self):
        import base64
        import bottle
        from bottle import tob
        from bottle import touni
        import wsgiref.util

        payload = b'token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.6OIg9riYNt9tZ2aMM_CK6TyMKN3OAk0j1W2XDfqfYPU'
        e = {}
        wsgiref.util.setup_testing_defaults(e)
        e['wsgi.input'].write(payload)
        e['wsgi.input'].seek(0)
        e['REQUEST_METHOD'] = "POST"
        e['CONTENT_TYPE'] = "application/x-www-form-urlencoded; charset=utf-8"
        e['CONTENT_LENGTH'] = str(len(payload))
        e['HTTP_AUTHORIZATION'] = 'basic %s' % touni(base64.b64encode(tob('%s:%s' % ('foobar', 'barsecret'))))

        request = bottle.BaseRequest(e)
        
        for i in range(0, loop_iterations):
            self.assertAuth(request)

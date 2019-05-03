from bottle import tob
from .bottle_tools import ServerTestBase
from tests.examples import quickstart_resourceserver


class test_quickstart(ServerTestBase):
    def setUp(self):
        import importlib
        importlib.reload(quickstart_resourceserver)
        super().setUp(quickstart_resourceserver.app)

    def test_no_token(self):
        resp = self.urlopen("/mail")
        self.assertEqual(403, resp['code'], resp['body'])

    def test_access_mail_granted(self):
        resp = self.urlopen("/mail", env={'HTTP_AUTHORIZATION': "Bearer sample_token"})
        self.assertEqual(200, resp['code'], resp['body'])
        self.assertEqual(tob("Welcome john, you have permissioned clientA to use your mail"), resp['body'])

    def test_access_mail_and_calendar_granted(self):
        resp = self.urlopen("/mail_and_calendar", env={'HTTP_AUTHORIZATION': "Bearer sample_token"})
        self.assertEqual(200, resp['code'], resp['body'])
        self.assertEqual(tob("Welcome john, you have permissioned clientA to use your mail & calendar"), resp['body'])

    def test_access_photos_not_granted(self):
        resp = self.urlopen("/photos", env={'HTTP_AUTHORIZATION': "Bearer sample_token"})
        self.assertEqual(403, resp['code'], resp['body'])

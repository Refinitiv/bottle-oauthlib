from setuptools import setup
from os import path, getenv
import inspect


if getenv("PATCH_VERSION"):
    patch = getenv("PATCH_VERSION")
else:
    patch = "1"

packageVersion = ("1.0.{}".format(patch))

with open(path.join(path.dirname(path.abspath(inspect.getfile(inspect.currentframe()))), "requirements.in")) as fd:
    dependencies = fd.read().split('\n')

setup(
    name='bottle-oauthlib',
    version=packageVersion,
    description='Bottle OAuth2.0 OAuthLib server implementation',
    author="Thomson Reuters",
    author_email="EikonEdge.Infra-Dev@thomsonreuters.com",
    packages=['bottle_oauthlib'],
    install_requires=dependencies,
    test_suite='tests'
)

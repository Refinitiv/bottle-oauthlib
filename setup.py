from setuptools import setup
from os import path
import inspect


with open(path.join(path.dirname(path.abspath(inspect.getfile(inspect.currentframe()))), "requirements.in")) as fd:
    dependencies = fd.read().split('\n')

setup(
    name='bottle-oauthlib',
    version='1.0',
    description='Bottle OAuth2.0 OAuthLib server implementation',
    author="Thomson Reuters",
    author_email="EikonEdge.Infra-Dev@thomsonreuters.com",
    packages=['bottle_oauthlib'],
    install_requires=dependencies,
    tests_require=dependencies,
)

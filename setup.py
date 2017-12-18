from setuptools import setup
from os import path, getenv
import inspect


with open(path.join(path.dirname(path.abspath(inspect.getfile(inspect.currentframe()))), "requirements.in")) as fd:
    dependencies = fd.read().split('\n')

setup(
    name='bottle-oauthlib',
    version='1.0.1',
    description='Bottle plugin for OAuthLib framework (OAuth2.0)',
    license='BSD-3-Clause',
    author="Thomson Reuters",
    author_email="EikonEdge.Infra-Dev@thomsonreuters.com",
    packages=['bottle_oauthlib'],
    install_requires=dependencies,
    test_suite='tests',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Programming Language :: Python :: 3.6',
    ]
)

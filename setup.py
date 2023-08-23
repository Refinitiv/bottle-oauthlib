from setuptools import setup
import inspect
from os import path
import os


with open(path.join(path.dirname(path.abspath(inspect.getfile(inspect.currentframe()))), "requirements.in")) as fd:
    dependencies = fd.read().split('\n')

try:
    version_tag = os.environ["GITHUB_REF_NAME"]
except KeyError:
    version_tag = "1.0.0"

setup(
    name='bottle-oauthlib',
    version=version_tag,
    description='Bottle adapter for OAuthLib framework (OAuth2.0)',
    url='https://github.com/Refinitiv/bottle-oauthlib',
    license='BSD-3-Clause',
    author="Refinitiv",
    author_email="EikonEdge.Infra-Dev@Refinitiv.com",
    packages=['bottle_oauthlib'],
    install_requires=dependencies,
    test_suite='tests',
    tests_require=['oauthlib>=3.0.0'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ]
)

Keystone: Identity Service
==========================

Keystone is a proposed independent authentication service for [OpenStack](http://www.openstack.org).

This initial proof of concept aims to address the current use cases in Swift and Nova which are:

* REST-based, token auth for Swift
* many-to-many relationship between identity and tenant for Nova.


SERVICES:
---------

* Keystone    - authentication service
* Auth_Token  - WSGI middleware that can be used to handle token auth protocol (WSGI or remote proxy)
* Echo        - A sample service that responds by returning call details

Also included:

* Auth_Basic  - Stub for WSGI middleware that will be used to handle basic auth
* Auth_OpenID - Stub for WSGI middleware that will be used to handle openid auth protocol
* RemoteAuth  - WSGI middleware that can be used in services (like Swift, Nova, and Glance) when Auth middleware is running remotely


ENVIRONMENT & DEPENDENCIES:
---------------------------
see pip-requires for dependency list
Setup:
Install http://pypi.python.org/pypi/setuptools
    sudo easy_install pip
    sudo pip install -r pip-requires


RUNNING KEYSTONE:
-----------------

    $ cd bin
    $ ./keystoned


RUNNING TEST SERVICE:
---------------------

    Standalone stack (with Auth_Token)
    $ cd echo/bin
    $ ./echod

    Distributed stack (with RemoteAuth local and Auth_Token remote)
    $ cd echo/bon
    $ ./echod --remote

    in separate session
    $ cd keystone/auth_protocols
    $ python auth_token.py --remote


DEMO CLIENT:
---------------------
    $ cd echo/echo
    $ python echo_client.py
    Note: this requires tests data. See section TESTING for initializing data


TESTING
-------

After starting keystone a keystone.db sqlite database should be created in the keystone folder.

Add test data to the database:

    $ sqlite3 keystone/keystone.db < test/test_setup.sql

To clean the test database

    $ sqlite3 keystone/keystone.db < test/kill.sql

To run unit tests:

    $ python test/unit/test_identity.py

To run client demo (with all auth middleware running locally on sample service):

    $ ./echo/bin/echod
    $ python echo/echo/echo_client.py


To perform contract validation and load testing, use SoapUI (for now).

Using SOAPUI:

Download [SOAPUI](http://sourceforge.net/projects/soapui/files/):

To Test Keystone Service:

* File->Import Project
* Select tests/IdentitySOAPUI.xml
* Double click on "Keystone Tests" and press the green play (>) button


Unit Test on Identity Services
------------------------------
In order to run the unit test on identity services:
* start the keystone server
* cat test_setup.sql |sqlite ../../keystone/keystone.db
* go to unit test/unit directory
* python test_identity.py

For more on unit testing please refer

 python test_identity --help



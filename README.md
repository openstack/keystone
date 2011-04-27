Keystone: Identity Service
==========================

Keystone is a proposed independent authentication service for [OpenStack](http://www.openstack.org).

This initial proof of concept aims to address the current use cases in Swift and Nova which are:

* REST-based, token auth for Swift
* many-to-many relationship between identity and tenant for Nova.


SERVICES:
---------

* Keystone - authentication service
* Auth_Protocal_Token - WSGI middleware that can be used to handle token auth protocol (WSGI or remote proxy)
* Echo     - A sample service that responds by returning call details

Also included:
* Auth_Protocal_Basic - Stub for WSGI middleware that will be used to handle basic auth
* Auth_Protocal_OpenID - Stub for WSGI middleware that will be used to handle openid auth protocol

DEPENDENCIES:
-------------

* bottle
* eventlet
* lxml
* Paste
* PasteDeploy
* PasteScript
* SQLAlchemy
* SQLite3
* webob


SETUP:
------

Install http://pypi.python.org/pypi/setuptools

    sudo easy_install bottle
    sudo easy_install eventlet
    sudo easy_install lxml
    sudo easy_install paste
    sudo easy_install pastedeploy
    sudo easy_install pastescript
    sudo easy_install pysqlite
    sudo easy_install sqlalchemy
    sudo easy_install webob

Or using pip:

    sudo pip install -r pip-requires


RUNNING KEYSTONE:
-----------------

    $ cd keystone
    $ python identity.py


RUNNING TEST SERVICE:
---------------------

Standalone stack (with PAPIAuth and Auth_Protocol_Token)
    $ cd echo/echo
    $ python echo.py

Distributed stack (with PAPIAuth local and Auth_Protocol_Token remote)
    $ cd echo/echo
    $ python echo.py --remote

    in separate session
    $ cd keystone/auth_protocol
    $ python auth_protocol_token.py --remote

DEMO CLIENT:
---------------------
    $ cd echo/echo
    $ python echo_client.py


INSTALLING KEYSTONE:
--------------------

    $ python setup.py build
    $ sudo python setup.py install


INSTALLING TEST SERVICE:
------------------------

    $ cd echo
    $ python setup.py build
    $ sudo python setup.py install


TESTING
-------

After starting identity.py a keystone.db sql-lite database should be created.

To test setup the test database:

    $ sqlite3 keystone/keystone.db < test/test_setup.sql

To clean the test database

    $ sqlite3 keystone/keystone.db < test/kill.sql

To run unit tests:

    $ python test/unit/test_identity.py

To run client demo (with all auth middleware running locally on sample service):

    $ python echo/echo/echo.py
    $ python echo/echo/echo_client.py


To perform contract validation and load testing, use SoapUI (for now).

Using SOAPUI:

Download [SOAPUI](http://sourceforge.net/projects/soapui/files/):

To Test Identity Service:

* File->Import Project
* Select tests/IdentitySOAPUI.xml
* Double click on "Keystone Tests" and press the green play (>) button


Unit Test on Identity Services
------------------------------
In order to run the unit test on identity services, run from the keystone directory

 python identity.py

Once the Identity service is running, go to unit test/unit directory

 python test_identity.py

For more on unit testing please refer

python test_identity --help



DATABASE SCHEMA
---------------

    CREATE TABLE groups(group_id varchar(255),group_desc varchar(255),tenant_id varchar(255),FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id));
    CREATE TABLE tenants(tenant_id varchar(255), tenant_desc varchar(255), tenant_enabled INTEGER, PRIMARY KEY(tenant_id ASC));
    CREATE TABLE token(token_id varchar(255),user_id varchar(255),expires datetime,tenant_id varchar(255));
    CREATE TABLE user_group(user_id varchar(255),group_id varchar(255), FOREIGN KEY(user_id) REFERENCES user(id), FOREIGN KEY(group_id) REFERENCES groups(group_id));
    CREATE TABLE user_tenant(tenant_id varchar(255),user_id varchar(255),FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id),FOREIGN KEY(user_id) REFERENCES user(id));
    CREATE TABLE users(id varchar(255),password varchar(255),email varchar(255),enabled integer);

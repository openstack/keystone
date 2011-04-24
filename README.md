Keystone: Identity Service
==========================

Keystone is a proposed independent authentication service for [OpenStack](http://www.openstack.org).

This initial proof of concept aims to address the current use cases in Swift and Nova which are:

* REST-based, token auth for Swift
* many-to-many relationship between identity and tenant for Nova.


SERVICES:
---------

* Keystone - authentication service
* PAPIAuth - WSGI middleware that can be used in services (like Swift, Nova, and Glance) to perform authentication
* Echo     - A sample service that responds by returning call details


DEPENDENCIES:
-------------

* bottle
* eventlet
* lxml
* Paste
* PasteDeploy
* PasteScript
* simplejson
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
    sudo easy_install simplejson
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

    $ cd echo/echo
    $ python echo.py


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

Testing is kinda manual right now...and based on SOAP UI.  After
starting identity.py a keystone.db sql-lite database should be created.

To test setup the test database:

    $ sqlite3 keystone.db < test/test_setup.sql

To clean the test database

    $ sqlite3 keystone.db < test/kill.sql

Using SOAPUI:

Download [SOAPUI](http://sourceforge.net/projects/soapui/files/):

To Test Identity Service:

* File->Import Project
* Select tests/IdentitySOAPUI.xml
* Double click on "Keystone Tests" and press the green play (>) button


DATABASE SCHEMA
---------------

    CREATE TABLE groups(group_id varchar(255),group_desc varchar(255),tenant_id varchar(255),FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id));
    CREATE TABLE tenants(tenant_id varchar(255), tenant_desc varchar(255), tenant_enabled INTEGER, PRIMARY KEY(tenant_id ASC));
    CREATE TABLE token(token_id varchar(255),user_id varchar(255),expires datetime,tenant_id varchar(255));
    CREATE TABLE user_group(user_id varchar(255),group_id varchar(255), FOREIGN KEY(user_id) REFERENCES user(id), FOREIGN KEY(group_id) REFERENCES groups(group_id));
    CREATE TABLE user_tenant(tenant_id varchar(255),user_id varchar(255),FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id),FOREIGN KEY(user_id) REFERENCES user(id));
    CREATE TABLE users(id varchar(255),password varchar(255),email varchar(255),enabled integer);

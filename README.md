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
See pip-requires for dependency list

Setup:
Install http://pypi.python.org/pypi/setuptools
    sudo easy_install pip
    sudo pip install -r pip-requires

Configuration:
Keystone gets its configuration from command-line parameters or a .conf file. The file can be provided explicitely
on the command line otherwise the following logic applies (the conf file in use will be output to help
in troubleshooting:

1. config.py takes the config file from <topdir>/etc/keystone.conf
2. If the keystone package is also intalled on the system,
    /etc/keystone.conf or /etc/keystone/keystone.conf have higher priority than <top_dir>/etc/keystone.conf.

If you are also doing development on a system that has keystone.conf installed in /etc you may need to disambiguate it by providing the conf file in the command-line

     $ bin/keystone-control --confg-file etc/keystone.conf  --pid-file <pidfile> auth <start|stop|restart>

Path:
keystone-control calls keystone-auth and it needs to be in the PATH

     $ export PATH=<top_dir>/bin:$PATH


RUNNING KEYSTONE:
-----------------

    $ cd bin
    $ ./keystone-auth


RUNNING KEYSTONE FOR DEVELOPMENT (HACKING):
------------------------------

During  development, you can simply run as user (root not needed)

From the top Keystone directory (<topdir>)

     $ bin/keystone=auth

It dumps stdout and stderr onto the terminal.

If you want to specify additional parameters (optional):

     $ bin/keystone-control --pid-file <pidfile>  --config-file etc/keystone.conf auth <start|stop|restart>

RUNNING KEYSTONE AS ROOT IN PRODUCTION
--------------------------------------
In production, stdout and stderr need to be closed and all the output needs to be redirected to a log file.
Once the package is installed through setup tools, RPM, deb, or ebuild keystone-control is installed as /usr/sbin/keystone-control. Typically, it will be started a script in /etc/init.d/keystoned

keystone-control can invoke keystone-auth and start the keystone daemon with 

     $ /usr/sbin/keystone-control auth start

It writes the process id of the daemon into /var/run/keystone/keystine-auth.pid.
The daemon can be stopped with
 
     $ /usr/sbin/keystone-control auth stop

keystone-control has the infrastructure to start and stop multiple servers keystone-xxx  


RUNNING TEST SERVICE:
---------------------

    Standalone stack (with Auth_Token)
    $ cd echo/bin
    $ ./echod

    Distributed stack (with RemoteAuth local and Auth_Token remote)
    $ cd echo/bin
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

To run client demo (with all auth middleware running locally on sample service):

    $ ./echo/bin/echod
    $ python echo/echo/echo_client.py

To run unit tests:
* go to unit test/unit directory
* run tests: python test_keystone

There are 8 groups of tests. They can be run individually or as an entire colection. To run the entire test suite run

    $ python test_keystone.py

A test can also be run individually e.g.

    $ python test_token.py

For more on unit testing please refer

    $ python test_keystone.py --help


To perform contract validation and load testing, use SoapUI (for now).

Using SOAPUI:

Download [SOAPUI](http://sourceforge.net/projects/soapui/files/):

To Test Keystone Service:

* File->Import Project
* Select tests/IdentitySOAPUI.xml
* Double click on "Keystone Tests" and press the green play (>) button

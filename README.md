Keystone: OpenStack Identity Service
====================================

Keystone is an open-source authentication service built to be integrated into [OpenStack](http://www.openstack.org).


Core Concepts:
--------------
-Roles
-Tokens
-Groups
-Authentication Protocol Plugins

<table>
  <tr>
    <th>Concept</th><th align="left">Description</th>
  </tr>
  <tr>
    <td>User</td><td>A 'user' is a client who has been registered with Keystone.</td>
  </tr>
  <tr>
    <td>Role</td><td>A 'role' describes a responsibility which is linked to a given user.</td>
  </tr>
  <tr>
    <td>Token</td><td>A 'token' describes a temporary object which helps users authenticate themselves.</td>
  </tr>
  <tr>
    <td>Tenant</td><td>A 'tenant' describes an entity which houses multiple users. <br/>For example, a tenant might represent an 'account' or 'company' which contains an arbitrary number of users.</td>
  </tr>
  <tr>
    <td>Group</td></td>Unknown</td>
  </tr>
</table>


Built-In Services:
------------------

* bin/keystone  - Provides HTTP API for users and administrators
* bin/keystone-admin - Provides HTTP API for administrators
* bin/keystone-service - Provides HTTP API for users
* bin/keystone-manage - Provides command-line interface for managing all aspects of Keystone


Also included:

* Keystone    - Service and Admin API are available separately. Admin API allows management of tenants, roles, and users as well.
* Auth_Basic  - Stub for WSGI middleware that will be used to handle basic auth
* Auth_OpenID - Stub for WSGI middleware that will be used to handle openid auth protocol
* RemoteAuth  - WSGI middleware that can be used in services (like Swift, Nova, and Glance) when Auth middleware is running remotely


RUNNING KEYSTONE:
-----------------

Starting both Admin and Service API endpoints:

    $ cd bin
    $ ./keystone

Starting the auth server only (exposes the Service API):

    $ cd bin
    $ ./keystone-auth

Starting the admin server only (exposes the Admin API):

    $ cd bin
    $ ./keystone-admin

All above files take parameters from etc/keystone.conf file under the Keystone root folder by default



DEPENDENCIES:
-------------
See tools/pip-requires for dependency list. The list of dependencies should not add to what already is needed to run other OpenStack services.

Setup:

    # Install http://pypi.python.org/pypi/setuptools
    sudo easy_install pip
    sudo pip install -r tools/pip-requires


RUNNING THE TEST SERVICE (Echo.py):
----------------------------------

    Standalone stack (with Auth_Token)
    $ cd echo/bin
    $ ./echod

    Distributed stack (with RemoteAuth local and Auth_Token remote)
    $ cd echo/bin
    $ ./echod --remote

    in separate session
    $ cd keystone/auth_protocols
    $ python auth_token.py


DEMO CLIENT:
------------
A sample client that gets a token from Keystone and then uses it to call Echo (and a few other example calls):

    $ cd echo/echo
    $ python echo_client.py
    Note: this requires test data. See section TESTING for initializing data



TESTING:
--------
A set of sample data can be added by running a shell script:

    $ ./bin/sampledata.sh

The script calls keystone-manage to create the sample data.

After starting keystone or running keystone-manage a keystone.db sqlite database should be created in the keystone folder.


To run client demo (with all auth middleware running locally on sample service):

    $ ./echo/bin/echod
    $ python echo/echo/echo_client.py

NOTE: NOT ALL TESTS CONVERTED TO NEW MODEL YET. MANY FAIL. THIS WILL BE ADDRESSED SOON.

To run unit tests:

* go to unit test/unit directory
* run tests: python test_keystone

There are 10 groups of tests. They can be run individually or as an entire colection. To run the entire test suite run

    $ python test_keystone.py

A test can also be run individually e.g.

    $ python test_token.py

For more on unit testing please refer

    $ python test_keystone.py --help


To perform contract validation and load testing, use SoapUI (for now).


Using SOAPUI:

First, download [SOAPUI](http://sourceforge.net/projects/soapui/files/):

To Test Keystone Service:

* File->Import Project
* Select tests/IdentitySOAPUI.xml
* Double click on "Keystone Tests" and press the green play (>) button


ADDITIONAL INFORMATION:
-----------------------

Configuration:
Keystone gets its configuration from command-line parameters or a .conf file. The file can be provided explicitely
on the command line otherwise the following logic applies (the conf file in use will be output to help
in troubleshooting:

1. config.py takes the config file from <topdir>/etc/keystone.conf
2. If the keystone package is also intalled on the system,
    /etc/keystone.conf or /etc/keystone/keystone.conf have higher priority than <top_dir>/etc/keystone.conf.

CURL commands:

   $ curl -d '{"passwordCredentials": {"username": "joeuser", "password": "secrete"}}' -H "Content-type: application/json" http://localhost:8081/v2.0/token

   $ curl -d '{"passwordCredentials": {"username": "joeuser", "password": "secrete", "tenant": "1234"}}' -H "Content-type: application/json" http://localhost:8081/v2.0/token

Load Testing:

   $ # Create post data

   $ echo '{"passwordCredentials": {"username": "joeuser", "password": "secrete", "tenant": "1234"}}' > post_data

   $ # Call Apache Bench

   $ ab -c 30 -n 1000 -T "application/json" -p post_data http://127.0.0.1:8081/v2.0/token


NOVA Integration:
-----------------

Initial support for using keystone as nova's identity component has been started.

    # clone projects
    bzr clone lp:nova
    git clone git://github.com/khussein/keystone.git

    # link keystone into the nova root dir
    ln -s keystone/keystone nova/keystone

    # run nova-api based on the paste config in keystone
    nova/bin/nova-api --api_paste_config=keystone/docs/nova-api-paste.ini

Assuming you added the test data using bin/sampledata.sh, you can then use joeuser/secrete

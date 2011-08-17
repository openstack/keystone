# Keystone: OpenStack Identity Service

Keystone is a proposed independent authentication service for [OpenStack](http://www.openstack.org).

This initial proof of concept aims to address the current use cases in Swift and Nova which are:

* REST-based, token auth for Swift
* many-to-many relationship between identity and tenant for Nova.

# For Users

## User Guide & Concepts

The [`Developer Guide`](https://github.com/rackspace/keystone/raw/master/keystone/content/identitydevguide.pdf) 
documents the APIs to call and how to use them.

#### Core Concepts:
<table>
  <tr>
    <th>Concept</th><th align="left">Description</th>
  </tr>
  <tr>
    <td>User</td><td>An identity stored in the Keystone identity store used by a client to authenticate to Keystone.</td>
  </tr>
  <tr>
    <td>Tenant</td><td>A container which houses multiple resources. <br/>For example, a tenant might represent an 'account' or 'company' which contains an arbitrary number of compute resources. One or more users may be assiciated and have rights to a tenant.</td>
  </tr>
  <tr>
    <td>Role</td><td>A responsibility which is linked to a given user (and optionally scoped to a particular tenant).</td>
  </tr>
  <tr>
    <td>Token</td><td>A 'token' describes a temporary object obtained by clients from Keystone and used to identify themselves to an OpenStack service.</td>
  </tr>
</table>

## Running Keystone

#### Setup

    $ sudo pip install -r tools/pip-requires
    $ sudo python setup.py install

#### Starting services
Starting both Admin and Service API endpoints:

    $ ./bin/keystone

### Temporary fix for Segfault

On some OSes, specifically Fedora 15, the current versions of
greenlet/eventlet segfault when running keystone. To fix this, install
the development versions of greenlet and eventlet

    $ pip uninstall greenlet eventlet
    $ cd <appropriate working directory>
    $ hg clone https://bitbucket.org/ambroff/greenlet
    $ cd greenlet
    $ sudo python setup.py install

    $ cd <appropriate working directory>
    $ hg clone https://bitbucket.org/which_linden/eventlet
    $ cd eventlet
    $ sudo python setup.py install


# For Keystone Contributors

## Components

#### Services

* Keystone    - identity store and authentication service
* Auth_Token  - WSGI middleware that can be used to handle token auth protocol (WSGI or remote proxy)
* Echo        - A sample service that responds by returning call details

#### Also included:

* Keystone    - Service and Admin API are available separately. Admin API allows management of tenants, roles, and users as well.
* Auth_Basic  - Stub for WSGI middleware that will be used to handle basic auth
* Auth_OpenID - Stub for WSGI middleware that will be used to handle openid auth protocol (to be implemented)
* RemoteAuth  - WSGI middleware that can be used in services (like Swift, Nova, and Glance) when Auth middleware is running remotely

#### Built-In commands:

* bin/keystone  - Provides HTTP API for users and administrators
* bin/keystone-admin - Provides HTTP API for administrators
* bin/keystone-service - Provides HTTP API for users
* bin/keystone-manage - Provides command-line interface for managing all aspects of Keystone

By default, configuration parameters are parsed from `etc/keystone.conf`.

## Dependencies

You may need to prefix your `pip install` commands with `sudo`, depending on your environment.

<pre>
# Show dependencies
$ cat tools/pip-requires

# Install dependencies (for production, testing, and development)
$ pip install -r tools/pip-requires

# Optional: Install Memcache (if enabled as a backend)
Refer #(http://memcached.org/)
</pre>

## Running Keystone

Starting both Admin and Service API endpoints:

    $ ./bin/keystone

Starting the auth server only (exposes the Service API):

    $ ./bin/keystone-auth

Starting the admin server only (exposes the Admin API):

    $ ./bin/keystone-admin

By default, configuration parameters (such as the IP and port binding for each service) are parsed from `etc/keystone.conf`.


## Running Tests

Before running tests, ensure you have installed the testing dependencies as described in the Dependencies section above.

To run the test suite in a single command:

    $ python keystone/test/run_tests.py


#### Sample data
A set of sample data can be added by running a shell script:

    $ ./bin/sampledata

The script calls `keystone-manage` to create the sample data.

After starting keystone or running `keystone-manage` a `keystone.db` sqlite database should be created in the keystone folder.


#### Demo
To run client demo (with all auth middleware running locally on sample service):

    $ ./examples/echo/bin/echod
    $ python examples/echo/echo_client.py


#### API Validation
To perform contract validation and load testing, use SoapUI (for now).

Using SOAPUI:

1. First, download [SOAPUI](http://sourceforge.net/projects/soapui/files/):

2. To Test Keystone Service:

* File->Import Project
* Select tests/IdentitySOAPUI.xml
* Double click on "Keystone Tests" and press the green play (>) button


## Writing Documentation

### Editing and Compiling the Developer Guide

Users of the Keystone API are often developers making ReSTfull calls to Keystone. The guide to provide them
information is therefore called a `Developer Guide`. Developer in this case is not to be confused with developers
working on the Keystone source code itself.

The [dev guide](https://github.com/rackspace/keystone/raw/master/keystone/content/identitydevguide.pdf) is automatically
generated from XML and other artifacts that live in the [OpenStack Manuals project](https://launchpad.net/openstack-manuals).

To build the Developer Guide from source, you need [Maven](http://maven.apache.org/). To build the docs and publish a new PDF:

    $ cd to folder with the pom.xml file
    $ mvn clean generate-sources && cp target/docbkx/pdf/identitydevguide.pdf ../../keystone/content/identitydevguide.pdf

The output will go into the `target` folder (the source is in `src`). Output generated is PDF and webhelp.

### Editing and Compiling the Admin Guide

The Admin guide is written in RST and compiled using sphinx. From the `keystone` folder:

    $ python setup.py build_sphinx && firefox build/sphinx/html/index.html


## Additional Information:

#### Configuration:
Keystone gets its configuration from command-line parameters or a .conf file. The file can be provided explicitely
on the command line otherwise the following logic applies (the conf file in use will be output to help
in troubleshooting:

1. config.py takes the config file from <topdir>/etc/keystone.conf
2. If the keystone package is also intalled on the system,
    /etc/keystone.conf or /etc/keystone/keystone.conf have higher priority than <top_dir>/etc/keystone.conf.

#### CURL commands
<pre>
    # Get an unscoped token
    
    $ curl -d '{"passwordCredentials": {"username": "joeuser", "password": "secrete"}}' -H "Content-type: application/json" http://localhost:5000/v2.0/tokens

    # Get a token for a tenant

    $ curl -d '{"passwordCredentials": {"username": "joeuser", "password": "secrete", "tenantId": "1234"}}' -H "Content-type: application/json" http://localhost:5000/v2.0/tokens

    # Get an admin token

    $ curl -d '{"passwordCredentials": {"username": "admin", "password": "secrete"}}' -H "Content-type: application/json" http://localhost:5001/v2.0/tokens
</pre>

#### Load Testing

<pre>
   # Create post data

   $ echo '{"passwordCredentials": {"username": "joeuser", "password": "secrete", "tenantId": "1234"}}' > post_data

   # Call Apache Bench

   $ ab -c 30 -n 1000 -T "application/json" -p post_data http://127.0.0.1:5001/v2.0/tokens
</pre>

## NOVA Integration

Initial support for using keystone as nova's identity component has been started.

    # clone projects
    bzr clone lp:nova
    git clone git://github.com/rackspace/keystone.git

    # link keystone into the nova root dir
    ln -s keystone/keystone nova/keystone

    # run nova-api based on the paste config in keystone
    nova/bin/nova-api --api_paste_config=keystone/examples/paste/nova-api-paste.ini

Assuming you added the test data using bin/sampledata, you can then use joeuser/secrete

## Swift Integration - Quick Start

1.  Install Swift, either from trunk or version 1.4.1 (once it's released) or
    higher. Do the standard SAIO install with the included TempAuth to be sure
    you have a working system to start with. This step is beyond the scope of
    this quick start; see http://swift.openstack.org/development_saio.html for
    a Swift development set up guide. Once you have a working Swift install, go
    ahead and shut it down for now (the default Swift install uses the same
    ports Keystone wants):

        $ swift-init all stop

2.  Obtain and install a source copy of Keystone:

        $ git clone https://github.com/rackspace/keystone.git ~/keystone
        ...
        $ cd ~/keystone && sudo python setup.py develop
        ...

3.  Start up the Keystone service:

        $ cd ~/keystone/bin && ./keystone
        Starting the Legacy Authentication component
        Service API listening on 0.0.0.0:5000
        Admin API listening on 0.0.0.0:5001

4.  In another window, edit the `~/keystone/keystone/test/sampledata.py` file,
    find the `swift.publicinternets.com` text and replace it with the URL to
    your Swift cluster using the following format (note that we're going to
    change Swift to run on port 8888 later):
    `http://127.0.0.1:8888/v1/AUTH_%tenant_id%`

5.  Create the sample data entries:

        $ cd ~/keystone/bin && ./sampledata
        ...

6.  Reconfigure Swift's proxy server to use Keystone instead of TempAuth.
    Here's an example `/etc/swift/proxy-server.conf`:

        [DEFAULT]
        bind_port = 8888
        user = <user>

        [pipeline:main]
        pipeline = catch_errors cache keystone proxy-server

        [app:proxy-server]
        use = egg:swift#proxy
        account_autocreate = true

        [filter:keystone]
        use = egg:keystone#tokenauth
        auth_protocol = http
        auth_host = 127.0.0.1
        auth_port = 5001
        admin_token = 999888777666
        delay_auth_decision = 0
        service_protocol = http
        service_host = 127.0.0.1
        service_port = 8100
        service_pass = dTpw

        [filter:cache]
        use = egg:swift#memcache
        set log_name = cache

        [filter:catch_errors]
        use = egg:swift#catch_errors

7.  Start Swift back up with the new configuration:

        $ swift-init main start
        ...

8.  Use `swift` to check everything works (note: you currently have to create a
    container or upload something as your first action to have the account
    created; there's a Swift bug to be fixed soon):

        $ swift -A http://127.0.0.1:5000/v1.0 -U joeuser -K secrete post container
        $ swift -A http://127.0.0.1:5000/v1.0 -U joeuser -K secrete stat -v
        StorageURL: http://127.0.0.1:8888/v1/AUTH_1234
        Auth Token: 74ce1b05-e839-43b7-bd76-85ef178726c3
           Account: AUTH_1234
        Containers: 1
           Objects: 0
             Bytes: 0
        Accept-Ranges: bytes
        X-Trans-Id: tx25c1a6969d8f4372b63912f411de3c3b

**Note: Keystone currently allows any valid token to do anything with any
account.**

But, it works as a demo!


## I want OpenStack (all of it)

To get an opinionated install of nova, keystone, dashboard and glance using openstack apis:

    # create a maverick cloud server
    curl -O https://github.com/cloudbuilders/deploy.sh/raw/master/nova.sh
    chmod 755 nova.sh
    export USE_GIT=1         # checkout source using github mirror
    export ENABLE_VOLUMES=0  # disable volumes
    export ENABLE_DASH=1     # install & configure dashboard
    export ENABLE_GLANCE=1   # install & configure glance image service
    export ENABLE_KEYSTONE=1 # install & configure keystone (unified auth)
    ./nova.sh branch
    ./nova.sh install
    # nova's patched libvirt ppa doesn't work on cloud servers, revert to old libvirt
    apt-get install -y --force-yes libvirt0=0.8.3-1ubuntu14.1 libvirt-bin=0.8.3-1ubuntu14.1 python-libvirt=0.8.3-1ubuntu14.1
    ./nova.sh run


## Relevant Technologies, Standards, and Links

### Useful links

https://sites.google.com/site/oauthgoog/Overlap


### Protocols
We could potentially integrate with those:

[WebID](http://www.w3.org/2005/Incubator/webid/spec/) - See also: (http://www.w3.org/wiki/Foaf+ssl)

[OpenID](http://openid.net/) and/or [OpenIDConnect](http://openidconnect.com/)

[OAUTH2](http://oauth.net/2/)

[SAML] (http://saml.xml.org/)

### LDAP Setup

#### On a Mac

Using macports:

	sudo port install openldap

It appears the package `python-ldap` needs to be recompiled to work. So,
download it from: http://pypi.python.org/pypi/python-ldap/2.4.1

After unpacking, edit `setup.cfg` as shown below:

	library_dirs = /opt/local/lib
	include_dirs = /opt/local/include /usr/include/sasl

Then, run:

	python setup.py build
	sudo python setup.py install

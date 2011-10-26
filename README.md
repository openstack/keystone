# Keystone: OpenStack Identity Service

Keystone is a Python implementation of the [OpenStack](http://www.openstack.org) identity service API.

# Documentation

## For users and sysadmins

Learn how to install, configure, manage, and interact with the OpenStack
Identity Service API at the [OpenStack Documentation](http://docs.openstack.org/) site.

## For contributors

Learn how to setup a development environment and then test, run, and contribute to Keystone at the
[Contributor Documentation](http://keystone.openstack.org/) site.

# Questions/Feedback

Having trouble? We'd like to help!

* Try the documentation first — it's got answers to many common questions.
* Search for information in the archives of the [OpenStack mailing list](http://wiki.openstack.org/MailingLists), or post a question.
* Ask a question in the [#openstack IRC channel](http://wiki.openstack.org/UsingIRC).
* If you notice errors, please [open a bug](https://bugs.launchpad.net/keystone) and let us know! Please only use the bug tracker for criticisms and improvements. For tech support, use the resources above.

# For Contributors

## What's in the box?

### Services

* Keystone    - identity store and authentication service
* Auth_Token  - WSGI middleware that can be used to handle token auth protocol (WSGI or remote proxy)
* Echo        - A sample service that responds by returning call details

### Also included:

* Auth_Basic  - Stub for WSGI middleware that will be used to handle basic auth
* Auth_OpenID - Stub for WSGI middleware that will be used to handle openid auth protocol (to be implemented)
* RemoteAuth  - WSGI middleware that can be used in services (like Swift, Nova, and Glance) when Auth middleware is running remotely

### Built-In commands:

* bin/keystone  - Provides HTTP API for users and administrators
* bin/keystone-admin - Provides HTTP API for administrators
* bin/keystone-service - Provides HTTP API for users
* bin/keystone-manage - Provides command-line interface for managing all aspects of Keystone

## Running Keystone

Starting both Admin and Service API endpoints:

    $ ./bin/keystone

Starting the auth server only (exposes the Service API):

    $ ./bin/keystone-auth

Starting the admin server only (exposes the Admin API):

    $ ./bin/keystone-admin

By default, configuration parameters (such as the IP and port binding for each service) are parsed from `etc/keystone.conf`.

## Configuring Keystone

Keystone gets its configuration from command-line parameters or a `.conf` file. While command line parameters take precedence,
Keystone looks in the following location to find a configuration file:

 1. Command line parameter
 2. /etc/keystone.conf
 3. /etc/keystone/keystone.conf
 4. <topdir>/etc/keystone.conf

Additional configuration templates are maintained in `keystone/test/etc/` that may be useful as a reference.

### Editing and Building the API Developer Guide

Users of the Keystone API are often developers making ReSTful API calls to Keystone. The guide to provide them
information is therefore called a `Developer Guide`. Developer in this case is not to be confused with contributors
working on the Keystone codebase itself.

The developer guides are automatically generated from XML and other artifacts that live in the
[OpenStack Manuals project](https://launchpad.net/openstack-manuals).

To build the Developer Guide from source, you need [Maven](http://maven.apache.org/). To build the docs and publish a new PDF:

    $ cd to folder with the pom.xml file
    $ mvn clean generate-sources && cp target/docbkx/pdf/identitydevguide.pdf ../../keystone/content/identitydevguide.pdf

The output will go into the `target` folder (the source is in `src`). Output generated is PDF and webhelp.

# Additional Information:

## Sample data

A set of sample data can be loaded by running a shell script:

    $ ./bin/sampledata

The script calls `keystone-manage` to import the sample data.

After starting keystone or running `keystone-manage` a `keystone.db` sqlite database should be created in the keystone folder,
per the default configuration.

## Demo

To run client demo (with all auth middleware running locally on sample service):

    $ ./examples/echo/bin/echod
    $ python examples/echo/echo_client.py

## CURL commands

<pre>
    # Get an unscoped token
    $ curl -d '{"auth": {"passwordCredentials": {"username": "joeuser", "password": "secrete"}}}' -H "Content-type: application/json" http://localhost:5000/v2.0/tokens

    # Get a token for a tenant
    $ curl -d '{"auth": {"passwordCredentials": {"username": "joeuser", "password": "secrete"}, "tenantName": "customer-x"}}' -H "Content-type: application/json" http://localhost:5000/v2.0/tokens

    # Get an admin token
    $ curl -d '{"auth": {"passwordCredentials": {"username": "admin", "password": "secrete"}}}' -H "Content-type: application/json" http://localhost:35357/v2.0/tokens
</pre>

## Load Testing

<pre>
   # Create post data
   $ echo '{"auth": {"passwordCredentials": {"username": "joeuser", "password": "secrete", "tenantName": "customer-x"}}}' > post_data

   # Call Apache Bench
   $ ab -c 30 -n 1000 -T "application/json" -p post_data http://127.0.0.1:35357/v2.0/tokens
</pre>

## NOVA Integration

Initial support for using keystone as nova's identity component has been started.

    # clone projects
    bzr clone lp:nova
    git clone git://github.com/openstack/keystone.git

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

        $ git clone https://github.com/openstack/keystone.git ~/keystone
        ...
        $ cd ~/keystone && sudo python setup.py develop
        ...

3.  Start up the Keystone service:

        $ cd ~/keystone/bin && ./keystone
        Starting the Legacy Authentication component
        Service API listening on 0.0.0.0:5000
        Admin API listening on 0.0.0.0:35357

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
        auth_port = 35357
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

## LDAP Setup on a Mac

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

# Relevant Standards and Technologies

[Overlap of Identity Technologies](https://sites.google.com/site/oauthgoog/Overlap)

Keystone could potentially integrate with:

 1. [WebID](http://www.w3.org/2005/Incubator/webid/spec/) (See also [FOAF+SSL](http://www.w3.org/wiki/Foaf+ssl))
 2. [OpenID](http://openid.net/) and/or [OpenIDConnect](http://openidconnect.com/)
 3. [OAUTH2](http://oauth.net/2/)
 4. [SAML](http://saml.xml.org/)

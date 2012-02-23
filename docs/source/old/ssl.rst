..
      Copyright 2011-2012 OpenStack, LLC
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

===========================
x.509 Client Authentication
===========================

Purpose
=======

Allows the Keystone middleware to authenticate itself with the Keystone server
via an x.509 client certificate.  Both Service API and Admin API may be secured
with this feature.

Certificates
============

The following types of certificates are required.  A set of certficates is provided
in the examples/ssl directory with the Keystone distribution for testing.  Here
is the description of each of them and their purpose:

ca.pem
    Certificate Authority chain to validate against.

keystone.pem
    Public certificate for Keystone server.

middleware-key.pem
    Public and private certificate for Keystone middleware.

cakey.pem
    Private key for the CA.

keystonekey.pem
    Private key for the Keystone server.

Note that you may choose whatever names you want for these certificates, or combine
the public/private keys in the same file if you wish.  These certificates are just
provided as an example.

Configuration
=============

By default, the Keystone server does not use SSL. To enable SSL with client authentication,
modify the etc/keystone.conf file accordingly:

1. To enable SSL for Service API::

       service_ssl = True

2. To enable SSL for Admin API::

       admin_ssl = True

3. To enable SSL client authentication::

       cert_required = True

4. Set the location of the Keystone certificate file (example)::

       certfile = /etc/keystone/ca/certs/keystone.pem

5. Set the location of the Keystone private file (example)::

       keyfile = /etc/keystone/ca/private/keystonekey.pem

6. Set the location of the CA chain::

       ca_certs = /etc/keystone/ca/certs/ca.pem

Middleware
==========

Add the following to your middleware configuration to support x.509 client authentication.
If ``cert_required`` is set to ``False`` on the keystone server, the certfile and keyfile parameters
in steps 3) and 4) may be commented out.

1. Specify 'https' as the auth_protocol::

       auth_protocol = https

2. Modify the protocol in 'auth_uri' to be 'https' as well, if the service API is configured
   for SSL::

       auth_uri = https://localhost:5000/

3. Set the location of the middleware certificate file (example)::

       certfile = /etc/keystone/ca/certs/middleware-key.pem

4. Set the location of the Keystone private file (example)::

       keyfile = /etc/keystone/ca/certs/middleware-key.pem

For an example, take a look at the ``echo.ini`` middleware configuration for the 'echo' example
service in the examples/echo directory.

Testing
=======

You can test out how it works by using the ``echo`` example service in the ``examples/echo`` directory
and the certficates included in the ``examples/ssl`` directory. Invoke the ``echo_client.py`` with
the path to the client certificate::

    python echo_client.py -s <path to client certificate>

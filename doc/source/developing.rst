..
      Copyright 2011 OpenStack, LLC
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

========================
Developing with Keystone
========================

Get your development environment set up according to :doc:`setup`.

Running a development instance
==============================

Setting up a virtualenv
-----------------------

We recommend establishing a virtualenv to run keystone within. To establish
this environment, use the command::

    $> python tools/install_venv.py

This will create a local virtual environment in the directory ``.keystone-venv``.
Once created, you can activate this virtualenv for your current shell using:

    $> source .keystone-venv/bin/activate

The virtual environment can be disabled using the command::

    $> deactivate

You can also use ``tools\with_venv.sh`` to prefix commands so that they run
within the virtual environment. For more information on virtual environments,
see virtualenv_.

.. _virtualenv: http://www.virtualenv.org/

Running Keystone
----------------

To run the keystone Admin and API server instances, use::

    $> tools/with_venv.sh bin/keystone

Running a demo service that uses Keystone
-----------------------------------------
To run client demo (with all auth middleware running locally on sample service):

    $> tools/with_venv.sh examples/echo/bin/echod

which spins up a simple "echo" service on port 8090. To use a simple echo client:

    $> python examples/echo/echo_client.py

Interacting with Keystone
=========================

You can interact with Keystone through the command line using :doc:`keystone-manage`
which allows you to establish tenants, users, etc.

You can also interact with Keystone through it's REST API. There is a python
keystone client library python-keystoneclient_ which interacts exclusively through
the REST API.

.. _python-keystoneclient: https://github.com/4P/python-keystoneclient

The easiest way to establish some base information in Keystone to interact with is
to invoke::

    $> tools/with_venv.sh bin/sampledata

You can see the details of what that creates in ``keystone/test/sampledata.py``

interacting with keystone using curl
------------------------------------

Get an unscoped token::

    $> curl -d '{"auth": {"passwordCredentials": {"username": "joeuser", "password": "secrete"}}}' -H "Content-type: application/json" http://localhost:5000/v2.0/tokens

Get a token for a tenant::

    $> curl -d '{"auth": {"passwordCredentials": {"username": "joeuser", "password": "secrete"}, "tenantName": "customer-x"}}' -H "Content-type: application/json" http://localhost:5000/v2.0/tokens

Get an admin token::

    $> curl -d '{"auth": {"passwordCredentials": {"username": "admin", "password": "secrete"}}}' -H "Content-type: application/json" http://localhost:35357/v2.0/tokens

Get a list of tenants using the admin token::

    $> curl -d '{"auth": {"passwordCredentials": {"username": "admin", "password": "secrete"}}}' -H "Content-type: application/json" http://localhost:35357/v2.0/tokens

Enabling debugging middleware
-----------------------------

You can enable a huge amount of additional data (debugging information) about
the request and repsonse objects flowing through Keystone using the debugging
WSGI middleware.

To enable this, just modify the pipelines in ``etc/keystone.conf``, changing::

    [pipeline:admin]
    pipeline =
        urlrewritefilter
        admin_api

    [pipeline:keystone-legacy-auth]
    pipeline =
        urlrewritefilter
        legacy_auth
        RAX-KEY-extension
        service_api

to::

    [pipeline:admin]
    pipeline =
        debug
        urlrewritefilter
        admin_api

    [pipeline:keystone-legacy-auth]
    pipeline =
        debug
        urlrewritefilter
        legacy_auth
        RAX-KEY-extension
        service_api

..
    Licensed under the Apache License, Version 2.0 (the "License"); you may not
    use this file except in compliance with the License. You may obtain a copy
    of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations
    under the License.

================================
Identity API v2.0 and v3 History
================================

Specifications
==============

As of the Queens release, Keystone solely implements the `Identity API v3`_.
Support for `Identity API v2.0`_ has been removed in Queens in favor of
the `Identity API v3`_.

Identity API v3 is a superset of all the functionality available in the
Identity API v2.0 and several of its extensions, and provides a much more
consistent developer experience.

.. _`Identity API v2.0`: https://developer.openstack.org/api-ref/identity/v2/
.. _`Identity API v3`: https://developer.openstack.org/api-ref/identity/v3/

History
=======

You're probably wondering why Keystone does not implement a "v1" API. As a
matter of fact, one exists, but it actually predates OpenStack. The v1.x API
was an extremely small API documented and implemented by Rackspace for their
early public cloud products.

With the advent of OpenStack, Keystone served to provide a superset of the
authentication and multi-tenant authorization models already implemented by
Rackspace's public cloud, Nova, and Swift. Thus, Identity API v2.0 was
introduced.

Identity API v3 was established to introduce namespacing for users and projects
by using "domains" as a higher-level container for more flexible identity
management and fixed a security issue in the v2.0 API (bearer tokens appearing
in URLs).

How do I migrate from v2.0 to v3?
=================================

I am a deployer
---------------

You'll need to ensure the v3 API is included in your Paste pipeline, usually
``etc/keystone-paste.ini``. Our `latest sample configuration`_ includes the v3
application pipeline.

First define a v3 application, which refers to the v3 application factory
method:

.. code-block:: ini

    [app:service_v3]
    use = egg:keystone#service_v3

Then define a v3 pipeline, which terminates with the v3 application you defined
above:

.. code-block:: ini

    [pipeline:api_v3]
    pipeline = ... service_v3

Replace "..." with whatever middleware you'd like to run in front of the API
service. Our `latest sample configuration`_ documents our tested
recommendations, but your requirements may vary.

Finally, include the v3 pipeline in at least one ``composite`` application (but
usually both ``[composite:main]`` and ``[composite:admin]``), for example:

.. code-block:: ini

    [composite:main]
    use = egg:Paste#urlmap
    /v3 = api_v3
    ...

Once your pipeline is configured to expose v3, you need to ensure that you've
configured your service catalog in Keystone correctly. The simplest, and most
ideal, configuration would expose one identity with unversioned endpoints (note
the lack of ``/v2.0/`` or ``/v3/`` in these URLs):

- Service (type: ``identity``)

  - Endpoint (interface: ``public``, URL: ``http://identity:5000/``)
  - Endpoint (interface: ``admin``, URL: ``http://identity:35357/``)

If you were to perform a ``GET`` against either of these endpoints, you would
be greeted by an ``HTTP/1.1 300 Multiple Choices`` response, which newer
Keystone clients can use to automatically detect available API versions.

.. NOTE::

    Deploying v3 only requires a single application since administrator and
    end-user operations are handled by the same process, and not separated into
    two different applications. Depending on how v2.0 was configured, you might
    be able to decommission one endpoint. Until users are educated about which
    endpoint to use, the former admin API (e.g.  using port 35357) and the
    public API (e.g. using port 5000) can run the v3 API simulateously and
    serve both sets of users.

.. code-block:: bash

    $ curl -i http://identity:35357/
    HTTP/1.1 300 Multiple Choices
    Vary: X-Auth-Token
    Content-Type: application/json
    Content-Length: 755
    Date: Tue, 10 Jun 2014 14:22:26 GMT

    {"versions": {"values": [ ... ]}}

With unversioned ``identity`` endpoints in the service catalog, you should be
able to `authenticate with keystoneclient`_ successfully.

.. _`latest sample configuration`: https://git.openstack.org/cgit/openstack/keystone/tree/etc/keystone-paste.ini
.. _`authenticate with keystoneclient`: https://docs.openstack.org/python-keystoneclient/latest/using-api-v3.html#authenticating-using-sessions

I have a Python client
----------------------

The Keystone community provides first-class support for Python API consumers
via our client library, `python-keystoneclient`_. If you're not currently using
this library, you should, as it is intended to expose all of our HTTP API
functionality. If we're missing something you're looking for, please
contribute!

Adopting `python-keystoneclient`_ should be the easiest way to migrate to
Identity API v3.

.. _`python-keystoneclient`: https://pypi.org/project/python-keystoneclient/

I have a non-Python client
--------------------------

You'll likely need to heavily reference our `API documentation`_ to port your
application to Identity API v3.

.. _`API documentation`: https://developer.openstack.org/api-ref/identity/v3/

The most common operation would be password-based authentication including a
tenant name (i.e. project name) to specify an authorization scope. In Identity
API v2.0, this would be a request to ``POST /v2.0/tokens``:

.. code-block:: javascript

    {
        "auth": {
            "passwordCredentials": {
                "password": "my-password",
                "username": "my-username"
            },
            "tenantName": "project-x"
        }
    }

And you would get back a JSON blob with an ``access`` -> ``token`` -> ``id``
that you could pass to another web service as your ``X-Auth-Token`` header
value.

In Identity API v3, an equivalent request would be to ``POST /v3/auth/tokens``:

.. code-block:: javascript

    {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "domain": {
                            "id": "default"
                        },
                        "name": "my-username",
                        "password": "my-password"
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {
                        "id": "default"
                    },
                    "name": "project-x"
                }
            }
        }
    }

Note a few key differences when compared to the v2.0 API:

- A "tenant" in v2.0 became a "project" in v3.
- The authentication method (``password``) is explicitly identified.
- Both the user name (``my-username``) and project name (``project-x``) are
  namespaced by an owning domain (where ``id`` = ``default``). The "default"
  domain exists by default in Keystone, and automatically owns the namespace
  exposed by Identity API v2.0. Alternatively, you may reference users and
  projects that exist outside the namespace of the default domain, which are
  thus inaccessible to the v2.0 API.
- In v3, your token is returned to you in an ``X-Subject-Token`` header,
  instead of as part of the request body. You should still authenticate
  yourself to other services using the ``X-Auth-Token`` header.

Why do I see deployments with Keystone running on two ports?
============================================================

During development of the v2.0 API, operational functionality was isolated into
different applications within the project. One application was dedicated to
end-user functionality and its sole purpose was to authenticate and validate
user identities. The second application consisted of more features and allowed
operators the ability to manage their deployment by adding or deleting users,
creating projects, etc. These applications were referred to as the ``public``
and ``admin`` APIs, respectively. This deployment model was required by the
architecture of the v2.0 API. In a way, authorization was limited to the
application you had access to.

Once development began on the v3 API, the code paths for both applications were
merged into one. Instead of isolating functionality into separate applications,
all functionality was consolidated into a single application. Each v3 endpoint
or API is protected by policy instead. This makes deployment and management of
Keystone's infrastructure easier for operators to deploy and for users to
consume. As a result, Keystone deployments are not required to deploy separate
``admin`` and ``public`` endpoints, especially now that the v2.0 API
implementation has been removed.

HTTP/1.1 Chunked Encoding
=========================
.. WARNING::

    Running Keystone under HTTPD in the recommended (and tested) configuration does not support
    the use of ``Transfer-Encoding: chunked``. This is due to a limitation with the WSGI spec
    and the implementation used by ``mod_wsgi``. It is recommended that all
    clients assume Keystone will not support ``Transfer-Encoding: chunked``.

..
      Copyright 2011-2012 OpenStack Foundation
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

====================
Configuring Keystone
====================

Setting up other OpenStack Services
===================================

Creating Service Users
----------------------

To configure the OpenStack services with service users, we need to create
a project for all the services, and then users for each of the services. We
then assign those service users an ``admin`` role on the service project. This
allows them to validate tokens - and to authenticate and authorize other user
requests.

Create a project for the services, typically named ``service`` (however, the
name can be whatever you choose):

.. code-block:: bash

    $ openstack project create service

Create service users for ``nova``, ``glance``, ``swift``, and ``neutron``
(or whatever subset is relevant to your deployment):

.. code-block:: bash

    $ openstack user create nova --password Sekr3tPass --project service

Repeat this for each service you want to enable.

Create an administrative role for the service accounts, typically named
``admin`` (however the name can be whatever you choose). For adding the
administrative role to the service accounts, you'll need to know the
name of the role you want to add. If you don't have it handy, you can look it
up quickly with:

.. code-block:: bash

    $ openstack role list

Once you have it, grant the administrative role to the service users.

.. code-block:: bash

    $ openstack role add admin --project service --user nova

Defining Services
-----------------

Keystone also acts as a service catalog to let other OpenStack systems know
where relevant API endpoints exist for OpenStack Services. The OpenStack
Dashboard, in particular, uses this heavily - and this **must** be configured
for the OpenStack Dashboard to properly function.

The endpoints for these services are defined in a template, an example of
which is in the project as the file ``etc/default_catalog.templates``.

Keystone supports two means of defining the services, one is the catalog
template, as described above - in which case everything is detailed in that
template.

The other is a SQL backend for the catalog service, in which case after
Keystone is online, you need to add the services to the catalog:

.. code-block:: bash

    $ openstack service create compute --name nova \
                                    --description "Nova Compute Service"
    $ openstack service create ec2 --name ec2 \
                                   --description "EC2 Compatibility Layer"
    $ openstack service create image --name glance \
                                      --description "Glance Image Service"
    $ openstack service create identity --name keystone \
                                        --description "Keystone Identity Service"
    $ openstack service create object-store --name swift \
                                     --description "Swift Service"


Identity sources
================

One of the most impactful decisions you'll have to make when configuring
keystone is deciding how you want keystone to source your identity data.
Keystone supports several different choices that will substantially impact how
you'll configure, deploy, and interact with keystone.

You can also mix-and-match various sources of identity (see `Domain-specific
Configuration`_ for an example). For example, you can store OpenStack service users
and their passwords in SQL, manage customers in LDAP, and authenticate employees
via SAML federation.

.. _Domain-specific Configuration: admin/identity-domain-specific-config.html
.. support_matrix:: identity-support-matrix.ini

Public ID Generators
--------------------

Keystone supports a customizable public ID generator and it is specified in the
``[identity_mapping]`` section of the configuration file. Keystone provides a
sha256 generator as default, which produces regenerable public IDs. The
generator algorithm for public IDs is a balance between key size (i.e. the
length of the public ID), the probability of collision and, in some
circumstances, the security of the public ID. The maximum length of public ID
supported by keystone is 64 characters, and the default generator (sha256) uses
this full capability. Since the public ID is what is exposed externally by
keystone and potentially stored in external systems, some installations may
wish to make use of other generator algorithms that have a different trade-off
of attributes. A different generator can be installed by configuring the
following property:

* ``generator`` - identity mapping generator. Defaults to ``sha256``
  (implemented by :class:`keystone.identity.id_generators.sha256.Generator`)

.. WARNING::

    Changing the generator may cause all existing public IDs to be become
    invalid, so typically the generator selection should be considered
    immutable for a given installation.


SSL
===

A secure deployment should have keystone running in a web server (such as
Apache httpd), or behind an SSL terminator.

Limiting list return size
=========================

Keystone provides a method of setting a limit to the number of entities
returned in a collection, which is useful to prevent overly long response times
for list queries that have not specified a sufficiently narrow filter. This
limit can be set globally by setting ``list_limit`` in the default section of
``keystone.conf``, with no limit set by default. Individual driver sections may
override this global value with a specific limit, for example:

.. code-block:: ini

    [resource]
    list_limit = 100

If a response to ``list_{entity}`` call has been truncated, then the response
status code will still be 200 (OK), but the ``truncated`` attribute in the
collection will be set to ``true``.


Supported clients
=================

There are two supported clients, `python-keystoneclient`_ project provides
python bindings and `python-openstackclient`_ provides a command line
interface.

.. _`python-openstackclient`: https://docs.openstack.org/python-openstackclient/latest
.. _`python-keystoneclient`: https://docs.openstack.org/python-keystoneclient/latest


Authenticating with a Password via CLI
--------------------------------------

To authenticate with keystone using a password and ``python-openstackclient``,
set the following flags, note that the following user referenced below should
be granted the ``admin`` role.

* ``--os-username OS_USERNAME``: Name of your user
* ``--os-password OS_PASSWORD``: Password for your user
* ``--os-project-name OS_PROJECT_NAME``: Name of your project
* ``--os-auth-url OS_AUTH_URL``: URL of the keystone authentication server

You can also set these variables in your environment so that they do not need
to be passed as arguments each time:

.. code-block:: bash

    $ export OS_USERNAME=my_username
    $ export OS_PASSWORD=my_password
    $ export OS_PROJECT_NAME=my_project
    $ export OS_AUTH_URL=http://localhost:5000/v3

For example, the commands ``user list``, ``token issue`` and ``project create``
can be invoked as follows:

.. code-block:: bash

    # Using password authentication, with environment variables
    $ export OS_USERNAME=admin
    $ export OS_PASSWORD=secret
    $ export OS_PROJECT_NAME=admin
    $ export OS_AUTH_URL=http://localhost:5000/v3
    $ openstack user list
    $ openstack project create demo
    $ openstack token issue

    # Using password authentication, with flags
    $ openstack --os-username=admin --os-password=secret --os-project-name=admin --os-auth-url=http://localhost:5000/v3 user list
    $ openstack --os-username=admin --os-password=secret --os-project-name=admin --os-auth-url=http://localhost:5000/v3 project create demo

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

================
Services
================

.. toctree::
   :maxdepth: 1


What are services?
==================

Keystone includes service registry and service catalog functionality which it
uses to respond to client authentication requests with information useful to
clients in locating the list of available services they can access.

The Service entity in Keystone represents an OpenStack service that is integrated
with Keystone. The Service entity is also used as a reference from roles, endpoints,
and endpoint templates.

Keystone also includes an authorization mechanism to allow a service to own
its own roles and endpoints and prevent other services from changing or
modifying them.

Who can create services?
========================

Any user with the Admin or Service Admin roles in Keystone may create services.

How are services created?
=========================

Services can be created using ``keystone-manage`` or through the REST API using
the OS-KSADM extension calls.

Using ``keystone-manage`` (see :doc:`man/keystone-manage` for details)::

    $ keystone-manage add service compute nova 'This is a sample compute service'

Using the REST API (see `extensions dev guide <https://github.com/openstack/keystone/blob/master/keystone/content/admin/OS-KSADM-admin-devguide.pdf?raw=true>`_ for details)::

    $ curl -H "Content-type: application/json" -X POST -d '{
                "OS-KSADM:service": {
                    "name": "nova",
                    "type": "compute",
                    "description": "This is a sample compute service"
                }
            }' -H "X-Auth-Token: 999888777666" http://localhost:35357/v2.0/OS-KSADM/services/

How is service ownership determined?
====================================

Currently, the way to assign ownership to a service is to provide the owner's
user id in the keystone-manage add command::

    $ keystone-manage add service nova compute 'This is a sample compute service' joeuser

This will assign ownership to the new service to joeuser.

When a service has an owner, then only that owner (or a global Admin) can create and manage
roles that start with that service name (ex: "nova:admin") and manage endpoints
and endpoint templates associated with that service.

Listing services
================

Using ``keystone-manage``, the list of services and their owners can be listed::

    $ keystone-manage service list

    id  name    type     owner_id      description
    -------------------------------------------------------------------------------
    1   compute nova     joeuser       This is a sample compute service

Using the REST API, call ``GET /v2.0/OS-KSADM/services``

.. note: The rest API does not yet support service ownership

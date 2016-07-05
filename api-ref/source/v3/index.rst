:tocdepth: 2

===========================
 Identity API v3 (CURRENT)
===========================

The Identity service generates authentication tokens that permit access to the
OpenStack services REST APIs. Clients obtain this token and the URL endpoints
for other service APIs by supplying their valid credentials to the
authentication service.

Each time you make a REST API request to an OpenStack service, you supply your
authentication token in the X-Auth-Token request header.

Like most OpenStack projects, OpenStack Identity protects its APIs by defining
policy rules based on a role-based access control (RBAC) approach.

The Identity service configuration file sets the name and location of a JSON
policy file that stores these rules.

For information about Identity API protection, see
`Identity API protection with role-based access control (RBAC)
<http://docs.openstack.org/admin-guide/identity_service_api_protection.html>`_
in the OpenStack Cloud Administrator Guide.

This page lists the Identity API operations in the following order:

* `Authentication and token management`_
* `Credentials`_
* `Domains`_
* `Domain configuration`_
* `Groups`_
* `Policies`_
* `Projects`_
* `Regions`_
* `Roles`_
* `Service catalog and endpoints`_
* `Users`_

.. rest_expand_all::

.. include:: authenticate-v3.inc
.. include:: credentials.inc
.. include:: domains.inc
.. include:: domains-config-v3.inc
.. include:: groups.inc
.. include:: policies.inc
.. include:: projects.inc
.. include:: regions-v3.inc
.. include:: roles.inc
.. include:: service-catalog.inc
.. include:: users.inc

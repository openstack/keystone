.. -*- rst -*-

======================
 Domain configuration
======================

You can manage domain-specific configuration options.

Domain-specific configuration options are structured within their
group objects. The API supports only the ``identity`` and ``ldap``
groups. These groups override the default configuration settings
for the storage of users and groups by the Identity server.

You can create, update, and delete domain-specific configuration
options by using the HTTP PUT , PATCH , and DELETE methods. When
updating, it is only necessary to include those options that are
being updated.

To create an option, use the PUT method. The Identity API does not
return options that are considered sensitive, although you can
create and update these options. The only option currently
considered sensitive is the ``password`` option within the ``ldap``
group.

The API enables you to include sensitive options as part of non-
sensitive options. For example, you can include the password as
part of the ``url`` option.

If you try to create or update configuration options for groups
other than the ``identity`` or ``ldap`` groups, the ``Forbidden
(403)`` response code is returned.

For information about how to integrate the Identity service with
LDAP, see `Integrate Identity with LDAP <http://docs.openstack.org
/admin-guide/keystone_integrate_with_ldap.html>`_.


Show domain group option configuration
======================================

.. rest_method::  GET /v3/domains/{domain_id}/config/{group}/{option}

Shows details for a domain group option configuration.

The API supports only the ``identity`` and ``ldap`` groups. For the
``ldap`` group, a valid value is ``url`` or ``user_tree_dn``. For
the ``identity`` group, a valid value is ``driver``.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - group: group
   - option: option

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-config-group-option-show-response.json
   :language: javascript


Update domain group option configuration
========================================

.. rest_method::  PATCH /v3/domains/{domain_id}/config/{group}/{option}

Updates a domain group option configuration.

The API supports only the ``identity`` and ``ldap`` groups. For the
``ldap`` group, a valid value is ``url`` or ``user_tree_dn``. For
the ``identity`` group, a valid value is ``driver``.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity
   - domain_id: domain_id
   - group: group
   - option: option

Request Example
---------------

.. literalinclude:: ./samples/admin/domain-config-group-option-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-config-group-option-update-response.json
   :language: javascript


Delete domain group option configuration
========================================

.. rest_method::  DELETE /v3/domains/{domain_id}/config/{group}/{option}

Deletes a domain group option configuration.

The API supports only the ``identity`` and ``ldap`` groups. For the
``ldap`` group, a valid value is ``url`` or ``user_tree_dn``. For
the ``identity`` group, a valid value is ``driver``.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - group: group
   - option: option


Show domain group configuration
===============================

.. rest_method::  GET /v3/domains/{domain_id}/config/{group}

Shows details for a domain group configuration.

The API supports only the ``identity`` and ``ldap`` groups.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - group: group

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-config-group-show-response.json
   :language: javascript


Update domain group configuration
=================================

.. rest_method::  PATCH /v3/domains/{domain_id}/config/{group}

Updates a domain group configuration.

The API supports only the ``identity`` and ``ldap`` groups. If you
try to set configuration options for other groups, this call fails
with the ``Forbidden (403)`` response code.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity
   - domain_id: domain_id
   - group: group

Request Example
---------------

.. literalinclude:: ./samples/admin/domain-config-group-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-config-group-update-response.json
   :language: javascript


Delete domain group configuration
=================================

.. rest_method::  DELETE /v3/domains/{domain_id}/config/{group}

Deletes a domain group configuration.

The API supports only the ``identity`` and ``ldap`` groups.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
   - group: group


Show domain configuration
=========================

.. rest_method::  GET /v3/domains/{domain_id}/config

Shows details for a domain configuration.

Normal response codes: 200
Error response codes:413,405,404,403,401,400,503,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-config-show-response.json
   :language: javascript


Update domain configuration
===========================

.. rest_method::  PATCH /v3/domains/{domain_id}/config

Updates a domain configuration.

Normal response codes: 200
Error response codes:413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity
   - domain_id: domain_id

Request Example
---------------

.. literalinclude:: ./samples/admin/domain-config-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - url: url
   - driver: driver
   - ldap: ldap
   - config: config
   - user_tree_dn: user_tree_dn
   - identity: identity

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-config-update-response.json
   :language: javascript


Delete domain configuration
===========================

.. rest_method::  DELETE /v3/domains/{domain_id}/config

Deletes a domain configuration.

Error response codes:204,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id

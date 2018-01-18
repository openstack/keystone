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
LDAP, see `Integrate Identity with LDAP
<https://docs.openstack.org/keystone/latest/admin/identity-integrate-with-ldap.html>`_.

Show default configuration settings
===================================

.. rest_method:: GET /v3/domains/config/default

The default configuration settings for the options that can be overridden
can be retrieved.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - config: domain_config
   - ldap: domain_ldap
   - url: domain_url
   - user_tree_dn: domain_user_tree_dn
   - identity: identity
   - driver: domain_driver

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-default-response.json
   :language: javascript


Show default configuration for a group
======================================

.. rest_method:: GET /v3/domains/config/{group}/default

Reads the default configuration settings for a specific group.

The API supports only the ``identity`` and ``ldap`` groups.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group: group_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - ldap: domain_ldap
   - url: domain_url
   - user_tree_dn: domain_user_tree_dn
   - identity: identity
   - driver: domain_driver

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 413
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-group-default-response.json
   :language: javascript


Show default option for a group
===============================

.. rest_method:: GET /v3/domains/config/{group}/{option}/default

Reads the default configuration setting for an option within a group.

The API supports only the ``identity`` and ``ldap`` groups. For the
``ldap`` group, a valid value is ``url`` or ``user_tree_dn``. For
the ``identity`` group, a valid value is ``driver``.

Relationship:
``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - group: group_id_path
   - option: option

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - url: domain_url
   - driver: domain_driver
   - user_tree_dn: domain_user_tree_dn

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 413
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-group-option-default-response.json
   :language: javascript


Show domain group option configuration
======================================

.. rest_method::  GET /v3/domains/{domain_id}/config/{group}/{option}

Shows details for a domain group option configuration.

The API supports only the ``identity`` and ``ldap`` groups. For the
``ldap`` group, a valid value is ``url`` or ``user_tree_dn``. For
the ``identity`` group, a valid value is ``driver``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - group: group_id_path
   - option: option

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 413
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-group-option-show-response.json
   :language: javascript


Update domain group option configuration
========================================

.. rest_method::  PATCH /v3/domains/{domain_id}/config/{group}/{option}

Updates a domain group option configuration.

The API supports only the ``identity`` and ``ldap`` groups. For the
``ldap`` group, a valid value is ``url`` or ``user_tree_dn``. For
the ``identity`` group, a valid value is ``driver``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - group: group_id_path
   - option: option
   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-group-option-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-group-option-update-response.json
   :language: javascript


Delete domain group option configuration
========================================

.. rest_method::  DELETE /v3/domains/{domain_id}/config/{group}/{option}

Deletes a domain group option configuration.

The API supports only the ``identity`` and ``ldap`` groups. For the
``ldap`` group, a valid value is ``url`` or ``user_tree_dn``. For
the ``identity`` group, a valid value is ``driver``.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - group: group_id_path
   - option: option

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503


Show domain group configuration
===============================

.. rest_method::  GET /v3/domains/{domain_id}/config/{group}

Shows details for a domain group configuration.

The API supports only the ``identity`` and ``ldap`` groups.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - group: group_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 413
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-group-show-response.json
   :language: javascript


Update domain group configuration
=================================

.. rest_method::  PATCH /v3/domains/{domain_id}/config/{group}

Updates a domain group configuration.

The API supports only the ``identity`` and ``ldap`` groups. If you
try to set configuration options for other groups, this call fails
with the ``Forbidden (403)`` response code.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - group: group_id_path
   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-group-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-group-update-response.json
   :language: javascript


Delete domain group configuration
=================================

.. rest_method::  DELETE /v3/domains/{domain_id}/config/{group}

Deletes a domain group configuration.

The API supports only the ``identity`` and ``ldap`` groups.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config_default``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - group: group_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503


Create domain configuration
===========================

.. rest_method::  PUT /v3/domains/{domain_id}/config

Creates a domain configuration.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-create-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200
   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 413
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-create-response.json
   :language: javascript


Show domain configuration
=========================

.. rest_method::  GET /v3/domains/{domain_id}/config

Shows details for a domain configuration.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 413
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-show-response.json
   :language: javascript


Update domain configuration
===========================

.. rest_method::  PATCH /v3/domains/{domain_id}/config

Updates a domain configuration.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-update-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - url: domain_url
   - driver: domain_driver
   - ldap: domain_ldap
   - config: domain_config
   - user_tree_dn: domain_user_tree_dn
   - identity: identity

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503

Example
~~~~~~~

.. literalinclude:: ./samples/admin/domain-config-update-response.json
   :language: javascript


Delete domain configuration
===========================

.. rest_method::  DELETE /v3/domains/{domain_id}/config

Deletes a domain configuration.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain_config``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path

Response
--------

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 405
   - 409
   - 413
   - 415
   - 503
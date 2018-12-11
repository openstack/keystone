=============================================================
Identity API protection with role-based access control (RBAC)
=============================================================

Like most OpenStack projects, Identity supports the protection of its
APIs by defining policy rules based on an RBAC approach. Identity stores
a reference to a policy JSON file in the main Identity configuration
file, ``/etc/keystone/keystone.conf``. Typically this file is named
``policy.json``, and contains the rules for which roles have access to
certain actions in defined services.

Each Identity API v3 call has a line in the policy file that dictates
which level of governance of access applies.

.. code-block:: none

   API_NAME: RULE_STATEMENT or MATCH_STATEMENT

Where:

``RULE_STATEMENT`` can contain ``RULE_STATEMENT`` or
``MATCH_STATEMENT``.

``MATCH_STATEMENT`` is a set of identifiers that must match between the
token provided by the caller of the API and the parameters or target
entities of the API call in question. For example:

.. code-block:: none

   "identity:create_user": "role:admin and domain_id:%(user.domain_id)s"

Indicates that to create a user, you must have the admin role in your
token. The ``domain_id`` in your token must match the
``domain_id`` in the user object that you are trying
to create, which implies this must be a domain-scoped token.
In other words, you must have the admin role on the domain
in which you are creating the user, and the token that you use
must be scoped to that domain.

Each component of a match statement uses this format:

.. code-block:: none

   ATTRIB_FROM_TOKEN:CONSTANT or ATTRIB_RELATED_TO_API_CALL

The Identity service expects these attributes:

Attributes from token:

- ``user_id``
- ``domain_id``
- ``project_id``

The ``project_id`` attribute requirement depends on the scope, and the
list of roles you have within that scope.

Attributes related to API call:

- ``user.domain_id``
- Any parameters passed into the API call
- Any filters specified in the query string

You reference attributes of objects passed with an object.attribute
syntax (such as, ``user.domain_id``). The target objects of an API are
also available using a target.object.attribute syntax. For instance:

.. code-block:: none

   "identity:delete_user": "role:admin and domain_id:%(target.user.domain_id)s"

would ensure that Identity only deletes the user object in the same
domain as the provided token.

Every target object has an ``id`` and a ``name`` available as
``target.OBJECT.id`` and ``target.OBJECT.name``. Identity retrieves
other attributes from the database, and the attributes vary between
object types. The Identity service filters out some database fields,
such as user passwords.

List of object attributes:

.. code-block:: yaml

   role:
        target.role.id
        target.role.name

   user:
        target.user.default_project_id
        target.user.description
        target.user.domain_id
        target.user.enabled
        target.user.id
        target.user.name

   group:
        target.group.description
        target.group.domain_id
        target.group.id
        target.group.name

   domain:
        target.domain.enabled
        target.domain.id
        target.domain.name

   project:
        target.project.description
        target.project.domain_id
        target.project.enabled
        target.project.id
        target.project.name

The default ``policy.json`` file supplied provides a somewhat
basic example of API protection, and does not assume any particular
use of domains. Refer to ``policy.v3cloudsample.json`` as an
example of multi-domain configuration installations where a cloud
provider wants to delegate administration of the contents of a domain
to a particular ``admin domain``. This example policy file also
shows the use of an ``admin_domain`` to allow a cloud provider to
enable administrators to have wider access across the APIs.

A clean installation could start with the standard policy file, to
allow creation of the ``admin_domain`` with the first users within
it. You could then obtain the ``domain_id`` of the admin domain,
paste the ID into a modified version of
``policy.v3cloudsample.json``, and then enable it as the main
``policy file``.

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

Mapping Combinations
====================

-----------
Description
-----------

During the authentication process an identity provider (IdP) will present
keystone with a set of user attributes about the user that is authenticating.
For example, in the SAML2 flow this comes to keystone in the form of a SAML
document and for the OpenID flow this comes from the token's claims.

The attributes are typically processed by third-party software and are presented
to keystone as environment variables. The original document from the IdP is
generally not available to keystone. This is how the `Shibboleth`, `Mellon` and
`mod_auth_openidc` implementations work.

The mapping format described in this document maps these environment variables
to a local keystone user. The mapping may also define group membership for
that user and projects the user can access.

An IdP has exactly one mapping specified per protocol. Mappings themselves can
be used multiple times by different combinations of IdP and protocol.

.. _important-prerequisites:

Important Prerequisites
------------------------

Before creating federated mappings, it's critical to understand how keystone
handles different resource types during federated authentication. The behavior
varies significantly depending on whether you're mapping to users, groups, or
projects:

**Users (with type=local)**
  Local users **must exist** in keystone's identity backend before federated
  authentication. If you map a federated user to a local user that doesn't
  exist, authentication will fail with an HTTP 401 Unauthorized error. Keystone
  will attempt to fetch the user details (id, name, roles, groups) from the
  identity backend, and if the user is not found, the authentication fails.

**Users (with type=ephemeral or no type specified)**
  Ephemeral users are created dynamically during authentication and become
  members of the identity provider's domain. They do not need to exist
  beforehand and all attributes must come from the IdP and mapping rules.

**Groups**
  Groups referenced in mappings **must already exist** in keystone. If a
  mapping references a group (by name or ID) that doesn't exist in the backend,
  keystone will **silently skip** that group assignment. The authentication
  will succeed, but the user won't receive the roles associated with the
  missing group. Check your logs for warnings about missing groups.

**Projects**
  Projects referenced in the ``projects`` section of a mapping **will be
  automatically created** if they don't exist. This is called auto-provisioning.
  Projects are created within the domain associated with the Identity Provider
  (or the domain specified in the mapping). This only applies to the ``projects``
  attribute in mappings - projects referenced through group memberships are not
  auto-created.

**Roles**
  Roles **must always exist** in the deployment. They are never auto-created.
  If a mapping references a role that doesn't exist, authentication will fail.

**Domains**
  Domains **must exist** in keystone. They are never auto-created. If a mapping
  references a non-existent domain, authentication will fail.

-----------
Definitions
-----------

A mapping looks as follows:

.. code-block:: none

   {
       "rules": [
           {
               "local": [
                   {
                       <user>
                       [<group>]
                       [<project>]
                   }
               ],
               "remote": [
                   {
                       <match>
                       [<condition>]
                   }
               ]
           }
       ]
   }

``mapping``
  A JSON object containing a list of rules.

``rules``
  A property in the mapping that contains the list of rules.

``rule``
  A JSON object containing ``local`` and ``remote`` properties to define the
  rule. There is no explicit ``rule`` property.

``local``
  A JSON object containing information on what local attributes will be mapped.
  The mapping engine processes this using the ``mapping context`` (defined below) and
  the result is a representation of the user from keystone's perspective.

  ``user``
    The local user that will be mapped to the federated user. The nested fields
    (``name``, ``id``, ``type``, ``domain``, etc.) can contain variable
    substitutions like ``{0}``, ``{1}``.

  ``group``
    (optional) A single local group the federated user will be placed in. Can
    reference groups by ``name`` or ``id``, with optional ``domain``.

  ``groups``
    (optional) A string containing semicolon-delimited group names (e.g.,
    ``"group1;group2;group3"``) that will be expanded into multiple group
    memberships for the federated user.

  ``projects``
    (optional) The local projects mapped to the federated user. Each project
    must include a ``roles`` array.

  ``domain``
    (optional) The local domain mapped to the federated user, projects, and
    groups. Projects and groups can also override this default domain by
    defining a domain of their own. Moreover, if no domain is defined in this
    configuration, the attribute mapping schema will use the identity provider
    OpenStack domain.

``remote``
  A JSON object containing information on what remote attributes will be mapped.

  ``type``
    The attribute name from the mapping context to match (typically an
    environment variable name like ``FirstName``, ``Email``, or
    ``OIDC_GROUPS``). This creates a direct mapping that can be referenced in
    the ``local`` section using indices like ``{0}``, ``{1}``, etc.

  Conditions (optional):
    Additional fields that filter which attribute values match this rule. Can
    include ``any_one_of``, ``not_any_of``, ``whitelist``, ``blacklist``, or
    ``regex``.

``mapping context``
  The data, represented as key-value pairs, that is used by the mapping engine
  to turn the ``local`` object into a representation of the user from
  keystone's perspective. The mapping context contains:

  * Environment variables from the keystone process (these contain the IdP's
    input data in SAML2 or claims data in OpenID Connect, transformed into
    environment variables by the authentication module)
  * Any ``direct mapping`` values calculated when processing the ``remote``
    list

``direct mapping``
  The mapping engine keeps track of each match from the ``remote`` section and
  makes them available to the ``local`` section for substitution using indices
  like ``{0}``, ``{1}``, etc.

--------------------------
How Mappings Are Processed
--------------------------

A mapping is selected by IdP and protocol. Then keystone takes the mapping and
processes each rule sequentially stopping after the first matched rule. A rule
is matched when all of its conditions are met.

First keystone evaluates each condition from the rule's remote property to see
if the rule is a match. If it is a match, keystone saves the data captured by
each of the matches from the rule's remote property in an ordered list. We call
these matches `direct mappings` since they can be used in the next step.

After the rule is found using the rule's conditions and a list of direct mappings is
stored, keystone begins processing the rule's `local` property. Each object in
the `local` property is collapsed into a single JSON object. For example:

.. code-block:: none

   {
       "local": [
           {
               "user": {...}
           },
           {
               "projects": [...]
           },
       ]
   }

becomes:

.. code-block:: none

   {
       "local": {
           "user": {...}
           "projects": [...]
       },
   }

when the same property exists in the local multiple times the first occurrence wins:

.. code-block:: none

   {
       "local": [
           {
               "user": {#first#}
           },
           {
               "projects": [...]
           },
           {
               "user": {#second#}
           },
       ]
   }

becomes:

.. code-block:: none

   {
       "local": {
           "user": {#first#}
           "projects": [...]
       },
   }

We take this JSON object and then recursively process it in order to apply
the direct mappings. This is simply looking for the pattern `{#}` and
substituting it with values from the direct mappings list. The index of the
direct mapping starts at zero.

--------------
Mapping Engine
--------------

The mapping engine can be tested before creating a federated setup. It can be
tested with the ``keystone-manage mapping_engine`` command:

.. code-block:: console

   $ keystone-manage mapping_engine --rules <file> --input <file>

.. NOTE::
    Although the rules file is formatted as JSON, the input file containing
    the mapping context data is formatted as individual lines of key: value
    pairs, see `keystone-manage mapping_engine --help` for details.


Mapping Conditions
------------------

Mappings support 5 different types of conditions:

``empty``: The rule is matched to all claims containing the remote attribute type.
This condition does not need to be specified.

``any_one_of``: The rule is matched only if any of the specified strings appear
in the remote attribute type. Condition result is boolean, not the argument that
is passed as input.

``not_any_of``: The rule is not matched if any of the specified strings appear
in the remote attribute type. Condition result is boolean, not the argument that
is passed as input.

``blacklist``: This rule removes all groups matched from the IdP's data. It is
not intended to be used as a way to prevent users, or groups of users, from
accessing the service provider. The output from filtering through a blacklist
will be all groups from the IdP's data that were not listed in the blacklist.

``whitelist``: This rule explicitly states which groups should be carried over
from the IdP's data. The result is the groups present in the IdP's data and in
the whitelist.

.. NOTE::

    ``empty``, ``blacklist`` and ``whitelist`` are the only conditions that can
    be used in direct mapping ({0}, {1}, etc.)

Multiple conditions can be combined to create a single rule.

Mappings Examples
-----------------

The following are all examples of mapping rule types. Each example includes
an explanation of what it does and when to use it.

empty condition
~~~~~~~~~~~~~~~

The ``empty`` condition matches any mapping context that contains the specified
attribute type, regardless of its value. This is useful when you want to
extract values from the IdP's data for variable substitution.

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0} {1}",
                           "email": "{2}"
                       },
                       "group": {
                           "name": "{3}",
                           "domain": {
                               "id": "0cd5e9"
                           }
                       }
                   }
               ],
               "remote": [
                   {
                       "type": "FirstName"
                   },
                   {
                       "type": "LastName"
                   },
                   {
                       "type": "Email"
                   },
                   {
                       "type": "OIDC_GROUPS"
                   }
               ]
           }
       ]
   }

**What this mapping does:**

* Creates a user with name "{FirstName} {LastName}" (e.g., "Jane Doe")
* Sets the user's email from the Email attribute
* Places the user in groups matching the values from OIDC_GROUPS

**Variable substitution:**

The numbers in braces ``{0}``, ``{1}``, ``{2}``, etc. are indices that map to
the remote attributes in order:

* ``{0}`` → value from ``FirstName`` attribute
* ``{1}`` → value from ``LastName`` attribute
* ``{2}`` → value from ``Email`` attribute
* ``{3}`` → value(s) from ``OIDC_GROUPS`` attribute

**Requirements for this mapping:**

* The group "0cd5e9" must exist (referenced by ID)
* Groups from OIDC_GROUPS must exist (referenced by name from the IdP data)
* If any group doesn't exist, it will be silently skipped

**Multi-valued attributes:**

Groups can have multiple values separated by semicolons:

* Example: ``OIDC_GROUPS=developers;testers``
* This creates mappings to both "developers" and "testers" groups

**Example mapping output:**

Given the above mapping with the following input data:

.. code-block:: none

   FirstName: Jane
   LastName: Doe
   Email: jane.doe@example.com
   OIDC_GROUPS: developers;testers

The ``keystone-manage mapping_engine`` would produce:

.. code-block:: json

   {
       "user": {
           "name": "Jane Doe",
           "email": "jane.doe@example.com",
           "type": "ephemeral",
           "domain": {
               "id": "Federated"
           }
       },
       "group_ids": ["0cd5e9"],
       "group_names": [
           {
               "name": "developers",
               "domain": {"id": "0cd5e9"}
           },
           {
               "name": "testers",
               "domain": {"id": "0cd5e9"}
           }
       ]
   }

**Important:** The groups "developers" and "testers" must exist in domain
"0cd5e9" for the user to receive their associated roles.

.. NOTE::

    If the user id and name are not specified in the mapping, the server tries to
    directly map ``REMOTE_USER`` environment variable. If this variable is also
    unavailable the server returns an HTTP 401 Unauthorized error.


other conditions
~~~~~~~~~~~~~~~~

In ``<other_condition>`` shown below, please supply one of the following:
``any_one_of``, or ``not_any_of``.

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       },
                       "group": {
                           "id": "0cd5e9"
                       }
                   }
               ],
               "remote": [
                   {
                       "type": "UserName"
                   },
                   {
                       "type": "HTTP_OIDC_GROUPIDS",
                       "<other_condition>": [
                           "HTTP_OIDC_EMAIL"
                       ]
                   }
               ]
           }
       ]
   }

In ``<other_condition>`` shown below, please supply one of the following:
``blacklist``, or ``whitelist``.

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       }
                   },
                   {
                       "groups": "{1}",
                       "domain": {
                           "id": "0cd5e9"
                       }
                   }
               ],
               "remote": [
                   {
                       "type": "UserName"
                   },
                   {
                       "type": "HTTP_OIDC_GROUPIDS",
                       "<other_condition>": [
                           "me@example.com"
                       ]
                   }
               ]
           }
       ]
   }

In the above example, a whitelist can be used to only map the user into a few of
the groups in their ``HTTP_OIDC_GROUPIDS`` remote attribute:

.. code-block:: json

    {
        "type": "HTTP_OIDC_GROUPIDS",
        "whitelist": [
            "Developers",
            "OpsTeam"
        ]
    }

A blacklist can map the user into all groups except those matched:

.. code-block:: json

    {
        "type": "HTTP_OIDC_GROUPIDS",
        "blacklist": [
            "Finance"
        ]
    }

**Example whitelist output:**

Given a mapping with the whitelist example above and this input data:

.. code-block:: none

   UserName: jsmith
   HTTP_OIDC_GROUPIDS: Developers;OpsTeam;Finance;Marketing

The ``keystone-manage mapping_engine`` would produce:

.. code-block:: json

   {
       "user": {
           "name": "jsmith",
           "type": "ephemeral",
           "domain": {
               "id": "Federated"
           }
       },
       "group_ids": [],
       "group_names": [
           {
               "name": "Developers",
               "domain": {"id": "abc1234"}
           },
           {
               "name": "OpsTeam",
               "domain": {"id": "abc1234"}
           }
       ]
   }

**Note:** Only "Developers" and "OpsTeam" are included because they match the
whitelist. "Finance" and "Marketing" are filtered out. Both groups must exist
in domain "abc1234" for the user to receive their roles.

**Example blacklist output:**

With the blacklist example above and the same input data, the output would be:

.. code-block:: json

   {
       "user": {
           "name": "jsmith",
           "type": "ephemeral",
           "domain": {
               "id": "Federated"
           }
       },
       "group_ids": [],
       "group_names": [
           {
               "name": "Developers",
               "domain": {"id": "0cd5e9"}
           },
           {
               "name": "OpsTeam",
               "domain": {"id": "0cd5e9"}
           },
           {
               "name": "Marketing",
               "domain": {"id": "0cd5e9"}
           }
       ]
   }

**Note:** All groups except "Finance" are included. The blacklist removes
"Finance" from the IdP's group list.

Regular expressions can be used in any condition for more flexible matches:

.. code-block:: json

    {
        "type": "HTTP_OIDC_GROUPIDS",
        "whitelist": [
            ".*Team$"
        ]
    }

When mapping into groups, either ids or names can be provided in the local section:

.. code-block:: json

   {
       "local": [
           {
               "group": {
                   "id":"0cd5e9"
               }
           }
       ]
   }

.. code-block:: json

   {
       "local": [
           {
               "group": {
                   "name": "developer_group",
                   "domain": {
                       "id": "abc1234"
                   }
               }
           }
       ]
   }

.. code-block:: json

   {
       "local": [
           {
               "group": {
                   "name": "developer_group",
                   "domain": {
                       "name": "private_cloud"
                   }
               }
           }
       ]
   }

.. _local-vs-ephemeral:

Mapping to Local vs Ephemeral Users
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Federated users can be mapped to either **local** or **ephemeral** users,
which behave very differently:

**Local Users (type=local)**

Use this approach when you want to link federated authentication to existing
keystone users. The user **must already exist** in keystone's identity backend.

.. code-block:: json

   {
       "local": [
           {
               "user": {
                   "name": "local_user",
                   "type": "local",
                   "domain": {
                       "name": "local_domain"
                   }
               }
           }
       ]
   }

**Important:** When using ``type: local``:

* The user and domain **must exist** in keystone's identity backend before
  authentication
* Keystone will fetch user details (id, name, roles, groups) from the backend
* If the user doesn't exist, authentication fails with ``401 Unauthorized``
* The federated user mapping assigns the federated identity to this local user
* Keystone will discard further group assignments from the mapping and use only
  the roles/groups already configured for the local user

**When to use local users:**

* You have existing users in LDAP or SQL that should authenticate via federation
* You want to maintain user identity across different authentication methods
* You need consistent user IDs regardless of authentication method

**Example mapping output for local users:**

The ``keystone-manage mapping_engine`` output for the above mapping would be:

.. code-block:: json

   {
       "user": {
           "name": "local_user",
           "type": "local",
           "domain": {
               "name": "local_domain"
           }
       },
       "group_ids": [],
       "group_names": []
   }

**Important:** During actual authentication, keystone will:

1. Look up "local_user" in domain "local_domain" in the identity backend
2. If found, fetch the user's existing ID, roles, and group memberships
3. Use those existing attributes (ignoring any group mappings in the mapping)
4. If not found, return ``401 Unauthorized`` error

**Ephemeral Users (type=ephemeral or omitted)**

Use this approach for purely federated users that don't need local accounts.

.. code-block:: json

   {
       "local": [
           {
               "user": {
                   "name": "{0}",
                   "email": "{1}"
               }
           }
       ]
   }

**Important:** When using ephemeral users (or omitting ``type``):

* The user does **not** need to exist beforehand
* The user becomes a member of the identity provider's domain (or a domain
  specified in the mapping)
* All user attributes must come from the IdP's data and mapping rules
* The user's groups and roles are determined entirely by the mapping
* Each authentication may result in a different user ID (based on the IdP's data)

**When to use ephemeral users:**

* Pure federated authentication with no local user accounts
* Users should only authenticate through the IdP
* You want to manage authorization through group mappings rather than direct
  user assignments

.. NOTE::
    Domain ``Federated`` is a service domain - it cannot be listed, displayed,
    added or deleted.  There is no need to perform any operation on it prior to
    federation configuration.

Output
------

If a mapping is valid you will receive the following output:

.. code-block:: none

   {
       "group_ids": "[<group-ids>]",
       "user":
           {
               "domain":
                   {
                       "id": "Federated" or "<local-domain-id>"
                   },
               "type": "ephemeral" or "local",
               "name": "<local-user-name>",
               "id": "<local-user-id>"
           },
       "group_names":
           [
               {
                   "domain":
                       {
                           "name": "<domain-name>"
                       },
                   "name":
                       {
                           "name": "[<groups-names>]"
                       }
               },
               {
                   "domain":
                       {
                           "name": "<domain-name>"
                       },
                   "name":
                       {
                           "name": "[<groups-names>]"
                       }
               }
           ]
   }

If the mapped user is local, mapping engine will discard further group
assigning and return set of roles configured for the user.

Regular Expressions
-------------------

Regular expressions can be used in a mapping by specifying the ``regex`` key, and
setting it to ``true``.

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       },
                       "group": {
                           "name": "{1}",
                           "domain": {
                               "id": "abc1234"
                           }
                       }
                   },
               ],
               "remote": [
                   {
                       "type": "UserName"
                   },
                   {
                       "type": "HTTP_OIDC_GROUPIDS",
                       "any_one_of": [
                           ".*@yeah.com$"
                       ]
                       "regex": true
                   },
                   {
                       "type": "HTTP_OIDC_GROUPIDS",
                       "whitelist": [
                           "Project.*$"
                       ],
                       "regex": true
                    }
               ]
           }
       ]
   }

This allows any user with a claim containing a key with any value in
``HTTP_OIDC_GROUPIDS`` to be mapped to group with id ``0cd5e9``. Additionally,
for every value in the ``HTTP_OIDC_GROUPIDS`` claim matching the string
``Project.*``, the user will be assigned to the project with that name.

**Example regex output:**

Given the above mapping with this input data:

.. code-block:: none

   UserName: jane.doe
   HTTP_OIDC_GROUPIDS: admin@yeah.com;users@yeah.com;ProjectAlpha;ProjectBeta;Finance

The ``keystone-manage mapping_engine`` would produce:

.. code-block:: json

   {
       "user": {
           "name": "jane.doe",
           "type": "ephemeral",
           "domain": {
               "id": "Federated"
           }
       },
       "group_ids": [],
       "group_names": [
           {
               "name": "ProjectAlpha",
               "domain": {"id": "abc1234"}
           },
           {
               "name": "ProjectBeta",
               "domain": {"id": "abc1234"}
           }
       ]
   }

**How the regex conditions work:**

1. ``any_one_of`` with ``".*@yeah.com$"``: Matches if ANY value in
   HTTP_OIDC_GROUPIDS ends with "@yeah.com". Since "admin@yeah.com" matches,
   the rule applies.

2. ``whitelist`` with ``"Project.*$"``: Filters HTTP_OIDC_GROUPIDS to only
   include values starting with "Project". This matches "ProjectAlpha" and
   "ProjectBeta" but not "Finance".

3. The filtered group names are placed in the groups, and must exist in domain
   "abc1234".

Condition Combinations
----------------------

Combinations of mappings conditions can also be done.

``empty``, ``any_one_of``, and ``not_any_of`` can all be used in the same rule,
but cannot be repeated within the same condition. ``any_one_of`` and
``not_any_of`` are mutually exclusive within a condition's scope. So are
``whitelist`` and ``blacklist``.

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       },
                       "group": {
                           "id": "0cd5e9"
                       }
                   },
               ],
               "remote": [
                   {
                       "type": "UserName"
                   },
                   {
                       "type": "cn=IBM_Canada_Lab",
                       "not_any_of": [
                           ".*@naww.com$"
                       ],
                       "regex": true
                   },
                   {
                       "type": "cn=IBM_USA_Lab",
                       "any_one_of": [
                           ".*@yeah.com$"
                       ]
                       "regex": true
                   }
               ]
           }
       ]
   }

As before group names and users can also be provided in the local section.

This allows any user with the following claim information to be mapped to
group with id 0cd5e9.

.. code-block:: json

   {"UserName":"<any_name>@yeah.com"}
   {"cn=IBM_USA_Lab":"<any_name>@yeah.com"}
   {"cn=IBM_Canada_Lab":"<any_name>@yeah.com"}

The following claims will be mapped:

- any claim containing the key UserName.
- any claim containing key cn=IBM_Canada_Lab that doesn't have the value <any_name>@naww.com.
- any claim containing key cn=IBM_USA_Lab that has value <any_name>@yeah.com.

Multiple Rules
--------------

Multiple rules can also be utilized in a mapping.

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       },
                       "group": {
                           "name": "non-contractors",
                           "domain": {
                               "id": "abc1234"
                           }
                       }
                   }
               ],
               "remote": [
                   {
                       "type": "UserName"
                   },
                   {
                       "type": "orgPersonType",
                       "not_any_of": [
                           "Contractor",
                           "SubContractor"
                       ]
                   }
               ]
           },
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       },
                       "group": {
                           "name": "contractors",
                           "domain": {
                               "id": "abc1234"
                           }
                       }
                   }
               ],
               "remote": [
                   {
                       "type": "UserName"
                   },
                   {
                       "type": "orgPersonType",
                       "any_one_of": [
                           "Contractor",
                           "SubContractor"
                       ]
                   }
               ]
           }
       ]
   }


The above assigns groups membership basing on ``orgPersonType`` values:

- neither ``Contractor`` nor ``SubContractor`` will belong to the ``non-contractors`` group.
- either ``Contractor or ``SubContractor`` will belong to the ``contractors`` group.

**Example multiple rules output:**

Given the above mapping with this input data:

.. code-block:: none

   UserName: jsmith
   orgPersonType: Employee

The ``keystone-manage mapping_engine`` would produce:

.. code-block:: json

   {
       "user": {
           "name": "jsmith",
           "type": "ephemeral",
           "domain": {
               "id": "Federated"
           }
       },
       "group_ids": [],
       "group_names": [
           {
               "name": "non-contractors",
               "domain": {"id": "abc1234"}
           }
       ]
   }

**How multiple rules work:**

1. Rules are evaluated **sequentially** from top to bottom
2. The **first rule** checks: is orgPersonType NOT "Contractor" or "SubContractor"?
   Since it's "Employee", this matches → user gets "non-contractors" group
3. Rules are **additive** - even though rule 1 matched, rule 2 is still evaluated
4. The **second rule** checks: is orgPersonType "Contractor" or "SubContractor"?
   Since it's "Employee", this does NOT match → nothing added

If ``orgPersonType`` were "Contractor", only the second rule would match and the
user would be in the "contractors" group instead.

Rules are additive, so permissions will only be granted for the rules that
succeed. All the remote conditions of a rule must be valid.

When using multiple rules you can specify more than one effective user
identification, but only the first match will be considered and the others
ignored ordered from top to bottom.

Since rules are additive one can specify one user identification and this will
also work. The best practice for multiple rules is to create a rule for just
user and another rule for just groups. Below is rules example repeated but with
global username mapping.


.. code-block:: json

   {
       "rules": [{
           "local": [{
               "user": {
                   "id": "{0}"
               }
           }],
           "remote": [{
               "type": "UserType"
           }]
       },
       {
           "local": [{
               "group": {
                   "name": "non-contractors",
                   "domain": {
                       "id": "abc1234"
                   }
               }
           }],
           "remote": [{
               "type": "orgPersonType",
               "not_any_of": [
                   "Contractor",
                   "SubContractor"
               ]
           }]
       },
       {
           "local": [{
               "group": {
                   "name": "contractors",
                   "domain": {
                       "id": "abc1234"
                   }
               }
           }],
           "remote": [{
               "type": "orgPersonType",
               "any_one_of": [
                   "Contractor",
                   "SubContractor"
               ]
           }]
       }]
    }

.. _auto-provisioning:

Auto-Provisioning
-----------------

The mapping engine can automatically provision **projects** when a federated
user authenticates. This allows you to create a mapping that grants users
access to specific projects, and those projects will be created automatically
if they don't already exist.

.. note::

   See the `Important Prerequisites`_ section for details on what resources
   are auto-provisioned versus what must exist beforehand. In summary:

   * **Auto-created:** Projects (defined in the ``projects`` section)
   * **Must pre-exist:** Groups, roles, domains, and local users

The ``projects`` section must include a ``roles`` array. Direct role
assignments are created for the user on these projects (not through group
membership), and these assignments persist in keystone's database even if the
mapping is later changed.

Auto-Provisioning Example
~~~~~~~~~~~~~~~~~~~~~~~~~~

Consider the following mapping that auto-provisions projects:

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       }
                   },
                   {
                       "projects": [
                           {
                               "name": "Production",
                               "roles": [
                                   {
                                       "name": "reader"
                                   }
                               ]
                           },
                           {
                               "name": "Staging",
                               "roles": [
                                   {
                                       "name": "member"
                                   }
                               ]
                           },
                           {
                               "name": "Project for {0}",
                               "roles": [
                                   {
                                       "name": "admin"
                                   }
                               ]
                           }
                       ]
                   }
               ],
               "remote": [
                   {
                       "type": "UserName"
                   }
               ]
           }
       ]
   }

**How This Mapping Works:**

The ``projects`` section within the ``local`` rules defines which projects
the federated user will be granted access to. When a user authenticates:

1. The mapping engine processes the IdP's data and applies the remote rules
2. Variable substitution occurs (e.g., ``{0}`` is replaced with the UserName)
3. For each project in the ``projects`` list:

   a. Keystone checks if the project exists in the IdP's domain
   b. If it doesn't exist, keystone creates it
   c. Role assignments are created for the user on that project

4. The user receives a token with access to all specified projects

**In the example above:**

An authenticated federated user with UserName "jsmith" will be granted:

* ``reader`` role on the ``Production`` project
* ``member`` role on the ``Staging`` project
* ``admin`` role on the ``Project for jsmith`` project

If ``Production`` or ``Staging`` don't exist, they will be created. The
``Project for jsmith`` project will be created with the user's name substituted
into the project name (making it unique per user).

**Example mapping output:**

Given the above mapping with the following input data:

.. code-block:: none

   UserName: jsmith

The ``keystone-manage mapping_engine`` would produce:

.. code-block:: json

   {
       "user": {
           "name": "jsmith",
           "type": "ephemeral",
           "domain": {
               "id": "Federated"
           }
       },
       "group_ids": [],
       "group_names": [],
       "projects": [
           {
               "name": "Production",
               "roles": [{"name": "reader"}]
           },
           {
               "name": "Staging",
               "roles": [{"name": "member"}]
           },
           {
               "name": "Project for jsmith",
               "roles": [{"name": "admin"}]
           }
       ]
   }

**What happens during authentication:**

1. Keystone checks if "Production" project exists - creates it if missing
2. Grants "jsmith" the "reader" role on Production (creates role assignment)
3. Keystone checks if "Staging" project exists - creates it if missing
4. Grants "jsmith" the "member" role on Staging (creates role assignment)
5. Keystone checks if "Project for jsmith" exists - creates it if missing
6. Grants "jsmith" the "admin" role on "Project for jsmith" (creates role assignment)
7. Returns a token that can be scoped to any of these three projects

.. note::

   Auto-provisioning is **idempotent** - if the IdP's attributes haven't
   changed, keystone checks for existing projects by name and domain before
   creating. If UserName is still "jsmith", no new "Project for jsmith" will
   be created on subsequent authentications.

Combining Projects with Groups
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can mix ``groups`` and ``projects`` in the same mapping. Projects provide
direct role assignments (persistent), while groups provide ephemeral memberships:

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       }
                   },
                   {
                       "projects": [
                           {
                               "name": "Marketing",
                               "roles": [
                                   {
                                       "name": "member"
                                   }
                               ]
                           },
                           {
                               "name": "Development project for {0}",
                               "roles": [
                                   {
                                       "name": "admin"
                                   }
                               ]
                           }
                       ]
                   },
                   {
                       "group": {
                           "name": "Finance",
                           "domain": {
                               "id": "6fe767"
                           }
                       }
                   }
               ],
               "remote": [
                   {
                       "type": "UserName"
                   }
               ]
           }
       ]
   }

This mapping gives users:

* **Persistent assignments:** Direct roles on auto-provisioned projects (Marketing and a per-user Development project)
* **Ephemeral membership:** Finance group (must pre-exist in domain 6fe767), which provides additional roles through group grants

See `Important Prerequisites`_ for details on the differences between persistent assignments and ephemeral group memberships.

Troubleshooting Federation Mappings
------------------------------------

Common Issues and Solutions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem: Authentication fails with 401 Unauthorized**

*Possible causes:*

1. **Local user doesn't exist**

   * If using ``type: local``, the user must exist in keystone's identity backend
   * Solution: Create the user first, or switch to ephemeral users (see local-vs-ephemeral_)

2. **REMOTE_USER not mapped**

   * If no user name/id is in the mapping, keystone looks for REMOTE_USER env var
   * Solution: Add explicit user mapping or configure REMOTE_USER in your IdP

3. **Referenced role doesn't exist**

   * Roles in auto-provisioned projects must pre-exist
   * Solution: Create roles before setting up federation

**Problem: User authenticates but has no permissions**

*Possible causes:*

1. **Groups don't exist**

   * Groups are silently skipped if they don't exist
   * Solution: Check logs for "Group X has no entry in the backend" warnings
   * Create missing groups before authentication

2. **Group has no role assignments**

   * Group exists but has no grants on any projects/domains
   * Solution: Grant roles to the group on appropriate resources

3. **Wrong domain specified**

   * Group or project in wrong domain
   * Solution: Verify domain IDs/names in mapping match keystone resources

**Problem: Projects aren't being auto-created**

See the auto-provisioning_ section for details on project auto-creation.

*Possible causes:*

1. **Using groups instead of projects section**

   * Only ``projects`` in local mapping are auto-created
   * Projects accessed via group membership are NOT auto-created

2. **Missing roles section**

   * ``projects`` must include ``roles``

3. **Domain doesn't exist**

   * Target domain must exist

**Problem: Mapping rules don't match IdP data**

*Possible causes:*

1. **Incorrect attribute names**

   * Attribute names in the mapping context are case-sensitive
   * Solution: Check IdP configuration and actual input data
   * Use ``keystone-manage mapping_engine`` to test

2. **Condition logic issues**

   * ``any_one_of`` vs ``not_any_of`` confusion
   * Multiple conditions in same rule must ALL match
   * Solution: Review condition documentation and test thoroughly

3. **Regex not enabled**

   * Forgot to set ``"regex": true``
   * Solution: Add ``"regex": true`` when using regex patterns

Debugging Tips
~~~~~~~~~~~~~~

**Test mappings before deploying:**

Use the mapping engine test command:

.. code-block:: console

   $ keystone-manage mapping_engine --rules mapping.json --input attributes.txt

**Enable debug logging:**

Set keystone logging to DEBUG to see:

* Which rules are being evaluated
* Which groups are being skipped
* Variable substitution results
* Assertion data received from IdP

**Check input data:**

The input data is logged at DEBUG level. Look for:

* Actual attribute names (case-sensitive)
* Actual values being sent by IdP
* Multiple values separated by semicolons

**Verify resources exist:**

Before creating mappings, verify in keystone:

.. code-block:: console

   # Check if group exists
   $ openstack group list --domain <domain>

   # Check if role exists
   $ openstack role list

   # Check if domain exists
   $ openstack domain list

   # Check if user exists (for local user mappings)
   $ openstack user list --domain <domain>

**Common mistake checklist:**

* [ ] All groups referenced in mapping exist
* [ ] All roles referenced in mapping exist
* [ ] All domains referenced in mapping exist
* [ ] For local users: user exists in identity backend
* [ ] Group/project/domain names match exactly (case-sensitive)
* [ ] Multi-valued attributes use semicolon separator
* [ ] Regex patterns have ``"regex": true`` flag
* [ ] Projects section includes roles
* [ ] Direct mapping indices ({0}, {1}) match remote order

keystone-to-keystone
--------------------

keystone-to-keystone federation also utilizes mappings, but has some
differences.

An attribute file (e.g. ``/etc/shibboleth/attribute-map.xml`` in a Shibboleth
implementation) is used to add attributes to the mapping `context`. Attributes
look as follows:

.. code-block:: xml

    <!-- example 1 from a K2k Shibboleth implementation -->
    <Attribute name="openstack_user" id="openstack_user"/>
    <Attribute name="openstack_user_domain" id="openstack_user_domain"/>

The service provider must contain a mapping as shown below.
``openstack_user``, and ``openstack_user_domain`` match to the attribute
names we have in the Identity Provider. It will map any user with the name
``user1`` or ``admin`` in the ``openstack_user`` attribute and
``openstack_domain`` attribute ``default`` to a group with id ``abc1234``.

.. code-block:: json

   {
       "rules": [
           {
               "local": [
                   {
                       "group": {
                           "id": "abc1234"
                       }
                   }
               ],
               "remote": [
                   {
                       "type": "openstack_user",
                       "any_one_of": [
                           "user1",
                           "admin"
                       ]
                   },
                   {
                       "type":"openstack_user_domain",
                       "any_one_of": [
                           "Default"
                       ]
                   }
               ]
           }
       ]
   }

A keystone user's groups can also be mapped to groups in the service provider.
For example, with the following attributes declared in Shibboleth's attributes file:

.. code-block:: xml

    <!-- example 2 from a K2k Shibboleth implementation -->
    <Attribute name="openstack_user" id="openstack_user"/>
    <Attribute name="openstack_groups" id="openstack_groups"/>

Then the following mapping can be used to map the user's group membership from the keystone
IdP to groups in the keystone SP:

.. code-block:: json

    {
        "rules": [
            {
                "local":
                [
                    {
                        "user":
                            {
                                "name": "{0}"
                            }
                    },
                    {
                        "groups": "{1}"
                    }
                ],
                "remote":
                [
                    {
                        "type": "openstack_user"
                    },
                    {
                        "type": "openstack_groups"
                    }
                ]
            }
        ]
    }


``openstack_user``, and ``openstack_groups`` will be matched by service
provider to the attribute names we have in the Identity Provider. It will
take the ``openstack_user`` attribute from the mapping context and inserts
it directly in the mapping.  The identity provider will set the value of
``openstack_groups`` by group name and domain name to which the user belongs
in the IdP. Suppose the user belongs to 'group1' in domain 'Default' in the IdP
then it will map to a group with the same name and same domain's name in the SP.

The possible attributes that can be used in a mapping are `openstack_user`,
`openstack_user_domain`, `openstack_roles`, `openstack_project`,
`openstack_project_domain` and `openstack_groups`.

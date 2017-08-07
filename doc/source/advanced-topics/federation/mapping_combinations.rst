:orphan:

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
document.

The attributes are typically processed by third-party software and are presented
to keystone as environment variables. The original document from the IdP is
generally not available to keystone. This is how the `Shibboleth` and `Mellon`
implementations work.

The mapping format described in this document maps these environment variables
to a local keystone user. The mapping may also define group membership for
that user and projects the user can access.

An IdP has exactly one mapping specified per protocol. Mappings themselves can
be used multiple times by different combinations of IdP and protocol.

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

* `mapping`: a JSON object containing a list of rules.
* `rules`: a property in the mapping that contains the list of rules.
* `rule`: a JSON object containing `local` and `remote` properties to define
  the rule. There is no explicit `rule` property.
* `local`: a JSON object containing information on what local attributes will
  be mapped. The mapping engine processes this using the `context` (defined
  below) and the result is a representation of the user from keystone's
  perspective.

  * `<user>`: the local user that will be mapped to the federated user.
  * `<group>`: (optional) the local groups the federated user will be placed in.
  * `<projects>`: (optional) the local projects mapped to the federated user.

* `remote`: a JSON object containing information on what remote attributes will be mapped.

  * `<match>`: a JSON object that tells the mapping engine what federated attribute
    to make available for substitution in the local object. There can be one or more
    of these objects in the `remote` list.
  * `<condition>`: a JSON object containing conditions that allow a rule. There can be
    zero or more of these objects in the `remote` list.

* `direct mapping`: the mapping engine keeps track of each match and makes them
  available to the local rule for substitution.
* `assertion`: data provided to keystone by the IdP to assert facts
  (name, groups, etc) about the authenticating user. This is an XML document when
  using the SAML2 protocol.
* `mapping context`: the data, represented as key-value pairs, that is used by the
  mapping engine to turn the `local` object into a representation of the user
  from keystone's perspective. The mapping context contains the environment of the
  keystone process and any `direct mapping` values calculated when processing the
  `remote` list.

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

-------------
Mapping Rules
-------------

Mapping Engine
--------------

The mapping engine can be tested before creating a federated setup. It can be
tested with the ``keystone-manage mapping_engine`` command:

.. code-block:: bash

    $ keystone-manage mapping_engine --rules <file> --input <file>

.. NOTE::
    Although the rules file is formatted as JSON, the input file of assertion
    data is formatted as individual lines of key: value pairs, see
    `keystone-manage mapping_engine --help` for details.


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

``blacklist``: This rule removes all groups matched from the assertion. It is
not intended to be used as a way to prevent users, or groups of users, from
accessing the service provider. The output from filtering through a blacklist
will be all groups from the assertion that were not listed in the blacklist.

``whitelist``: This rule explicitly states which groups should be carried over
from the assertion. The result is the groups present in the assertion and in
the whitelist.

.. NOTE::

    ``empty``, ``blacklist`` and ``whitelist`` are the only conditions that can
    be used in direct mapping ({0}, {1}, etc.)

Multiple conditions can be combined to create a single rule.

Mappings Examples
-----------------

The following are all examples of mapping rule types.

empty condition
~~~~~~~~~~~~~~~

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

.. NOTE::

    The numbers in braces {} are indices, they map in order. For example::

        - Mapping to user with the name matching the value in remote attribute FirstName
        - Mapping to user with the name matching the value in remote attribute LastName
        - Mapping to user with the email matching value in remote attribute Email
        - Mapping to a group(s) with the name matching the value(s) in remote attribute OIDC_GROUPS



Groups can have multiple values. Each value must be separated by a `;`
Example: OIDC_GROUPS=developers;testers


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

.. NOTE::

    If the user id and name are not specified in the mapping, the server tries to
    directly map ``REMOTE_USER`` environment variable. If this variable is also
    unavailable the server returns an HTTP 401 Unauthorized error.

Group ids and names can be provided in the local section:

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

Users can be mapped to local users that already exist in keystone's identity
backend by setting the ``type`` attribute of the user to ``local`` and providing
the domain to which the local user belongs:

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

The user is then treated as existing in the local identity backend, and the
server will attempt to fetch user details (id, name, roles, groups) from the
identity backend. The local user and domain are not generated dynamically, so
if they do not exist in the local identity backend, authentication attempts
will result in a 401 Unauthorized error.

If you omit the ``type`` attribute or set it to ``ephemeral`` or do not provide a
domain, the user is deemed ephemeral and becomes a member of the identity
provider's domain. It will not be looked up in the local keystone backend, so
all of its attributes must come from the IdP and the mapping rules.

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
                }
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
                            "id": "0cd5e9"
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
                    }
                ]
            }
        ]
    }

This allows any user with a claim containing a key with any value in
``HTTP_OIDC_GROUPIDS`` to be mapped to group with id ``0cd5e9``.

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

Rules are additive, so permissions will only be granted for the rules that
succeed.  All the remote conditions of a rule must be valid.

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

Auto-Provisioning
-----------------

The mapping engine has the ability to aid in the auto-provisioning of resources
when a federated user authenticates for the first time. This can be achieved
using a specific mapping syntax that the mapping engine can parse and
ultimately make decisions on.

For example, consider the following mapping:

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
                                        "name": "observer"
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

The semantics of the ``remote`` section have not changed. The difference
between this mapping and the other examples is the addition of a ``projects``
section within the ``local`` rules. The ``projects`` list supplies a list
of projects that the federated user will be given access to. The projects
will be automatically created if they don't exist when the user
authenticated and the mapping engine has applied values from the assertion
and mapped them into the ``local`` rules.

In the above example, an authenticated federated user will be granted the
``observer`` role on the ``Production`` project, ``member`` role on the
``Staging`` project, and they will have ``admin`` role on the ``Project for
jsmith``.

It is important to note the following constraints apply when auto-provisioning:

* Projects are the only resource that will be created dynamically.
* Projects will be created within the domain associated with the Identity
  Provider.
* The ``projects`` section of the mapping must also contain a ``roles``
  section.

  + Roles within the project must already exist in the deployment or domain.

* Assignments are actually created for the user which is unlike the
  ephemeral group memberships.

Since the creation of roles typically requires policy changes across other
services in the deployment, it is expected that roles are created ahead of
time. Federated authentication should also be considered idempotent if the
attributes from the SAML assertion have not changed. In the example from above,
if the user's name is still ``jsmith``, then no new projects will be
created as a result of authentication.

Mappings can be created that mix ``groups`` and ``projects`` within the
``local`` section. The mapping shown in the example above does not contain a
``groups`` section in the ``local`` rules. This will result in the federated
user having direct role assignments on the projects in the ``projects`` list.
The following example contains ``local`` rules comprised of both ``projects``
and ``groups``, which allow for direct role assignments and group memberships.

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

In the above example, a federated user will receive direct role assignments on
the ``Marketing`` project, as well as a dedicated project specific to the
federated user's name. In addition to that, they will also be placed in the
``Finance`` group and receive all role assignments that group has on projects
and domains.

keystone-to-keystone
--------------------

keystone-to-keystone federation also utilizes mappings, but has some
differences.

An attribute file (e.g. ``/etc/shibboleth/attribute-map.xml`` in a Shibboleth
implementation) is used to add attributes to the mapping `context`. Attributes
look as follows:

.. code-block:: xml

    <!-- example from a K2k Shibboleth implementation -->
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

The possible attributes that can be used in a mapping are `openstack_user`,
`openstack_user_domain`, `openstack_roles`, `openstack_project`, and
`openstack_project_domain`.

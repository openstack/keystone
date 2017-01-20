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

Mapping adds a set of rules to map federation attributes to Keystone users and/or
groups. An Identity Provider has exactly one mapping specified per protocol.

Mapping objects can be used multiple times by different combinations of Identity
Provider and Protocol.

-----------
Definitions
-----------

A rule hierarchy looks as follows:

.. code-block:: javascript

    {
        "rules": [
            {
                "local": [
                    {
                        "<user> or <group>"
                    }
                ],
                "remote": [
                    {
                        "<condition>"
                    }
                ]
            }
        ]
    }

* `rules`: top-level list of rules.
* `local`: a rule containing information on what local attributes will be mapped.
* `remote`: a rule containing information on what remote attributes will be mapped.
* `<condition>`: contains information on conditions that allow a rule, can only
  be set in a `remote` rule.

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
    Although the rules file is formated as json the input file of assertion
    data is formatted as individual lines of key: value pairs,
    see `keystone-manage mapping_engine --help` for details.


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

``blacklist``: The rule allows all except a specified set of groups. Condition
result is the argument(s) passed as input minus what was matched in the
blacklist.

``whitelist``: The rules allows a specified set of groups. Condition result is
the argument(s) passed as input and is/are also present in the whitelist.

.. NOTE::

    ``empty``, ``blacklist`` and ``whitelist`` are the only conditions that can
    be used in direct mapping ({0}, {1}, etc.)

Multiple conditions can be combined to create a single rule.

Mappings Examples
-----------------

The following are all examples of mapping rule types.

empty condition
~~~~~~~~~~~~~~~

.. code-block:: javascript

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

.. code-block:: javascript

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

.. code-block:: javascript

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

.. code-block:: javascript

    {
        "local": [
            {
                "group": {
                    "id":"0cd5e9"
                }
            }
        ]
    }

.. code-block:: javascript

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

.. code-block:: javascript

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


Output
------

If a mapping is valid you will receive the following output:

.. code-block:: javascript

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

The ``type`` parameter specifies the type of user being mapped. The 2 possible
user types are ``local`` and ``ephemeral``.``local`` is displayed if the user
has a domain specified. The user is treated as existing in the backend, hence
the server will fetch user details (id, name, roles, groups).``ephemeral`` is
displayed for a user that does not exist in the backend.

The ``id`` parameter in the service domain specifies the domain a user belongs
to. ``Federated`` will be displayed if no domain is specified in the local rule.
User is deemed ephemeral and becomes a member of service domain named ``Federated``.
If the domain is specified the local domain's id will be displayed.
If the mapped user is local, mapping engine will discard further group
assigning and return set of roles configured for the user.

.. NOTE::
    Domain ``Federated`` is a service domain - it cannot be listed, displayed,
    added or deleted.  There is no need to perform any operation on it prior to
    federation configuration.

Regular Expressions
-------------------

Regular expressions can be used in a mapping by specifying the ``regex`` key, and
setting it to ``true``.

.. code-block:: javascript

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

.. code-block:: javascript

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

.. code-block:: javascript

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

.. code-block:: javascript

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


.. code-block:: javascript

    {
        "rules": [
            {
                "local": [
                    "user": {
                        "id": "{0}"
                    }
                ],
                "remote": [
                    {
                        "type": "UserType"
                    }
                ]
            },
            {
                "local": [
                    {
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


Auto-Provisioning
-----------------

The mapping engine has the ability to aid in the auto-provisioning of resources
when a federated user authenticates for the first time. This can be achieved
using a specific mapping syntax that the mapping engine can parse and
ultimately make decisions on.

For example, consider the following mapping:

.. code-block:: javascript

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
authenticates and the mapping engine has applied values from the assertion
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

.. code-block:: javascript

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

Keystone to Keystone
--------------------

Keystone to Keystone federation also utilizes mappings, but has some
differences.

An attribute file (``/etc/shibboleth/attribute-map.xml``) is used to add
attributes to the Keystone Identity Provider. Attributes look as follows:

.. code-block:: xml

    <Attribute name="openstack_user" id="openstack_user"/>
    <Attribute name="openstack_user_domain" id="openstack_user_domain"/>

The Keystone Service Provider must contain a mapping as shown below.
``openstack_user``, and ``openstack_user_domain`` match to the attribute
names we have in the Identity Provider. It will map any user with the name
``user1`` or ``admin`` in the ``openstack_user`` attribute and
``openstack_domain`` attribute ``default`` to a group with id ``abc1234``.

.. code-block:: javascript

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

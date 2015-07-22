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

===================================
Mapping Combinations for Federation
===================================

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

You can combine multiple conditions in a single rule. The schema that needs to be
followed for the mapping rules can be seen in the :doc:`mapping_schema` page.

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
                            "name": "{3}"
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
                        },
                        "groups": {
                            "name": "{1}",
                            "domain": {
                                "id": "0cd5e9"
                            }
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



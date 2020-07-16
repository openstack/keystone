# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Fixtures for Federation Mapping."""


EMPLOYEE_GROUP_ID = "0cd5e9"
CONTRACTOR_GROUP_ID = "85a868"
TESTER_GROUP_ID = "123"
TESTER_GROUP_NAME = "tester"
DEVELOPER_GROUP_ID = "xyz"
DEVELOPER_GROUP_NAME = "Developer"
CONTRACTOR_GROUP_NAME = "Contractor"
DEVELOPER_GROUP_DOMAIN_NAME = "outsourcing"
DEVELOPER_GROUP_DOMAIN_ID = "5abc43"
FEDERATED_DOMAIN = "Federated"
LOCAL_DOMAIN = "Local"

# Mapping summary:
# LastName Smith & Not Contractor or SubContractor -> group 0cd5e9
# FirstName Jill & Contractor or SubContractor -> to group 85a868
MAPPING_SMALL = {
    "rules": [
        {
            "local": [
                {
                    "group": {
                        "id": EMPLOYEE_GROUP_ID
                    }
                },
                {
                    "user": {
                        "name": "{0}"
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
                },
                {
                    "type": "LastName",
                    "any_one_of": [
                        "Bo"
                    ]
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "id": CONTRACTOR_GROUP_ID
                    }
                },
                {
                    "user": {
                        "name": "{0}"
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
                },
                {
                    "type": "FirstName",
                    "any_one_of": [
                        "Jill"
                    ]
                }
            ]
        }
    ]
}

# Mapping summary:
# orgPersonType Admin or Big Cheese -> name {0} {1} email {2} and group 0cd5e9
# orgPersonType Customer -> user name {0} email {1}
# orgPersonType Test and email ^@example.com$ -> group 123 and xyz
MAPPING_LARGE = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0} {1}",
                        "email": "{2}"
                    },
                    "group": {
                        "id": EMPLOYEE_GROUP_ID
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
                    "type": "orgPersonType",
                    "any_one_of": [
                        "Admin",
                        "Big Cheese"
                    ]
                }
            ]
        },
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "email": "{1}"
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "Email"
                },
                {
                    "type": "orgPersonType",
                    "not_any_of": [
                        "Admin",
                        "Employee",
                        "Contractor",
                        "Tester"
                    ]
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "id": TESTER_GROUP_ID
                    }
                },
                {
                    "group": {
                        "id": DEVELOPER_GROUP_ID
                    }
                },
                {
                    "user": {
                        "name": "{0}"
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
                        "Tester"
                    ]
                },
                {
                    "type": "Email",
                    "any_one_of": [
                        ".*@example.com$"
                    ],
                    "regex": True
                }
            ]
        }
    ]
}

MAPPING_BAD_REQ = {
    "rules": [
        {
            "local": [
                {
                    "user": "name"
                }
            ],
            "remote": [
                {
                    "type": "UserName",
                    "bad_requirement": [
                        "Young"
                    ]
                }
            ]
        }
    ]
}

MAPPING_BAD_VALUE = {
    "rules": [
        {
            "local": [
                {
                    "user": "name"
                }
            ],
            "remote": [
                {
                    "type": "UserName",
                    "any_one_of": "should_be_list"
                }
            ]
        }
    ]
}

MAPPING_NO_RULES = {
    'rules': []
}

MAPPING_NO_REMOTE = {
    "rules": [
        {
            "local": [
                {
                    "user": "name"
                }
            ],
            "remote": []
        }
    ]
}

MAPPING_MISSING_LOCAL = {
    "rules": [
        {
            "remote": [
                {
                    "type": "UserName",
                    "any_one_of": "should_be_list"
                }
            ]
        }
    ]
}

MAPPING_WRONG_TYPE = {
    "rules": [
        {
            "local": [
                {
                    "user": "{1}"
                }
            ],
            "remote": [
                {
                    "not_type": "UserName"
                }
            ]
        }
    ]
}

MAPPING_MISSING_TYPE = {
    "rules": [
        {
            "local": [
                {
                    "user": "{1}"
                }
            ],
            "remote": [
                {}
            ]
        }
    ]
}

MAPPING_EXTRA_REMOTE_PROPS_NOT_ANY_OF = {
    "rules": [
        {
            "local": [
                {
                    "group": {
                        "id": "0cd5e9"
                    }
                },
                {
                    "user": {
                        "name": "{0}"
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
                        "SubContractor"
                    ],
                    "invalid_type": "xyz"
                }
            ]
        }
    ]
}

MAPPING_EXTRA_REMOTE_PROPS_ANY_ONE_OF = {
    "rules": [
        {
            "local": [
                {
                    "group": {
                        "id": "0cd5e9"
                    }
                },
                {
                    "user": {
                        "name": "{0}"
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
                        "SubContractor"
                    ],
                    "invalid_type": "xyz"
                }
            ]
        }
    ]
}

MAPPING_EXTRA_REMOTE_PROPS_JUST_TYPE = {
    "rules": [
        {
            "local": [
                {
                    "group": {
                        "id": "0cd5e9"
                    }
                },
                {
                    "user": {
                        "name": "{0}"
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "orgPersonType",
                    "invalid_type": "xyz"
                }
            ]
        }
    ]
}

MAPPING_EXTRA_RULES_PROPS = {
    "rules": [
        {
            "local": [
                {
                    "group": {
                        "id": "0cd5e9"
                    }
                },
                {
                    "user": {
                        "name": "{0}"
                    }
                }
            ],
            "invalid_type": {
                "id": "xyz",
            },
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "orgPersonType",
                    "not_any_of": [
                        "SubContractor"
                    ]
                }
            ]
        }
    ]
}

MAPPING_TESTER_REGEX = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "id": TESTER_GROUP_ID
                    }
                }
            ],
            "remote": [
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        ".*Tester*"
                    ],
                    "regex": True
                }
            ]
        }
    ]
}


MAPPING_DIRECT_MAPPING_THROUGH_KEYWORD = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                    }

                },
                {
                    "group": {
                        "id": TESTER_GROUP_ID
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName",
                    "any_one_of": [
                        "bwilliams"
                    ]
                }
            ]
        }
    ]
}

MAPPING_DEVELOPER_REGEX = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                    },
                    "group": {
                        "id": DEVELOPER_GROUP_ID
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
                        "Developer"
                    ],
                },
                {
                    "type": "Email",
                    "not_any_of": [
                        ".*@example.org$"
                    ],
                    "regex": True
                }
            ]
        }
    ]
}

MAPPING_GROUP_NAMES = {

    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "name": DEVELOPER_GROUP_NAME,
                        "domain": {
                            "name": DEVELOPER_GROUP_DOMAIN_NAME
                        }
                    }
                }
            ],
            "remote": [
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        "Employee"
                    ],
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "name": TESTER_GROUP_NAME,
                        "domain": {
                            "id": DEVELOPER_GROUP_DOMAIN_ID
                        }
                    }
                }
            ],
            "remote": [
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        "BuildingX"
                    ]
                }
            ]
        },
    ]
}

MAPPING_GROUP_NAME_WITHOUT_DOMAIN = {

    "rules": [
        {
            "local": [
                {
                    "group": {
                        "name": DEVELOPER_GROUP_NAME,
                    }
                }
            ],
            "remote": [
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        "Employee"
                    ],
                }
            ]
        },
    ]
}

MAPPING_GROUP_ID_WITH_DOMAIN = {

    "rules": [
        {
            "local": [
                {
                    "group": {
                        "id": EMPLOYEE_GROUP_ID,
                        "domain": {
                            "id": DEVELOPER_GROUP_DOMAIN_ID
                        }
                    }
                }
            ],
            "remote": [
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        "Employee"
                    ],
                }
            ]
        },
    ]
}

MAPPING_BAD_GROUP = {

    "rules": [
        {
            "local": [
                {
                    "group": {
                    }
                }
            ],
            "remote": [
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        "Employee"
                    ],
                }
            ]
        },
    ]
}

MAPPING_BAD_DOMAIN = {

    "rules": [
        {
            "local": [
                {
                    "group": {
                        "id": EMPLOYEE_GROUP_ID,
                        "domain": {
                            "id": DEVELOPER_GROUP_DOMAIN_ID,
                            "badkey": "badvalue"
                        }
                    }
                }
            ],
            "remote": [
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        "Employee"
                    ],
                }
            ]
        },
    ]
}

MAPPING_EPHEMERAL_USER = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "domain": {
                            "id": FEDERATED_DOMAIN
                        },
                        "type": "ephemeral"
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "UserName",
                    "any_one_of": [
                        "tbo"
                    ]
                }
            ]
        }
    ]
}

MAPPING_GROUPS_WHITELIST = {
    "rules": [
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "whitelist": [
                        "Developer", "Contractor"
                    ]
                },
                {
                    "type": "UserName"
                }
            ],
            "local": [
                {
                    "groups": "{0}",
                    "domain": {
                        "id": DEVELOPER_GROUP_DOMAIN_ID
                    }
                },
                {
                    "user": {
                        "name": "{1}"
                    }
                }
            ]
        }
    ]
}

MAPPING_EPHEMERAL_USER_LOCAL_DOMAIN = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "domain": {
                            "id": LOCAL_DOMAIN
                        },
                        "type": "ephemeral"
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "UserName",
                    "any_one_of": [
                        "jsmith"
                    ]
                }
            ]
        }
    ]
}

MAPPING_GROUPS_WHITELIST_MISSING_DOMAIN = {
    "rules": [
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "whitelist": [
                        "Developer", "Contractor"
                    ]
                },
            ],
            "local": [
                {
                    "groups": "{0}",
                }
            ]
        }
    ]
}

MAPPING_LOCAL_USER_LOCAL_DOMAIN = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "domain": {
                            "id": LOCAL_DOMAIN
                        },
                        "type": "local"
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "UserName",
                    "any_one_of": [
                        "jsmith"
                    ]
                }
            ]
        }
    ]
}

MAPPING_GROUPS_BLACKLIST_MULTIPLES = {
    "rules": [
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "blacklist": [
                        "Developer", "Manager"
                    ]
                },
                {
                    "type": "Thing"  # this could be variable length!
                },
                {
                    "type": "UserName"
                },
            ],
            "local": [
                {
                    "groups": "{0}",
                    "domain": {
                        "id": DEVELOPER_GROUP_DOMAIN_ID
                    }
                },
                {
                    "user": {
                        "name": "{2}",
                    }
                }
            ]
        }
    ]
}
MAPPING_GROUPS_BLACKLIST = {
    "rules": [
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "blacklist": [
                        "Developer", "Manager"
                    ]
                },
                {
                    "type": "UserName"
                }
            ],
            "local": [
                {
                    "groups": "{0}",
                    "domain": {
                        "id": DEVELOPER_GROUP_DOMAIN_ID
                    }
                },
                {
                    "user": {
                        "name": "{1}"
                    }
                }
            ]
        }
    ]
}

MAPPING_GROUPS_BLACKLIST_REGEX = {
    "rules": [
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "blacklist": [
                        ".*Employee$"
                    ],
                    "regex": True
                },
            ],
            "local": [
                {
                    "groups": "{0}",
                    "domain": {
                        "id": FEDERATED_DOMAIN
                    }
                },
            ]
        }
    ]
}

MAPPING_GROUPS_WHITELIST_REGEX = {
    "rules": [
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "whitelist": [
                        ".*Employee$"
                    ],
                    "regex": True
                },
            ],
            "local": [
                {
                    "groups": "{0}",
                    "domain": {
                        "id": FEDERATED_DOMAIN
                    }
                },
            ]
        }
    ]
}

# Exercise all possibilities of user identification. Values are hardcoded on
# purpose.
MAPPING_USER_IDS = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "UserName",
                    "any_one_of": [
                        "jsmith"
                    ]
                }
            ]
        },
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "id": "abc123@example.com",
                        "domain": {
                            "id": "federated"
                        }
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "UserName",
                    "any_one_of": [
                        "tbo"
                    ]
                }
            ]
        },
        {
            "local": [
                {
                    "user": {
                        "id": "{0}"
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "UserName",
                    "any_one_of": [
                        "bob"
                    ]
                }
            ]
        },
        {
            "local": [
                {
                    "user": {
                        "id": "abc123@example.com",
                        "name": "{0}",
                        "domain": {
                            "id": "federated"
                        }
                    }
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "UserName",
                    "any_one_of": [
                        "bwilliams"
                    ]
                }
            ]
        }
    ]
}

MAPPING_GROUPS_BLACKLIST_MISSING_DOMAIN = {
    "rules": [
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "blacklist": [
                        "Developer", "Manager"
                    ]
                },
            ],
            "local": [
                {
                    "groups": "{0}",
                },
            ]
        }
    ]
}

MAPPING_GROUPS_WHITELIST_AND_BLACKLIST = {
    "rules": [
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "blacklist": [
                        "Employee"
                    ],
                    "whitelist": [
                        "Contractor"
                    ]
                },
            ],
            "local": [
                {
                    "groups": "{0}",
                    "domain": {
                        "id": DEVELOPER_GROUP_DOMAIN_ID
                    }
                },
            ]
        }
    ]
}

# Mapping used by tokenless test cases, it maps the user_name
# and domain_name.
MAPPING_WITH_USERNAME_AND_DOMAINNAME = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'name': '{0}',
                        'domain': {
                            'name': '{1}'
                        },
                        'type': 'local'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_NAME'
                },
                {
                    'type': 'SSL_CLIENT_DOMAIN_NAME'
                }
            ]
        }
    ]
}

# Mapping used by tokenless test cases, it maps the user_id
# and domain_name.
MAPPING_WITH_USERID_AND_DOMAINNAME = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'id': '{0}',
                        'domain': {
                            'name': '{1}'
                        },
                        'type': 'local'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_ID'
                },
                {
                    'type': 'SSL_CLIENT_DOMAIN_NAME'
                }
            ]
        }
    ]
}

# Mapping used by tokenless test cases, it maps the user_name
# and domain_id.
MAPPING_WITH_USERNAME_AND_DOMAINID = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'name': '{0}',
                        'domain': {
                            'id': '{1}'
                        },
                        'type': 'local'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_NAME'
                },
                {
                    'type': 'SSL_CLIENT_DOMAIN_ID'
                }
            ]
        }
    ]
}

# Mapping used by tokenless test cases, it maps the user_id
# and domain_id.
MAPPING_WITH_USERID_AND_DOMAINID = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'id': '{0}',
                        'domain': {
                            'id': '{1}'
                        },
                        'type': 'local'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_ID'
                },
                {
                    'type': 'SSL_CLIENT_DOMAIN_ID'
                }
            ]
        }
    ]
}

# Mapping used by tokenless test cases, it maps the domain_id only.
MAPPING_WITH_DOMAINID_ONLY = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'domain': {
                            'id': '{0}'
                        },
                        'type': 'local'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_DOMAIN_ID'
                }
            ]
        }
    ]
}

MAPPING_GROUPS_IDS_WHITELIST = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    }
                },
                {
                    "group_ids": "{1}"
                },
                {
                    "group": {
                        "id": "{2}"
                    }
                }
            ],
            "remote": [
                {
                    "type": "name"
                },
                {
                    "type": "group_ids",
                    "whitelist": [
                        "abc123", "ghi789", "321cba"
                    ]
                },
                {
                    "type": "group"
                }
            ]
        }
    ]
}

MAPPING_GROUPS_IDS_BLACKLIST = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    }
                },
                {
                    "group_ids": "{1}"
                },
                {
                    "group": {
                        "id": "{2}"
                    }
                }
            ],
            "remote": [
                {
                    "type": "name"
                },
                {
                    "type": "group_ids",
                    "blacklist": [
                        "def456"
                    ]
                },
                {
                    "type": "group"
                }
            ]
        }
    ]
}

# Mapping used by tokenless test cases, it maps the domain_name only.
MAPPING_WITH_DOMAINNAME_ONLY = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'domain': {
                            'name': '{0}'
                        },
                        'type': 'local'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_DOMAIN_NAME'
                }
            ]
        }
    ]
}

# Mapping used by tokenless test cases, it maps the user_name only.
MAPPING_WITH_USERNAME_ONLY = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'name': '{0}',
                        'type': 'local'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_NAME'
                }
            ]
        }
    ]
}

# Mapping used by tokenless test cases, it maps the user_id only.
MAPPING_WITH_USERID_ONLY = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'id': '{0}',
                        'type': 'local'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_ID'
                }
            ]
        }
    ]
}

MAPPING_FOR_EPHEMERAL_USER = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'name': '{0}',
                        'type': 'ephemeral'
                    },
                    'group': {
                        'id': 'dummy'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_NAME'
                }
            ]
        }
    ]
}

MAPPING_FOR_EPHEMERAL_USER_AND_GROUP_DOMAIN_NAME = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'name': '{0}',
                        'type': 'ephemeral'
                    },
                    'group': {
                        'name': 'dummy',
                        'domain': {
                            'name': 'dummy'
                        }
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_NAME'
                }
            ]
        }
    ]
}

MAPPING_FOR_DEFAULT_EPHEMERAL_USER = {
    'rules': [
        {
            'local': [
                {
                    'user': {
                        'name': '{0}'
                    },
                    'group': {
                        'id': 'dummy'
                    }
                }
            ],
            'remote': [
                {
                    'type': 'SSL_CLIENT_USER_NAME'
                }
            ]
        }
    ]
}

MAPPING_GROUPS_WHITELIST_PASS_THROUGH = {
    "rules": [
        {
            "remote": [
                {
                    "type": "UserName"
                }
            ],
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "domain": {
                            "id": DEVELOPER_GROUP_DOMAIN_ID
                        }
                    }
                }
            ]
        },
        {
            "remote": [
                {
                    "type": "orgPersonType",
                    "whitelist": ['Developer']
                }
            ],
            "local": [
                {
                    "groups": "{0}",
                    "domain": {
                        "id": DEVELOPER_GROUP_DOMAIN_ID
                    }
                }
            ]
        }
    ]
}

MAPPING_BAD_LOCAL_SETUP = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "domain": {"id": "default"}
                    },
                    "whatisthis": "local"
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

MAPPING_BAD_LOCAL_TYPE_USER_IN_ASSERTION = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}",
                        "groups": "{1}"
                    }
                }
            ],
            "remote": [
                {
                    "type": "openstack_user"
                },
                {
                    "type": "openstack_groups"

                },
                {
                    "type": "openstack_roles",
                    "any_one_of": [
                        "Admin"
                    ]
                }
            ]
        },
    ]
}

MAPPING_GROUPS_WITH_EMAIL = {
    "rules": [
        {
            "remote": [
                {
                    "type": "groups",
                },
                {
                    "type": "userEmail",
                },
                {
                    "type": "UserName"
                }
            ],
            "local": [
                {
                    "groups": "{0}",
                    "domain": {
                        "id": DEVELOPER_GROUP_DOMAIN_ID
                    }
                },
                {
                    "user": {
                        "name": "{2}",
                        "email": "{1}"
                    }
                }
            ]
        }
    ]
}


MAPPING_GROUPS_DOMAIN_OF_USER = {
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

EMPLOYEE_ASSERTION = {
    'Email': 'tim@example.com',
    'UserName': 'tbo',
    'FirstName': 'Tim',
    'LastName': 'Bo',
    'orgPersonType': 'Employee;BuildingX'
}

EMPLOYEE_PARTTIME_ASSERTION = {
    'Email': 'tim@example.com',
    'UserName': 'tbo',
    'FirstName': 'Tim',
    'LastName': 'Bo',
    'orgPersonType': 'Employee;PartTimeEmployee;Manager'
}

EMPLOYEE_ASSERTION_MULTIPLE_GROUPS = {
    'Email': 'tim@example.com',
    'UserName': 'tbo',
    'FirstName': 'Tim',
    'LastName': 'Bo',
    'orgPersonType': 'Developer;Manager;Contractor',
    'Thing': 'yes!;maybe!;no!!'
}

EMPLOYEE_ASSERTION_PREFIXED = {
    'PREFIX_Email': 'tim@example.com',
    'PREFIX_UserName': 'tbo',
    'PREFIX_FirstName': 'Tim',
    'PREFIX_LastName': 'Bo',
    'PREFIX_orgPersonType': 'SuperEmployee;BuildingX'
}

CONTRACTOR_ASSERTION = {
    'Email': 'jill@example.com',
    'UserName': 'jsmith',
    'FirstName': 'Jill',
    'LastName': 'Smith',
    'orgPersonType': 'Contractor;Non-Dev'
}

ADMIN_ASSERTION = {
    'Email': 'bob@example.com',
    'UserName': 'bob',
    'FirstName': 'Bob',
    'LastName': 'Thompson',
    'orgPersonType': 'Admin;Chief'
}

CUSTOMER_ASSERTION = {
    'Email': 'beth@example.com',
    'UserName': 'bwilliams',
    'FirstName': 'Beth',
    'LastName': 'Williams',
    'orgPersonType': 'Customer'
}

ANOTHER_CUSTOMER_ASSERTION = {
    'Email': 'mark@example.com',
    'UserName': 'markcol',
    'FirstName': 'Mark',
    'LastName': 'Collins',
    'orgPersonType': 'Managers;CEO;CTO'
}

TESTER_ASSERTION = {
    'Email': 'testacct@example.com',
    'UserName': 'testacct',
    'FirstName': 'Test',
    'LastName': 'Account',
    'orgPersonType': 'MadeupGroup;Tester;GroupX'
}

ANOTHER_TESTER_ASSERTION = {
    'Email': 'testacct@example.com',
    'UserName': 'IamTester'
}

BAD_TESTER_ASSERTION = {
    'Email': 'eviltester@example.org',
    'UserName': 'Evil',
    'FirstName': 'Test',
    'LastName': 'Account',
    'orgPersonType': 'Tester'
}

BAD_DEVELOPER_ASSERTION = {
    'Email': 'evildeveloper@example.org',
    'UserName': 'Evil',
    'FirstName': 'Develop',
    'LastName': 'Account',
    'orgPersonType': 'Developer'
}

MALFORMED_TESTER_ASSERTION = {
    'Email': 'testacct@example.com',
    'UserName': 'testacct',
    'FirstName': 'Test',
    'LastName': 'Account',
    'orgPersonType': 'Tester',
    'object': object(),
    'dictionary': dict(zip('teststring', range(10))),
    'tuple': tuple(range(5))
}

DEVELOPER_ASSERTION = {
    'Email': 'developacct@example.com',
    'UserName': 'developacct',
    'FirstName': 'Develop',
    'LastName': 'Account',
    'orgPersonType': 'Developer'
}

CONTRACTOR_MALFORMED_ASSERTION = {
    'UserName': 'user',
    'FirstName': object(),
    'orgPersonType': 'Contractor'
}

LOCAL_USER_ASSERTION = {
    'UserName': 'marek',
    'UserType': 'random'
}

ANOTHER_LOCAL_USER_ASSERTION = {
    'UserName': 'marek',
    'Position': 'DirectorGeneral'
}

USER_NO_GROUPS_ASSERTION = {
    'Email': 'nogroupsuser1@example.org',
    'UserName': 'nogroupsuser1',
    'orgPersonType': 'NoGroupsOrg'
}

UNMATCHED_GROUP_ASSERTION = {
    'REMOTE_USER': 'Any Momoose',
    'REMOTE_USER_GROUPS': 'EXISTS;NO_EXISTS'
}

GROUP_IDS_ASSERTION = {
    'name': 'opilotte',
    'group_ids': 'abc123;def456;ghi789',
    'group': 'klm012'
}

GROUP_IDS_ASSERTION_ONLY_ONE_GROUP = {
    'name': 'opilotte',
    'group_ids': '321cba',
    'group': '210mlk'
}

UNICODE_NAME_ASSERTION = {
    'PFX_Email': 'jon@example.com',
    'PFX_UserName': 'jonkare',
    'PFX_FirstName': 'Jon Kåre',
    'PFX_LastName': 'Hellån',
    'PFX_orgPersonType': 'Admin;Chief'
}

GROUPS_ASSERTION_ONLY_ONE_GROUP = {
    'userEmail': 'jill@example.com',
    'UserName': 'jsmith',
    'groups': 'ALL USERS'
}

GROUPS_DOMAIN_ASSERTION = {
    'openstack_user': 'bwilliams',
    'openstack_user_domain': 'default',
    'openstack_roles': 'Admin',
    'openstack_groups': 'JSON:{"name":"group1","domain":{"name":"xxx"}};'
                        'JSON:{"name":"group2","domain":{"name":"yyy"}}'
}

MAPPING_UNICODE = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0} {1}",
                        "email": "{2}"
                    },
                    "group": {
                        "id": EMPLOYEE_GROUP_ID
                    }
                }
            ],
            "remote": [
                {
                    "type": "PFX_FirstName"
                },
                {
                    "type": "PFX_LastName"
                },
                {
                    "type": "PFX_Email"
                },
                {
                    "type": "PFX_orgPersonType",
                    "any_one_of": [
                        "Admin",
                        "Big Cheese"
                    ]
                }
            ]
        },
    ],
}

MAPPING_PROJECTS = {
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
                        {"name": "Production",
                         "roles": [{"name": "observer"}]},
                        {"name": "Staging",
                         "roles": [{"name": "member"}]},
                        {"name": "Project for {0}",
                         "roles": [{"name": "admin"}]},
                    ],
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                },
                {
                    "type": "Email",
                },
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        "Employee"
                    ]
                }
            ]
        }
    ]
}

MAPPING_PROJECTS_WITHOUT_ROLES = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    },
                    "projects": [
                        {"name": "a"},
                        {"name": "b"},
                        {"name": "Project for {0}"},
                    ],
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                }
            ]
        },
    ]
}

MAPPING_PROJECTS_WITHOUT_NAME = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    },
                    "projects": [
                        {"roles": [{"name": "observer"}]},
                        {"name": "Staging",
                         "roles": [{"name": "member"}]},
                        {"name": "Project for {0}",
                         "roles": [{"name": "admin"}]},
                    ]
                }
            ],
            "remote": [
                {
                    "type": "UserName"
                }
            ]
        },
    ]
}

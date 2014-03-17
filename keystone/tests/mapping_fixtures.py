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
DEVELOPER_GROUP_ID = "xyz"

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

EMPLOYEE_ASSERTION = {
    'Email': 'tim@example.com',
    'UserName': 'tbo',
    'FirstName': 'Tim',
    'LastName': 'Bo',
    'orgPersonType': 'Employee;BuildingX;'
}

EMPLOYEE_ASSERTION_PREFIXED = {
    'PREFIX_Email': 'tim@example.com',
    'PREFIX_UserName': 'tbo',
    'PREFIX_FirstName': 'Tim',
    'PREFIX_LastName': 'Bo',
    'PREFIX_orgPersonType': 'SuperEmployee;BuildingX;'
}

CONTRACTOR_ASSERTION = {
    'Email': 'jill@example.com',
    'UserName': 'jsmith',
    'FirstName': 'Jill',
    'LastName': 'Smith',
    'orgPersonType': 'Contractor;Non-Dev;'
}

ADMIN_ASSERTION = {
    'Email': 'bob@example.com',
    'UserName': 'bob',
    'FirstName': 'Bob',
    'LastName': 'Thompson',
    'orgPersonType': 'Admin;Chief;'
}

CUSTOMER_ASSERTION = {
    'Email': 'beth@example.com',
    'UserName': 'bwilliams',
    'FirstName': 'Beth',
    'LastName': 'Williams',
    'orgPersonType': 'Customer;'
}

TESTER_ASSERTION = {
    'Email': 'testacct@example.com',
    'UserName': 'testacct',
    'FirstName': 'Test',
    'LastName': 'Account',
    'orgPersonType': 'Tester;'
}

BAD_TESTER_ASSERTION = {
    'Email': 'eviltester@example.org',
    'UserName': 'Evil',
    'FirstName': 'Test',
    'LastName': 'Account',
    'orgPersonType': 'Tester;'
}

MALFORMED_TESTER_ASSERTION = {
    'Email': 'testacct@example.com',
    'UserName': 'testacct',
    'FirstName': 'Test',
    'LastName': 'Account',
    'orgPersonType': 'Tester;',
    'object': object(),
    'dictionary': dict(zip('teststring', xrange(10))),
    'tuple': tuple(xrange(5))
}

CONTRACTOR_MALFORMED_ASSERTION = {
    'UserName': 'user',
    'FirstName': object(),
    'orgPersonType': 'Contractor'
}

# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
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

MAPPING_SMALL = {
    'name': 'large mapping',
    "rules": [
        {
            "local": [
                {
                    "group": {
                        "id": "0cd5e9"
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
                        "id": "85a868"
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

MAPPING_LARGE = {
    "rules": [
        {
            "local": [
                {
                    "user": {
                        "name": "$0 $1",
                        "email": "$2"
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
                    "type": "Group",
                    "any_one_of": [
                        "Admin",
                        "God"
                    ]
                }
            ]
        },
        {
            "local": [
                {
                    "user": {
                        "name": "$0",
                        "email": "$1"
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
                    "type": "Group",
                    "any_one_of": [
                        "Customer"
                    ]
                }
            ]
        },
        {
            "local": [
                {
                    "group": {
                        "id": "123"
                    }
                },
                {
                    "group": {
                        "id": "xyz"
                    }
                }
            ],
            "remote": [
                {
                    "type": "Group",
                    "any_one_of": [
                        "Special"
                    ]
                },
                {
                    "type": "Email",
                    "any_one_of": [
                        "^@example.com$"
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
                    "user": "$1"
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
                    "user": "$1"
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
                }
            ],
            "remote": [
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
                }
            ],
            "remote": [
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
                }
            ],
            "remote": [
                {
                    "type": "orgPersonType",
                    "invalid_type": "xyz"
                }
            ]
        }
    ]
}

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from keystone.auth import schema
from keystone import exception
from keystone.tests import unit


class TestValidateIssueTokenAuth(unit.BaseTestCase):
    def _expect_failure(self, post_data):
        self.assertRaises(
            exception.SchemaValidationError,
            schema.validate_issue_token_auth, post_data)

    def test_auth_not_object_ex(self):
        self._expect_failure('something')

    def test_auth_no_identity_ex(self):
        self._expect_failure({})

    def test_identity_not_object_ex(self):
        self._expect_failure({'identity': 'something'})

    def test_no_methods_ex(self):
        self._expect_failure({'identity': {}})

    def test_methods_not_array_ex(self):
        p = {'identity': {'methods': 'something'}}
        self._expect_failure(p)

    def test_methods_not_array_str_ex(self):
        p = {'identity': {'methods': [{}]}}
        self._expect_failure(p)

    def test_no_auth_plugin_parameters(self):
        # auth plugin (password / token) may not be present.
        post_data = {
            'identity': {
                'methods': ['password'],
            },
        }
        schema.validate_issue_token_auth(post_data)

    def test_password_not_object_ex(self):
        # if password is present, it must be an object.
        p = {
            'identity': {
                'methods': ['password'],
                'password': 'something',
            },
        }
        self._expect_failure(p)

    def test_password_user_not_object_ex(self):
        # if user is present, it must be an object
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': 'something',
                },
            },
        }
        self._expect_failure(p)

    def test_password_user_name_not_string_ex(self):
        # if user name is present, it must be a string
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'name': 1,
                    },
                },
            },
        }
        self._expect_failure(p)

    def test_password_user_id_not_string_ex(self):
        # if user id is present, it must be a string
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'id': {},
                    },
                },
            },
        }
        self._expect_failure(p)

    def test_password_no_user_id_or_name_ex(self):
        # either user id or name must be present.
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {},
                },
            },
        }
        self._expect_failure(p)

    def test_password_user_password_not_string_ex(self):
        # if user password is present, it must be a string
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'id': 'something',
                        'password': {},
                    },
                },
            },
        }
        self._expect_failure(p)

    def test_password_user_domain_not_object_ex(self):
        # if user domain is present, it must be an object
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'id': 'something',
                        'domain': 'something',
                    },
                },
            },
        }
        self._expect_failure(p)

    def test_password_user_domain_no_id_or_name_ex(self):
        # user domain must have id or name.
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'id': 'something',
                        'domain': {},
                    },
                },
            },
        }
        self._expect_failure(p)

    def test_password_user_domain_name_not_string_ex(self):
        # if user domain name is present, it must be a string.
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'id': 'something',
                        'domain': {
                            'name': {}
                        },
                    },
                },
            },
        }
        self._expect_failure(p)

    def test_password_user_domain_id_not_string_ex(self):
        # if user domain id is present, it must be a string.
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'id': 'something',
                        'domain': {
                            'id': {}
                        },
                    },
                },
            },
        }
        self._expect_failure(p)

    def test_token(self):
        # valid token auth plugin data is supported.
        p = {
            'identity': {
                'methods': ['token'],
                'token': {
                    'id': 'something',
                },
            },
        }
        schema.validate_issue_token_auth(p)

    def test_token_not_object_ex(self):
        # if token auth plugin data is present, it must be an object.
        p = {
            'identity': {
                'methods': ['token'],
                'token': '',
            },
        }
        self._expect_failure(p)

    def test_token_no_id_ex(self):
        # if token auth plugin data is present, id must be present.
        p = {
            'identity': {
                'methods': ['token'],
                'token': {},
            },
        }
        self._expect_failure(p)

    def test_token_id_not_string_ex(self):
        # if token auth plugin data is present, id must be a string.
        p = {
            'identity': {
                'methods': ['token'],
                'token': {
                    'id': 123,
                },
            },
        }
        self._expect_failure(p)

    def test_scope_not_object_or_string_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': 1,
        }
        self._expect_failure(p)

    def test_project_not_object_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'project': 'something',
            },
        }
        self._expect_failure(p)

    def test_project_name_not_string_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'project': {
                    'name': {},
                },
            },
        }
        self._expect_failure(p)

    def test_project_id_not_string_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'project': {
                    'id': {},
                },
            },
        }
        self._expect_failure(p)

    def test_project_no_id_or_name_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'project': {},
            },
        }
        self._expect_failure(p)

    def test_project_domain_not_object_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'project': {
                    'id': 'something',
                    'domain': 'something',
                },
            },
        }
        self._expect_failure(p)

    def test_project_domain_name_not_string_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'project': {
                    'id': 'something',
                    'domain': {'name': {}, },
                },
            },
        }
        self._expect_failure(p)

    def test_project_domain_id_not_string_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'project': {
                    'id': 'something',
                    'domain': {'id': {}, },
                },
            },
        }
        self._expect_failure(p)

    def test_project_domain_no_id_or_name_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'project': {
                    'id': 'something',
                    'domain': {},
                },
            },
        }
        self._expect_failure(p)

    def test_domain_not_object_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'domain': 'something',
            },
        }
        self._expect_failure(p)

    def test_domain_id_not_string_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'domain': {'id': {}, },
            },
        }
        self._expect_failure(p)

    def test_domain_name_not_string_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'domain': {'name': {}, },
            },
        }
        self._expect_failure(p)

    def test_domain_no_id_or_name_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'domain': {},
            },
        }
        self._expect_failure(p)

    def test_trust_not_object_ex(self):
        p = {
            'identity': {'methods': [], },
            'scope': {
                'OS-TRUST:trust': 'something',
            },
        }
        self._expect_failure(p)

    def test_unscoped(self):
        post_data = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'name': 'admin',
                        'domain': {
                            'name': 'Default',
                        },
                        'password': 'devstacker',
                    },
                },
            },
        }
        schema.validate_issue_token_auth(post_data)

    def test_user_domain_id(self):
        post_data = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'name': 'admin',
                        'domain': {
                            'id': 'default',
                        },
                        'password': 'devstacker',
                    },
                },
            },
        }
        schema.validate_issue_token_auth(post_data)

    def test_two_methods(self):
        post_data = {
            'identity': {
                'methods': ['password', 'mapped'],
                'password': {
                    'user': {
                        'name': 'admin',
                        'domain': {
                            'name': 'Default',
                        },
                        'password': 'devstacker',
                    },
                },
            },
        }
        schema.validate_issue_token_auth(post_data)

    def test_project_scoped(self):
        post_data = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'name': 'admin',
                        'domain': {
                            'name': 'Default',
                        },
                        'password': 'devstacker',
                    },
                },
            },
            'scope': {
                'project': {
                    'name': 'demo',
                    'domain': {
                        'name': 'Default',
                    },
                },
            },
        }
        schema.validate_issue_token_auth(post_data)

    def test_domain_scoped(self):
        post_data = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'name': 'admin',
                        'domain': {
                            'name': 'Default',
                        },
                        'password': 'devstacker',
                    },
                },
            },
            'scope': {
                'domain': {
                    'name': 'Default',
                },
            },
        }
        schema.validate_issue_token_auth(post_data)

    def test_explicit_unscoped(self):
        post_data = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'name': 'admin',
                        'domain': {
                            'name': 'Default',
                        },
                        'password': 'devstacker',
                    },
                },
            },
            'scope': 'unscoped',
        }
        schema.validate_issue_token_auth(post_data)

    def test_additional_properties(self):
        # Everything can have extra properties and they're ignored.
        p = {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'id': 'whatever',
                        'extra4': 'whatever4',
                        'domain': {
                            'id': 'whatever',
                            'extra5': 'whatever5',
                        },
                    },
                    'extra3': 'whatever3',
                },
                'token': {
                    'id': 'something',
                    'extra9': 'whatever9',
                },
                'extra4': 'whatever4',
            },
            'scope': {
                'project': {
                    'id': 'something',
                    'domain': {
                        'id': 'something',
                        'extra8': 'whatever8',
                    },
                    'extra7': 'whatever7',
                },
                'domain': {
                    'id': 'something',
                    'extra9': 'whatever9',
                },
                'extra6': 'whatever6',
            },
            'extra2': 'whatever2',
        }
        schema.validate_issue_token_auth(p)

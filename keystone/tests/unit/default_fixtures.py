# Copyright 2012 OpenStack Foundation
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

# NOTE(dolph): please try to avoid additional fixtures if possible; test suite
#              performance may be negatively affected.

DEFAULT_DOMAIN_ID = 'default'

TENANTS = [
    {
        'id': 'bar',
        'name': 'BAR',
        'domain_id': DEFAULT_DOMAIN_ID,
        'description': 'description',
        'enabled': True,
        'parent_id': None,
        'is_domain': False,
    }, {
        'id': 'baz',
        'name': 'BAZ',
        'domain_id': DEFAULT_DOMAIN_ID,
        'description': 'description',
        'enabled': True,
        'parent_id': None,
        'is_domain': False,
    }, {
        'id': 'mtu',
        'name': 'MTU',
        'description': 'description',
        'enabled': True,
        'domain_id': DEFAULT_DOMAIN_ID,
        'parent_id': None,
        'is_domain': False,
    }, {
        'id': 'service',
        'name': 'service',
        'description': 'description',
        'enabled': True,
        'domain_id': DEFAULT_DOMAIN_ID,
        'parent_id': None,
        'is_domain': False,
    }
]

# NOTE(ja): a role of keystone_admin is done in setUp
USERS = [
    {
        'id': 'foo',
        'name': 'FOO',
        'domain_id': DEFAULT_DOMAIN_ID,
        'password': 'foo2',
        'tenants': ['bar'],
        'enabled': True,
        'email': 'foo@bar.com',
    }, {
        'id': 'two',
        'name': 'TWO',
        'domain_id': DEFAULT_DOMAIN_ID,
        'password': 'two2',
        'enabled': True,
        'default_project_id': 'baz',
        'tenants': ['baz'],
        'email': 'two@three.com',
    }, {
        'id': 'badguy',
        'name': 'BadGuy',
        'domain_id': DEFAULT_DOMAIN_ID,
        'password': 'bad',
        'enabled': False,
        'default_project_id': 'baz',
        'tenants': ['baz'],
        'email': 'bad@guy.com',
    }, {
        'id': 'sna',
        'name': 'SNA',
        'domain_id': DEFAULT_DOMAIN_ID,
        'password': 'snafu',
        'enabled': True,
        'tenants': ['bar'],
        'email': 'sna@snl.coom',
    }
]

ROLES = [
    {
        'id': 'admin',
        'name': 'admin',
    }, {
        'id': 'member',
        'name': 'Member',
    }, {
        'id': '9fe2ff9ee4384b1894a90878d3e92bab',
        'name': '_member_',
    }, {
        'id': 'other',
        'name': 'Other',
    }, {
        'id': 'browser',
        'name': 'Browser',
    }, {
        'id': 'writer',
        'name': 'Writer',
    }, {
        'id': 'service',
        'name': 'Service',
    }
]

DOMAINS = [{'description':
            (u'Owns users and tenants (i.e. projects)'
                ' available on Identity API v2.'),
            'enabled': True,
            'id': DEFAULT_DOMAIN_ID,
            'name': u'Default'}]

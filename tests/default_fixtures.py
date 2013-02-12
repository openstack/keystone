# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from keystone import config


DEFAULT_DOMAIN_ID = config.CONF.identity.default_domain_id


TENANTS = [
    {
        'id': 'bar',
        'name': 'BAR',
        'domain_id': DEFAULT_DOMAIN_ID,
    }, {
        'id': 'baz',
        'name': 'BAZ',
        'domain_id': DEFAULT_DOMAIN_ID,
        'description': 'description',
        'enabled': True,
    }
]

# NOTE(ja): a role of keystone_admin and attribute "is_admin" is done in setUp
USERS = [
    {
        'id': 'foo',
        'name': 'FOO',
        'domain_id': DEFAULT_DOMAIN_ID,
        'password': 'foo2',
        'tenants': ['bar']
    }, {
        'id': 'two',
        'name': 'TWO',
        'domain_id': DEFAULT_DOMAIN_ID,
        'password': 'two2',
        'email': 'two@example.com',
        'enabled': True,
        'tenant_id': 'baz',
        'tenants': ['baz'],
    }, {
        'id': 'badguy',
        'name': 'BadGuy',
        'domain_id': DEFAULT_DOMAIN_ID,
        'password': 'bad',
        'email': 'bad@guy.com',
        'enabled': False,
        'tenant_id': 'baz',
        'tenants': ['baz'],
    }
]

METADATA = [
    {
        'user_id': 'foo',
        'tenant_id': 'bar',
        'extra': 'extra',
    }
]

ROLES = [
    {
        'id': 'keystone_admin',
        'name': 'Keystone Admin',
    }, {
        'id': 'member',
        'name': 'Member',
    }
]

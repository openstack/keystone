# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import uuid

from keystone import config
from keystone.identity.backends import pam as identity_pam
from keystone import tests


CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class PamIdentity(tests.TestCase):
    def setUp(self):
        super(PamIdentity, self).setUp()
        self.config([tests.etcdir('keystone.conf.sample'),
                     tests.testsdir('test_overrides.conf'),
                     tests.testsdir('backend_pam.conf')])
        self.identity_api = identity_pam.PamIdentity()
        tenant_id = uuid.uuid4().hex
        self.tenant_in = {'id': tenant_id, 'name': tenant_id}
        self.user_in = {'id': CONF.pam.userid, 'name': CONF.pam.userid}

    def test_get_project(self):
        tenant_out = self.identity_api.get_project(self.tenant_in['id'])
        self.assertDictEqual(self.tenant_in, tenant_out)

    def test_get_project_by_name(self):
        tenant_in_name = self.tenant_in['name']
        tenant_out = self.identity_api.get_project_by_name(
            tenant_in_name, DEFAULT_DOMAIN_ID)
        self.assertDictEqual(self.tenant_in, tenant_out)

    def test_get_user(self):
        user_out = self.identity_api.get_user(self.user_in['id'])
        self.assertDictEqual(self.user_in, user_out)

    def test_get_user_by_name(self):
        user_out = self.identity_api.get_user_by_name(
            self.user_in['name'], DEFAULT_DOMAIN_ID)
        self.assertDictEqual(self.user_in, user_out)

    def test_get_metadata_for_non_root(self):
        metadata_out = self.identity_api._get_metadata(self.user_in['id'],
                                                       self.tenant_in['id'])
        self.assertDictEqual({}, metadata_out)

    def test_get_metadata_for_root(self):
        metadata = {'is_admin': True}
        metadata_out = self.identity_api._get_metadata('root',
                                                       self.tenant_in['id'])
        self.assertDictEqual(metadata, metadata_out)

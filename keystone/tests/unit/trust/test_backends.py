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

import datetime
import uuid

from oslo_utils import timeutils

from keystone.common import provider_api
from keystone import exception
from keystone.tests.unit import core

PROVIDERS = provider_api.ProviderAPIs


class TrustTests(object):
    def create_sample_trust(self, new_id, remaining_uses=None):
        self.trustor = self.user_foo
        self.trustee = self.user_two
        expires_at = datetime.datetime.utcnow().replace(year=2032)
        trust_data = (PROVIDERS.trust_api.create_trust
                      (new_id,
                       {'trustor_user_id': self.trustor['id'],
                        'trustee_user_id': self.user_two['id'],
                        'project_id': self.project_bar['id'],
                        'expires_at': expires_at,
                        'impersonation': True,
                        'remaining_uses': remaining_uses},
                       roles=[{"id": "member"},
                              {"id": "other"},
                              {"id": "browser"}]))
        return trust_data

    def test_delete_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        trust_id = trust_data['id']
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.get_trust(trust_id)
        self.assertEqual(new_id, trust_data['id'])
        PROVIDERS.trust_api.delete_trust(trust_id)
        self.assertRaises(exception.TrustNotFound,
                          PROVIDERS.trust_api.get_trust,
                          trust_id)

    def test_delete_trust_not_found(self):
        trust_id = uuid.uuid4().hex
        self.assertRaises(exception.TrustNotFound,
                          PROVIDERS.trust_api.delete_trust,
                          trust_id)

    def test_get_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        trust_id = trust_data['id']
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.get_trust(trust_id)
        self.assertEqual(new_id, trust_data['id'])
        PROVIDERS.trust_api.delete_trust(trust_data['id'])

    def test_get_deleted_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)
        self.assertIsNotNone(trust_data)
        self.assertIsNone(trust_data['deleted_at'])
        PROVIDERS.trust_api.delete_trust(new_id)
        self.assertRaises(exception.TrustNotFound,
                          PROVIDERS.trust_api.get_trust,
                          new_id)
        deleted_trust = PROVIDERS.trust_api.get_trust(
            trust_data['id'], deleted=True
        )
        self.assertEqual(trust_data['id'], deleted_trust['id'])
        self.assertIsNotNone(deleted_trust.get('deleted_at'))

    def test_create_trust(self):
        new_id = uuid.uuid4().hex
        trust_data = self.create_sample_trust(new_id)

        self.assertEqual(new_id, trust_data['id'])
        self.assertEqual(self.trustee['id'], trust_data['trustee_user_id'])
        self.assertEqual(self.trustor['id'], trust_data['trustor_user_id'])
        self.assertGreater(timeutils.normalize_time(trust_data['expires_at']),
                           timeutils.utcnow())

        self.assertEqual([{'id': 'member'},
                          {'id': 'other'},
                          {'id': 'browser'}], trust_data['roles'])

    def test_list_trust_by_trustee(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = PROVIDERS.trust_api.list_trusts_for_trustee(
            self.trustee['id']
        )
        self.assertEqual(3, len(trusts))
        self.assertEqual(trusts[0]["trustee_user_id"], self.trustee['id'])
        trusts = PROVIDERS.trust_api.list_trusts_for_trustee(
            self.trustor['id']
        )
        self.assertEqual(0, len(trusts))

    def test_list_trust_by_trustor(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = PROVIDERS.trust_api.list_trusts_for_trustor(
            self.trustor['id']
        )
        self.assertEqual(3, len(trusts))
        self.assertEqual(trusts[0]["trustor_user_id"], self.trustor['id'])
        trusts = PROVIDERS.trust_api.list_trusts_for_trustor(
            self.trustee['id']
        )
        self.assertEqual(0, len(trusts))

    def test_list_trusts(self):
        for i in range(3):
            self.create_sample_trust(uuid.uuid4().hex)
        trusts = PROVIDERS.trust_api.list_trusts()
        self.assertEqual(3, len(trusts))

    def test_trust_has_remaining_uses_positive(self):
        # create a trust with limited uses, check that we have uses left
        trust_data = self.create_sample_trust(uuid.uuid4().hex,
                                              remaining_uses=5)
        self.assertEqual(5, trust_data['remaining_uses'])
        # create a trust with unlimited uses, check that we have uses left
        trust_data = self.create_sample_trust(uuid.uuid4().hex)
        self.assertIsNone(trust_data['remaining_uses'])

    def test_trust_has_remaining_uses_negative(self):
        # try to create a trust with no remaining uses, check that it fails
        self.assertRaises(exception.ValidationError,
                          self.create_sample_trust,
                          uuid.uuid4().hex,
                          remaining_uses=0)
        # try to create a trust with negative remaining uses,
        # check that it fails
        self.assertRaises(exception.ValidationError,
                          self.create_sample_trust,
                          uuid.uuid4().hex,
                          remaining_uses=-12)

    def test_consume_use(self):
        # consume a trust repeatedly until it has no uses anymore
        trust_data = self.create_sample_trust(uuid.uuid4().hex,
                                              remaining_uses=2)
        PROVIDERS.trust_api.consume_use(trust_data['id'])
        t = PROVIDERS.trust_api.get_trust(trust_data['id'])
        self.assertEqual(1, t['remaining_uses'])
        PROVIDERS.trust_api.consume_use(trust_data['id'])
        # This was the last use, the trust isn't available anymore
        self.assertRaises(exception.TrustNotFound,
                          PROVIDERS.trust_api.get_trust,
                          trust_data['id'])

    def test_duplicate_trusts_not_allowed(self):
        self.trustor = self.user_foo
        self.trustee = self.user_two
        trust_data = {'trustor_user_id': self.trustor['id'],
                      'trustee_user_id': self.user_two['id'],
                      'project_id': self.project_bar['id'],
                      'expires_at': timeutils.parse_isotime(
                          '2032-02-18T18:10:00Z'),
                      'impersonation': True,
                      'remaining_uses': None}
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        PROVIDERS.trust_api.create_trust(uuid.uuid4().hex, trust_data, roles)
        self.assertRaises(exception.Conflict,
                          PROVIDERS.trust_api.create_trust,
                          uuid.uuid4().hex,
                          trust_data,
                          roles)

    def test_flush_expired_trusts(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        trust_ref2 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=1)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref2['id'], trusts[0]['id'])

    def test_flush_expired_trusts_with_all_id(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_foo['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        trust_ref2 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=5)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            project_id=self.project_bar['id'],
            trustor_user_id=self.user_foo['id'],
            trustee_user_id=self.user_two['id'],
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref1['id'], trusts[0]['id'])

    def test_flush_expired_trusts_with_no_project_id(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        trust_ref2 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=1)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            trustor_user_id=self.user_foo['id'],
            trustee_user_id=self.user_two['id'],
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref2['id'], trusts[0]['id'])

    def test_flush_expired_trusts_with_no_trustor_id(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        trust_ref2 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=1)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            project_id=self.project_bar['id'],
            trustee_user_id=self.user_two['id'],
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref2['id'], trusts[0]['id'])

    def test_flush_expired_trusts_with_no_trustee_id(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        trust_ref2 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=1)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            project_id=self.project_bar['id'],
            trustor_user_id=self.user_foo['id'],
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref2['id'], trusts[0]['id'])

    def test_flush_expired_trusts_with_project_id(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        trust_ref2 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.user_foo['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=5)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            project_id=self.project_bar['id'],
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref2['id'], trusts[0]['id'])

    def test_flush_expired_trusts_with_trustee_id(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        trust_ref2 = core.new_trust_ref(
            self.user_foo['id'], self.user_foo['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=5)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)
        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            trustee_user_id=self.user_two['id'],
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref2['id'], trusts[0]['id'])

    def test_flush_expired_trusts_with_trustor_id(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        trust_ref2 = core.new_trust_ref(
            self.user_two['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=5)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            trustor_user_id=self.user_foo['id'],
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref2['id'], trusts[0]['id'])

    def test_non_expired_soft_deleted_trusts(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=10)
        trust_ref2 = core.new_trust_ref(
            self.user_two['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=5)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)
        PROVIDERS.trust_api.delete_trust(trust_ref2['id'])

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref1['id'], trusts[0]['id'])

    def test_non_expired_non_deleted_trusts(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=10)
        trust_ref2 = core.new_trust_ref(
            self.user_two['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=5)
        trust_ref3 = core.new_trust_ref(
            self.user_two['id'], self.user_foo['id'],
            project_id=self.project_bar['id'])
        trust_ref3['expires_at'] = None

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)
        PROVIDERS.trust_api.delete_trust(trust_ref2['id'])
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref3['id'],
                                                      trust_ref3, roles)
        self.assertIsNotNone(trust_data)

        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            date=datetime.datetime.utcnow())
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 2)

    def test_flush_expired_trusts_with_date(self):
        roles = [{"id": "member"},
                 {"id": "other"},
                 {"id": "browser"}]
        trust_ref1 = core.new_trust_ref(
            self.user_foo['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref1['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=10)
        trust_ref2 = core.new_trust_ref(
            self.user_two['id'], self.user_two['id'],
            project_id=self.project_bar['id'])
        trust_ref2['expires_at'] = \
            timeutils.utcnow() + datetime.timedelta(minutes=30)
        trust_ref3 = core.new_trust_ref(
            self.user_two['id'], self.user_foo['id'],
            project_id=self.project_bar['id'])
        trust_ref3['expires_at'] = \
            timeutils.utcnow() - datetime.timedelta(minutes=30)

        trust_data = PROVIDERS.trust_api.create_trust(trust_ref1['id'],
                                                      trust_ref1, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref2['id'],
                                                      trust_ref2, roles)
        self.assertIsNotNone(trust_data)
        trust_data = PROVIDERS.trust_api.create_trust(trust_ref3['id'],
                                                      trust_ref3, roles)
        self.assertIsNotNone(trust_data)
        fake_date = timeutils.utcnow() + datetime.timedelta(minutes=15)
        PROVIDERS.trust_api.flush_expired_and_soft_deleted_trusts(
            date=fake_date
        )
        trusts = self.trust_api.list_trusts()
        self.assertEqual(len(trusts), 1)
        self.assertEqual(trust_ref2['id'], trusts[0]['id'])

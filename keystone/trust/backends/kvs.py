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
"""
An in memory implementation of the trusts API.
only to be used for testing purposes
"""
import copy

from keystone.common import kvs
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import trust


def _filter_trust(ref):
    if ref['deleted']:
        return None
    if ref.get('expires_at') and timeutils.utcnow() > ref['expires_at']:
        return None
    ref = copy.deepcopy(ref)
    return ref


class Trust(kvs.Base, trust.Driver):
    def create_trust(self, trust_id, trust, roles):
        trust_ref = trust
        trust_ref['id'] = trust_id
        trust_ref['deleted'] = False
        trust_ref['roles'] = roles
        if (trust_ref.get('expires_at') and
                trust_ref['expires_at'].tzinfo is not None):
                    trust_ref['expires_at'] = (timeutils.normalize_time
                                               (trust_ref['expires_at']))

        self.db.set('trust-%s' % trust_id, trust_ref)
        trustee_user_id = trust_ref['trustee_user_id']
        trustee_list = self.db.get('trustee-%s' % trustee_user_id, [])
        trustee_list.append(trust_id)
        self.db.set('trustee-%s' % trustee_user_id, trustee_list)
        trustor_user_id = trust_ref['trustor_user_id']
        trustor_list = self.db.get('trustor-%s' % trustor_user_id, [])
        trustor_list.append(trust_id)
        self.db.set('trustor-%s' % trustor_user_id, trustor_list)
        return copy.deepcopy(trust_ref)

    def get_trust(self, trust_id):
        try:
            ref = self.db.get('trust-%s' % trust_id)
            return _filter_trust(ref)
        except exception.NotFound:
            return None

    def delete_trust(self, trust_id):
        try:
            ref = self.db.get('trust-%s' % trust_id)
        except exception.NotFound:
            raise exception.TrustNotFound(trust_id=trust_id)
        ref['deleted'] = True
        self.db.set('trust-%s' % trust_id, ref)

    def list_trusts(self):
        trusts = []
        for key, value in self.db.items():
            if key.startswith("trust-") and not value['deleted']:
                trusts.append(value)
        return trusts

    def list_trusts_for_trustee(self, trustee_user_id):
        trusts = []
        for trust in self.db.get('trustee-%s' % trustee_user_id, []):
            trusts.append(self.get_trust(trust))
        return trusts

    def list_trusts_for_trustor(self, trustor_user_id):
        trusts = []
        for trust in self.db.get('trustor-%s' % trustor_user_id, []):
            trusts.append(self.get_trust(trust))
        return trusts

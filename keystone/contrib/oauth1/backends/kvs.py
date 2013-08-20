# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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

import datetime
import random
import uuid

from keystone.common import kvs
from keystone.contrib.oauth1 import core
from keystone import exception
from keystone.openstack.common import log as logging
from keystone.openstack.common import timeutils


LOG = logging.getLogger(__name__)


class OAuth1(kvs.Base):
    """kvs backend for oauth is deprecated.
    Deprecated in Havana and will be removed in Icehouse, as this backend
    is not production grade.
    """

    def __init__(self, *args, **kw):
        super(OAuth1, self).__init__(*args, **kw)
        LOG.warn(_("kvs token backend is DEPRECATED. Use "
                   "keystone.contrib.oauth1.sql instead."))

    def _get_consumer(self, consumer_id):
        return self.db.get('consumer-%s' % consumer_id)

    def get_consumer(self, consumer_id):
        consumer_ref = self.db.get('consumer-%s' % consumer_id)
        return core.filter_consumer(consumer_ref)

    def create_consumer(self, consumer):
        consumer_id = consumer['id']
        consumer['secret'] = uuid.uuid4().hex
        if not consumer.get('description'):
            consumer['description'] = None
        self.db.set('consumer-%s' % consumer_id, consumer)
        consumer_list = set(self.db.get('consumer_list', []))
        consumer_list.add(consumer_id)
        self.db.set('consumer_list', list(consumer_list))
        return consumer

    def _delete_consumer(self, consumer_id):
        # call get to make sure it exists
        self.db.get('consumer-%s' % consumer_id)
        self.db.delete('consumer-%s' % consumer_id)
        consumer_list = set(self.db.get('consumer_list', []))
        consumer_list.remove(consumer_id)
        self.db.set('consumer_list', list(consumer_list))

    def _delete_request_tokens(self, consumer_id):
        consumer_requests = set(self.db.get('consumer-%s-requests' %
                                            consumer_id, []))
        for token in consumer_requests:
            self.db.get('request_token-%s' % token)
            self.db.delete('request_token-%s' % token)

        if len(consumer_requests) > 0:
            self.db.delete('consumer-%s-requests' % consumer_id)

    def _delete_access_tokens(self, consumer_id):
        consumer_accesses = set(self.db.get('consumer-%s-accesses' %
                                            consumer_id, []))
        for token in consumer_accesses:
            access_token = self.db.get('access_token-%s' % token)
            self.db.delete('access_token-%s' % token)

            # kind of a hack, but I needed to update the auth_list
            user_id = access_token['authorizing_user_id']
            user_auth_list = set(self.db.get('auth_list-%s' % user_id, []))
            user_auth_list.remove(token)
            self.db.set('auth_list-%s' % user_id, list(user_auth_list))

        if len(consumer_accesses) > 0:
            self.db.delete('consumer-%s-accesses' % consumer_id)

    def delete_consumer(self, consumer_id):
        self._delete_consumer(consumer_id)
        self._delete_request_tokens(consumer_id)
        self._delete_access_tokens(consumer_id)

    def list_consumers(self):
        consumer_ids = self.db.get('consumer_list', [])
        return [self.get_consumer(x) for x in consumer_ids]

    def update_consumer(self, consumer_id, consumer):
        # call get to make sure it exists
        old_consumer_ref = self.db.get('consumer-%s' % consumer_id)
        new_consumer_ref = old_consumer_ref.copy()
        new_consumer_ref['description'] = consumer['description']
        new_consumer_ref['id'] = consumer_id
        self.db.set('consumer-%s' % consumer_id, new_consumer_ref)
        return new_consumer_ref

    def create_request_token(self, consumer_id, roles,
                             project_id, token_duration):
        expiry_date = None
        if token_duration:
            now = timeutils.utcnow()
            future = now + datetime.timedelta(seconds=token_duration)
            expiry_date = timeutils.isotime(future, subsecond=True)

        ref = {}
        request_token_id = uuid.uuid4().hex
        ref['id'] = request_token_id
        ref['request_secret'] = uuid.uuid4().hex
        ref['verifier'] = None
        ref['authorizing_user_id'] = None
        ref['requested_project_id'] = project_id
        ref['requested_roles'] = roles
        ref['consumer_id'] = consumer_id
        ref['expires_at'] = expiry_date
        self.db.set('request_token-%s' % request_token_id, ref)

        # add req token to the list that containers the consumers req tokens
        consumer_requests = set(self.db.get('consumer-%s-requests' %
                                            consumer_id, []))
        consumer_requests.add(request_token_id)
        self.db.set('consumer-%s-requests' %
                    consumer_id, list(consumer_requests))
        return ref

    def get_request_token(self, request_token_id):
        return self.db.get('request_token-%s' % request_token_id)

    def authorize_request_token(self, request_token_id, user_id):
        request_token = self.db.get('request_token-%s' % request_token_id)
        request_token['authorizing_user_id'] = user_id
        request_token['verifier'] = str(random.randint(1000, 9999))
        self.db.set('request_token-%s' % request_token_id, request_token)
        return request_token

    def create_access_token(self, request_id, token_duration):
        request_token = self.db.get('request_token-%s' % request_id)

        expiry_date = None
        if token_duration:
            now = timeutils.utcnow()
            future = now + datetime.timedelta(seconds=token_duration)
            expiry_date = timeutils.isotime(future, subsecond=True)

        ref = {}
        access_token_id = uuid.uuid4().hex
        ref['id'] = access_token_id
        ref['access_secret'] = uuid.uuid4().hex
        ref['authorizing_user_id'] = request_token['authorizing_user_id']
        ref['project_id'] = request_token['requested_project_id']
        ref['requested_roles'] = request_token['requested_roles']
        ref['consumer_id'] = request_token['consumer_id']
        ref['expires_at'] = expiry_date
        self.db.set('access_token-%s' % access_token_id, ref)

        #add access token id to user authorizations list too
        user_id = request_token['authorizing_user_id']
        user_auth_list = set(self.db.get('auth_list-%s' % user_id, []))
        user_auth_list.add(access_token_id)
        self.db.set('auth_list-%s' % user_id, list(user_auth_list))

        #delete request token from table, it has been exchanged
        self.db.get('request_token-%s' % request_id)
        self.db.delete('request_token-%s' % request_id)

        #add access token to the list that containers the consumers acc tokens
        consumer_id = request_token['consumer_id']
        consumer_accesses = set(self.db.get('consumer-%s-accesses' %
                                            consumer_id, []))
        consumer_accesses.add(access_token_id)
        self.db.set('consumer-%s-accesses' %
                    consumer_id, list(consumer_accesses))

        # remove the used up request token id from consumer req list
        consumer_requests = set(self.db.get('consumer-%s-requests' %
                                            consumer_id, []))
        consumer_requests.remove(request_id)
        self.db.set('consumer-%s-requests' %
                    consumer_id, list(consumer_requests))

        return ref

    def get_access_token(self, access_token_id):
        return self.db.get('access_token-%s' % access_token_id)

    def list_access_tokens(self, user_id):
        user_auth_list = self.db.get('auth_list-%s' % user_id, [])
        return [self.get_access_token(x) for x in user_auth_list]

    def delete_access_token(self, user_id, access_token_id):
        access_token = self.get_access_token(access_token_id)
        consumer_id = access_token['consumer_id']
        if access_token['authorizing_user_id'] != user_id:
            raise exception.Unauthorized(_('User IDs do not match'))
        self.db.get('access_token-%s' % access_token_id)
        self.db.delete('access_token-%s' % access_token_id)

        # remove access token id from user authz list
        user_auth_list = set(self.db.get('auth_list-%s' % user_id, []))
        user_auth_list.remove(access_token_id)
        self.db.set('auth_list-%s' % user_id, list(user_auth_list))

        # remove this token id from the consumer access list
        consumer_accesses = set(self.db.get('consumer-%s-accesses' %
                                            consumer_id, []))
        consumer_accesses.remove(access_token_id)
        self.db.set('consumer-%s-accesses' %
                    consumer_id, list(consumer_accesses))

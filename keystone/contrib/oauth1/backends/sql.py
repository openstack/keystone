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

from keystone.common import sql
from keystone.common.sql import migration
from keystone.contrib.oauth1 import core
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone.openstack.common import timeutils


class Consumer(sql.ModelBase, sql.DictBase):
    __tablename__ = 'consumer'
    attributes = ['id', 'description', 'secret']
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    description = sql.Column(sql.String(64), nullable=True)
    secret = sql.Column(sql.String(64), nullable=False)
    extra = sql.Column(sql.JsonBlob(), nullable=False)


class RequestToken(sql.ModelBase, sql.DictBase):
    __tablename__ = 'request_token'
    attributes = ['id', 'request_secret',
                  'verifier', 'authorizing_user_id', 'requested_project_id',
                  'role_ids', 'consumer_id', 'expires_at']
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    request_secret = sql.Column(sql.String(64), nullable=False)
    verifier = sql.Column(sql.String(64), nullable=True)
    authorizing_user_id = sql.Column(sql.String(64), nullable=True)
    requested_project_id = sql.Column(sql.String(64), nullable=False)
    role_ids = sql.Column(sql.Text(), nullable=True)
    consumer_id = sql.Column(sql.String(64), sql.ForeignKey('consumer.id'),
                             nullable=False, index=True)
    expires_at = sql.Column(sql.String(64), nullable=True)

    @classmethod
    def from_dict(cls, user_dict):
        return cls(**user_dict)

    def to_dict(self):
        return dict(self.iteritems())


class AccessToken(sql.ModelBase, sql.DictBase):
    __tablename__ = 'access_token'
    attributes = ['id', 'access_secret', 'authorizing_user_id',
                  'project_id', 'role_ids', 'consumer_id',
                  'expires_at']
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    access_secret = sql.Column(sql.String(64), nullable=False)
    authorizing_user_id = sql.Column(sql.String(64), nullable=False,
                                     index=True)
    project_id = sql.Column(sql.String(64), nullable=False)
    role_ids = sql.Column(sql.Text(), nullable=False)
    consumer_id = sql.Column(sql.String(64), sql.ForeignKey('consumer.id'),
                             nullable=False)
    expires_at = sql.Column(sql.String(64), nullable=True)

    @classmethod
    def from_dict(cls, user_dict):
        return cls(**user_dict)

    def to_dict(self):
        return dict(self.iteritems())


class OAuth1(sql.Base):
    def db_sync(self):
        migration.db_sync()

    def _get_consumer(self, session, consumer_id):
        consumer_ref = session.query(Consumer).get(consumer_id)
        if consumer_ref is None:
            raise exception.NotFound(_('Consumer not found'))
        return consumer_ref

    def get_consumer_with_secret(self, consumer_id):
        session = self.get_session()
        consumer_ref = self._get_consumer(session, consumer_id)
        return consumer_ref.to_dict()

    def get_consumer(self, consumer_id):
        return core.filter_consumer(
            self.get_consumer_with_secret(consumer_id))

    def create_consumer(self, consumer):
        consumer['secret'] = uuid.uuid4().hex
        if not consumer.get('description'):
            consumer['description'] = None
        session = self.get_session()
        with session.begin():
            consumer_ref = Consumer.from_dict(consumer)
            session.add(consumer_ref)
            session.flush()
        return consumer_ref.to_dict()

    def _delete_consumer(self, session, consumer_id):
        consumer_ref = self._get_consumer(session, consumer_id)
        q = session.query(Consumer)
        q = q.filter_by(id=consumer_id)
        q.delete(False)
        session.delete(consumer_ref)

    def _delete_request_tokens(self, session, consumer_id):
        q = session.query(RequestToken)
        req_tokens = q.filter_by(consumer_id=consumer_id)
        req_tokens_list = set([x.id for x in req_tokens])
        for token_id in req_tokens_list:
            token_ref = self._get_request_token(session, token_id)
            q = session.query(RequestToken)
            q = q.filter_by(id=token_id)
            q.delete(False)
            session.delete(token_ref)

    def _delete_access_tokens(self, session, consumer_id):
        q = session.query(AccessToken)
        acc_tokens = q.filter_by(consumer_id=consumer_id)
        acc_tokens_list = set([x.id for x in acc_tokens])
        for token_id in acc_tokens_list:
            token_ref = self._get_access_token(session, token_id)
            q = session.query(AccessToken)
            q = q.filter_by(id=token_id)
            q.delete(False)
            session.delete(token_ref)

    def delete_consumer(self, consumer_id):
        session = self.get_session()
        with session.begin():
            self._delete_request_tokens(session, consumer_id)
            self._delete_access_tokens(session, consumer_id)
            self._delete_consumer(session, consumer_id)
            session.flush()

    def list_consumers(self):
        session = self.get_session()
        cons = session.query(Consumer)
        return [core.filter_consumer(x.to_dict()) for x in cons]

    def update_consumer(self, consumer_id, consumer):
        session = self.get_session()
        with session.begin():
            consumer_ref = self._get_consumer(session, consumer_id)
            old_consumer_dict = consumer_ref.to_dict()
            old_consumer_dict.update(consumer)
            new_consumer = Consumer.from_dict(old_consumer_dict)
            consumer_ref.description = new_consumer.description
            consumer_ref.extra = new_consumer.extra
            session.flush()
        return core.filter_consumer(consumer_ref.to_dict())

    def create_request_token(self, consumer_id, project_id, token_duration):
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
        ref['role_ids'] = None
        ref['consumer_id'] = consumer_id
        ref['expires_at'] = expiry_date
        session = self.get_session()
        with session.begin():
            token_ref = RequestToken.from_dict(ref)
            session.add(token_ref)
            session.flush()
        return token_ref.to_dict()

    def _get_request_token(self, session, request_token_id):
        token_ref = session.query(RequestToken).get(request_token_id)
        if token_ref is None:
            raise exception.NotFound(_('Request token not found'))
        return token_ref

    def get_request_token(self, request_token_id):
        session = self.get_session()
        token_ref = self._get_request_token(session, request_token_id)
        return token_ref.to_dict()

    def authorize_request_token(self, request_token_id, user_id,
                                role_ids):
        session = self.get_session()
        with session.begin():
            token_ref = self._get_request_token(session, request_token_id)
            token_dict = token_ref.to_dict()
            token_dict['authorizing_user_id'] = user_id
            token_dict['verifier'] = str(random.randint(1000, 9999))
            token_dict['role_ids'] = jsonutils.dumps(role_ids)

            new_token = RequestToken.from_dict(token_dict)
            for attr in RequestToken.attributes:
                if (attr == 'authorizing_user_id' or attr == 'verifier'
                        or attr == 'role_ids'):
                    setattr(token_ref, attr, getattr(new_token, attr))

            session.flush()
        return token_ref.to_dict()

    def create_access_token(self, request_token_id, token_duration):
        session = self.get_session()
        with session.begin():
            req_token_ref = self._get_request_token(session, request_token_id)
            token_dict = req_token_ref.to_dict()

            expiry_date = None
            if token_duration:
                now = timeutils.utcnow()
                future = now + datetime.timedelta(seconds=token_duration)
                expiry_date = timeutils.isotime(future, subsecond=True)

            # add Access Token
            ref = {}
            access_token_id = uuid.uuid4().hex
            ref['id'] = access_token_id
            ref['access_secret'] = uuid.uuid4().hex
            ref['authorizing_user_id'] = token_dict['authorizing_user_id']
            ref['project_id'] = token_dict['requested_project_id']
            ref['role_ids'] = token_dict['role_ids']
            ref['consumer_id'] = token_dict['consumer_id']
            ref['expires_at'] = expiry_date
            token_ref = AccessToken.from_dict(ref)
            session.add(token_ref)

            # remove request token, it's been used
            q = session.query(RequestToken)
            q = q.filter_by(id=request_token_id)
            q.delete(False)
            session.delete(req_token_ref)

            session.flush()
        return token_ref.to_dict()

    def _get_access_token(self, session, access_token_id):
        token_ref = session.query(AccessToken).get(access_token_id)
        if token_ref is None:
            raise exception.NotFound(_('Access token not found'))
        return token_ref

    def get_access_token(self, access_token_id):
        session = self.get_session()
        token_ref = self._get_access_token(session, access_token_id)
        return token_ref.to_dict()

    def list_access_tokens(self, user_id):
        session = self.get_session()
        q = session.query(AccessToken)
        user_auths = q.filter_by(authorizing_user_id=user_id)
        return [core.filter_token(x.to_dict()) for x in user_auths]

    def delete_access_token(self, user_id, access_token_id):
        session = self.get_session()
        with session.begin():
            token_ref = self._get_access_token(session, access_token_id)
            token_dict = token_ref.to_dict()
            if token_dict['authorizing_user_id'] != user_id:
                raise exception.Unauthorized(_('User IDs do not match'))

            q = session.query(AccessToken)
            q = q.filter_by(id=access_token_id)
            q.delete(False)

            session.delete(token_ref)
            session.flush()

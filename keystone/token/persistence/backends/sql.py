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

import copy
import functools

from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils

from keystone.common import sql
from keystone import exception
from keystone.i18n import _LI
from keystone import token
from keystone.token import provider


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class TokenModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'token'
    attributes = ['id', 'expires', 'user_id', 'trust_id']
    id = sql.Column(sql.String(64), primary_key=True)
    expires = sql.Column(sql.DateTime(), default=None)
    extra = sql.Column(sql.JsonBlob())
    valid = sql.Column(sql.Boolean(), default=True, nullable=False)
    user_id = sql.Column(sql.String(64))
    trust_id = sql.Column(sql.String(64))
    __table_args__ = (
        sql.Index('ix_token_expires', 'expires'),
        sql.Index('ix_token_expires_valid', 'expires', 'valid'),
        sql.Index('ix_token_user_id', 'user_id'),
        sql.Index('ix_token_trust_id', 'trust_id')
    )


def _expiry_range_batched(session, upper_bound_func, batch_size):
    """Returns the stop point of the next batch for expiration.

    Return the timestamp of the next token that is `batch_size` rows from
    being the oldest expired token.
    """

    # This expiry strategy splits the tokens into roughly equal sized batches
    # to be deleted.  It does this by finding the timestamp of a token
    # `batch_size` rows from the oldest token and yielding that to the caller.
    # It's expected that the caller will then delete all rows with a timestamp
    # equal to or older than the one yielded.  This may delete slightly more
    # tokens than the batch_size, but that should be ok in almost all cases.
    LOG.debug('Token expiration batch size: %d', batch_size)
    query = session.query(TokenModel.expires)
    query = query.filter(TokenModel.expires < upper_bound_func())
    query = query.order_by(TokenModel.expires)
    query = query.offset(batch_size - 1)
    query = query.limit(1)
    while True:
        try:
            next_expiration = query.one()[0]
        except sql.NotFound:
            # There are less than `batch_size` rows remaining, so fall
            # through to the normal delete
            break
        yield next_expiration
    yield upper_bound_func()


def _expiry_range_all(session, upper_bound_func):
    """Expires all tokens in one pass."""

    yield upper_bound_func()


class Token(token.persistence.TokenDriverV8):
    # Public interface
    def get_token(self, token_id):
        if token_id is None:
            raise exception.TokenNotFound(token_id=token_id)
        session = sql.get_session()
        token_ref = session.query(TokenModel).get(token_id)
        if not token_ref or not token_ref.valid:
            raise exception.TokenNotFound(token_id=token_id)
        return token_ref.to_dict()

    def create_token(self, token_id, data):
        data_copy = copy.deepcopy(data)
        if not data_copy.get('expires'):
            data_copy['expires'] = provider.default_expire_time()
        if not data_copy.get('user_id'):
            data_copy['user_id'] = data_copy['user']['id']

        token_ref = TokenModel.from_dict(data_copy)
        token_ref.valid = True
        session = sql.get_session()
        with session.begin():
            session.add(token_ref)
        return token_ref.to_dict()

    def delete_token(self, token_id):
        session = sql.get_session()
        with session.begin():
            token_ref = session.query(TokenModel).get(token_id)
            if not token_ref or not token_ref.valid:
                raise exception.TokenNotFound(token_id=token_id)
            token_ref.valid = False

    def delete_tokens(self, user_id, tenant_id=None, trust_id=None,
                      consumer_id=None):
        """Deletes all tokens in one session

        The user_id will be ignored if the trust_id is specified. user_id
        will always be specified.
        If using a trust, the token's user_id is set to the trustee's user ID
        or the trustor's user ID, so will use trust_id to query the tokens.

        """
        session = sql.get_session()
        token_list = []
        with session.begin():
            now = timeutils.utcnow()
            query = session.query(TokenModel)
            query = query.filter_by(valid=True)
            query = query.filter(TokenModel.expires > now)
            if trust_id:
                query = query.filter(TokenModel.trust_id == trust_id)
            else:
                query = query.filter(TokenModel.user_id == user_id)

            for token_ref in query.all():
                if tenant_id:
                    token_ref_dict = token_ref.to_dict()
                    if not self._tenant_matches(tenant_id, token_ref_dict):
                        continue
                if consumer_id:
                    token_ref_dict = token_ref.to_dict()
                    if not self._consumer_matches(consumer_id, token_ref_dict):
                        continue

                token_ref.valid = False
                token_list.append(token_ref.id)

        return token_list

    def _tenant_matches(self, tenant_id, token_ref_dict):
        return ((tenant_id is None) or
                (token_ref_dict.get('tenant') and
                 token_ref_dict['tenant'].get('id') == tenant_id))

    def _consumer_matches(self, consumer_id, ref):
        if consumer_id is None:
            return True
        else:
            try:
                oauth = ref['token_data']['token'].get('OS-OAUTH1', {})
                return oauth and oauth['consumer_id'] == consumer_id
            except KeyError:
                return False

    def _list_tokens_for_trust(self, trust_id):
        session = sql.get_session()
        tokens = []
        now = timeutils.utcnow()
        query = session.query(TokenModel)
        query = query.filter(TokenModel.expires > now)
        query = query.filter(TokenModel.trust_id == trust_id)

        token_references = query.filter_by(valid=True)
        for token_ref in token_references:
            token_ref_dict = token_ref.to_dict()
            tokens.append(token_ref_dict['id'])
        return tokens

    def _list_tokens_for_user(self, user_id, tenant_id=None):
        session = sql.get_session()
        tokens = []
        now = timeutils.utcnow()
        query = session.query(TokenModel)
        query = query.filter(TokenModel.expires > now)
        query = query.filter(TokenModel.user_id == user_id)

        token_references = query.filter_by(valid=True)
        for token_ref in token_references:
            token_ref_dict = token_ref.to_dict()
            if self._tenant_matches(tenant_id, token_ref_dict):
                tokens.append(token_ref['id'])
        return tokens

    def _list_tokens_for_consumer(self, user_id, consumer_id):
        tokens = []
        session = sql.get_session()
        with session.begin():
            now = timeutils.utcnow()
            query = session.query(TokenModel)
            query = query.filter(TokenModel.expires > now)
            query = query.filter(TokenModel.user_id == user_id)
            token_references = query.filter_by(valid=True)

            for token_ref in token_references:
                token_ref_dict = token_ref.to_dict()
                if self._consumer_matches(consumer_id, token_ref_dict):
                    tokens.append(token_ref_dict['id'])
        return tokens

    def _list_tokens(self, user_id, tenant_id=None, trust_id=None,
                     consumer_id=None):
        if not CONF.token.revoke_by_id:
            return []
        if trust_id:
            return self._list_tokens_for_trust(trust_id)
        if consumer_id:
            return self._list_tokens_for_consumer(user_id, consumer_id)
        else:
            return self._list_tokens_for_user(user_id, tenant_id)

    def list_revoked_tokens(self):
        session = sql.get_session()
        tokens = []
        now = timeutils.utcnow()
        query = session.query(TokenModel.id, TokenModel.expires)
        query = query.filter(TokenModel.expires > now)
        token_references = query.filter_by(valid=False)
        for token_ref in token_references:
            record = {
                'id': token_ref[0],
                'expires': token_ref[1],
            }
            tokens.append(record)
        return tokens

    def _expiry_range_strategy(self, dialect):
        """Choose a token range expiration strategy

        Based on the DB dialect, select an expiry range callable that is
        appropriate.
        """

        # DB2 and MySQL can both benefit from a batched strategy.  On DB2 the
        # transaction log can fill up and on MySQL w/Galera, large
        # transactions can exceed the maximum write set size.
        if dialect == 'ibm_db_sa':
            # Limit of 100 is known to not fill a transaction log
            # of default maximum size while not significantly
            # impacting the performance of large token purges on
            # systems where the maximum transaction log size has
            # been increased beyond the default.
            return functools.partial(_expiry_range_batched,
                                     batch_size=100)
        elif dialect == 'mysql':
            # We want somewhat more than 100, since Galera replication delay is
            # at least RTT*2.  This can be a significant amount of time if
            # doing replication across a WAN.
            return functools.partial(_expiry_range_batched,
                                     batch_size=1000)
        return _expiry_range_all

    def flush_expired_tokens(self):
        session = sql.get_session()
        dialect = session.bind.dialect.name
        expiry_range_func = self._expiry_range_strategy(dialect)
        query = session.query(TokenModel.expires)
        total_removed = 0
        upper_bound_func = timeutils.utcnow
        for expiry_time in expiry_range_func(session, upper_bound_func):
            delete_query = query.filter(TokenModel.expires <=
                                        expiry_time)
            row_count = delete_query.delete(synchronize_session=False)
            total_removed += row_count
            LOG.debug('Removed %d total expired tokens', total_removed)

        session.flush()
        LOG.info(_LI('Total expired tokens removed: %d'), total_removed)

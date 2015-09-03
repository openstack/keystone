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

from keystone.common import sql
from keystone.contrib import revoke
from keystone.contrib.revoke import model


class RevocationEvent(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'revocation_event'
    attributes = model.REVOKE_KEYS

    # The id field is not going to be exposed to the outside world.
    # It is, however, necessary for SQLAlchemy.
    id = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64))
    project_id = sql.Column(sql.String(64))
    user_id = sql.Column(sql.String(64))
    role_id = sql.Column(sql.String(64))
    trust_id = sql.Column(sql.String(64))
    consumer_id = sql.Column(sql.String(64))
    access_token_id = sql.Column(sql.String(64))
    issued_before = sql.Column(sql.DateTime(), nullable=False)
    expires_at = sql.Column(sql.DateTime())
    revoked_at = sql.Column(sql.DateTime(), nullable=False, index=True)
    audit_id = sql.Column(sql.String(32))
    audit_chain_id = sql.Column(sql.String(32))


class Revoke(revoke.RevokeDriverV8):
    def _flush_batch_size(self, dialect):
        batch_size = 0
        if dialect == 'ibm_db_sa':
            # This functionality is limited to DB2, because
            # it is necessary to prevent the transaction log
            # from filling up, whereas at least some of the
            # other supported databases do not support update
            # queries with LIMIT subqueries nor do they appear
            # to require the use of such queries when deleting
            # large numbers of records at once.
            batch_size = 100
            # Limit of 100 is known to not fill a transaction log
            # of default maximum size while not significantly
            # impacting the performance of large token purges on
            # systems where the maximum transaction log size has
            # been increased beyond the default.
        return batch_size

    def _prune_expired_events(self):
        oldest = revoke.revoked_before_cutoff_time()

        session = sql.get_session()
        dialect = session.bind.dialect.name
        batch_size = self._flush_batch_size(dialect)
        if batch_size > 0:
            query = session.query(RevocationEvent.id)
            query = query.filter(RevocationEvent.revoked_at < oldest)
            query = query.limit(batch_size).subquery()
            delete_query = (session.query(RevocationEvent).
                            filter(RevocationEvent.id.in_(query)))
            while True:
                rowcount = delete_query.delete(synchronize_session=False)
                if rowcount == 0:
                    break
        else:
            query = session.query(RevocationEvent)
            query = query.filter(RevocationEvent.revoked_at < oldest)
            query.delete(synchronize_session=False)

        session.flush()

    def list_events(self, last_fetch=None):
        session = sql.get_session()
        query = session.query(RevocationEvent).order_by(
            RevocationEvent.revoked_at)

        if last_fetch:
            query = query.filter(RevocationEvent.revoked_at > last_fetch)

        events = [model.RevokeEvent(**e.to_dict()) for e in query]

        return events

    def revoke(self, event):
        kwargs = dict()
        for attr in model.REVOKE_KEYS:
            kwargs[attr] = getattr(event, attr)
        kwargs['id'] = uuid.uuid4().hex
        record = RevocationEvent(**kwargs)
        session = sql.get_session()
        with session.begin():
            session.add(record)
        self._prune_expired_events()

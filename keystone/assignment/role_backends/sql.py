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
from oslo_db import exception as db_exception

from keystone.assignment.role_backends import base
from keystone.assignment.role_backends import sql_model
from keystone.common import driver_hints
from keystone.common import resource_options
from keystone.common import sql
from keystone import exception


class Role(base.RoleDriverBase):

    @sql.handle_conflicts(conflict_type='role')
    def create_role(self, role_id, role):
        with sql.session_for_write() as session:
            ref = sql_model.RoleTable.from_dict(role)
            session.add(ref)
            # Set resource options passed on creation
            resource_options.resource_options_ref_to_mapper(
                ref, sql_model.RoleOption
            )
            return ref.to_dict()

    @driver_hints.truncated
    def list_roles(self, hints):
        # If there is a filter on domain_id and the value is None, then to
        # ensure that the sql filtering works correctly, we need to patch
        # the value to be NULL_DOMAIN_ID. This is safe to do here since we
        # know we are able to satisfy any filter of this type in the call to
        # filter_limit_query() below, which will remove the filter from the
        # hints (hence ensuring our substitution is not exposed to the caller).
        for f in hints.filters:
            if (f['name'] == 'domain_id' and f['value'] is None):
                f['value'] = base.NULL_DOMAIN_ID

        with sql.session_for_read() as session:
            query = session.query(sql_model.RoleTable)
            refs = sql.filter_limit_query(sql_model.RoleTable, query, hints)
            return [ref.to_dict() for ref in refs]

    def list_roles_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.session_for_read() as session:
                query = session.query(sql_model.RoleTable)
                query = query.filter(sql_model.RoleTable.id.in_(ids))
                role_refs = query.all()
                return [role_ref.to_dict() for role_ref in role_refs]

    def _get_role(self, session, role_id):
        ref = session.query(sql_model.RoleTable).get(role_id)
        if ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        return ref

    def get_role(self, role_id):
        with sql.session_for_read() as session:
            return self._get_role(session, role_id).to_dict()

    @sql.handle_conflicts(conflict_type='role')
    def update_role(self, role_id, role):
        with sql.session_for_write() as session:
            ref = self._get_role(session, role_id)
            old_dict = ref.to_dict()
            for k in role:
                old_dict[k] = role[k]
            new_role = sql_model.RoleTable.from_dict(old_dict)
            for attr in sql_model.RoleTable.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_role, attr))
            ref.extra = new_role.extra
            ref.description = new_role.description
            # Move the "_resource_options" attribute over to the real ref
            # so that resource_options.resource_options_ref_to_mapper can
            # handle the work.
            setattr(ref, '_resource_options',
                    getattr(new_role, '_resource_options', {}))
            # Move options into the propper attribute mapper construct
            resource_options.resource_options_ref_to_mapper(
                ref, sql_model.RoleOption)
            return ref.to_dict()

    def delete_role(self, role_id):
        with sql.session_for_write() as session:
            ref = self._get_role(session, role_id)
            session.delete(ref)

    def _get_implied_role(self, session, prior_role_id, implied_role_id):
        query = session.query(sql_model.ImpliedRoleTable).filter(
            sql_model.ImpliedRoleTable.prior_role_id == prior_role_id).filter(
            sql_model.ImpliedRoleTable.implied_role_id == implied_role_id)
        try:
            ref = query.one()
        except sql.NotFound:
            raise exception.ImpliedRoleNotFound(
                prior_role_id=prior_role_id,
                implied_role_id=implied_role_id)
        return ref

    @sql.handle_conflicts(conflict_type='implied_role')
    def create_implied_role(self, prior_role_id, implied_role_id):
        with sql.session_for_write() as session:
            inference = {'prior_role_id': prior_role_id,
                         'implied_role_id': implied_role_id}
            ref = sql_model.ImpliedRoleTable.from_dict(inference)
            try:
                session.add(ref)
            except db_exception.DBReferenceError:
                # We don't know which role threw this.
                # Query each to trigger the exception.
                self._get_role(session, prior_role_id)
                self._get_role(session, implied_role_id)
            return ref.to_dict()

    def delete_implied_role(self, prior_role_id, implied_role_id):
        with sql.session_for_write() as session:
            ref = self._get_implied_role(session, prior_role_id,
                                         implied_role_id)
            session.delete(ref)

    def list_implied_roles(self, prior_role_id):
        with sql.session_for_read() as session:
            query = session.query(
                sql_model.ImpliedRoleTable).filter(
                    sql_model.ImpliedRoleTable.prior_role_id == prior_role_id)
            refs = query.all()
            return [ref.to_dict() for ref in refs]

    def list_role_inference_rules(self):
        with sql.session_for_read() as session:
            query = session.query(sql_model.ImpliedRoleTable)
            refs = query.all()
            return [ref.to_dict() for ref in refs]

    def get_implied_role(self, prior_role_id, implied_role_id):
        with sql.session_for_read() as session:
            ref = self._get_implied_role(session, prior_role_id,
                                         implied_role_id)
            return ref.to_dict()

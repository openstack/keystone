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

from keystone.common import sql
from keystone.common.sql import migration
from keystone import exception


class ProjectEndpoint(sql.ModelBase, sql.DictBase):
    """project-endpoint relationship table."""
    __tablename__ = 'project_endpoint'
    attributes = ['endpoint_id', 'project_id']
    endpoint_id = sql.Column(sql.String(64),
                             primary_key=True,
                             nullable=False)
    project_id = sql.Column(sql.String(64),
                            primary_key=True,
                            nullable=False)


class EndpointFilter(sql.Base):
    # Internal interface to manage the database

    def db_sync(self, version=None):
        migration.db_sync(version=version)

    @sql.handle_conflicts(type='project_endpoint')
    def add_endpoint_to_project(self, endpoint_id, project_id):
        session = self.get_session()
        with session.begin():
            endpoint_filter_ref = ProjectEndpoint(endpoint_id=endpoint_id,
                                                  project_id=project_id)
            session.add(endpoint_filter_ref)
            session.flush()

    def _get_project_endpoint_ref(self, session, endpoint_id, project_id):
        endpoint_filter_ref = session.query(ProjectEndpoint).get(
            (endpoint_id, project_id))
        if endpoint_filter_ref is None:
            msg = _('Endpoint %(endpoint_id)s not found in project '
                    '%(project_id)s') % {'endpoint_id': endpoint_id,
                                         'project_id': project_id}
            raise exception.NotFound(msg)
        return endpoint_filter_ref

    def check_endpoint_in_project(self, endpoint_id, project_id):
        session = self.get_session()
        self._get_project_endpoint_ref(session, endpoint_id, project_id)

    def remove_endpoint_from_project(self, endpoint_id, project_id):
        session = self.get_session()
        endpoint_filter_ref = self._get_project_endpoint_ref(
            session, endpoint_id, project_id)
        with session.begin():
            session.delete(endpoint_filter_ref)
            session.flush()

    def list_endpoints_for_project(self, project_id):
        session = self.get_session()
        query = session.query(ProjectEndpoint)
        query = query.filter_by(project_id=project_id)
        endpoint_filter_refs = query.all()
        return endpoint_filter_refs

    def list_projects_for_endpoint(self, endpoint_id):
        session = self.get_session()
        query = session.query(ProjectEndpoint)
        query = query.filter_by(endpoint_id=endpoint_id)
        endpoint_filter_refs = query.all()
        return endpoint_filter_refs

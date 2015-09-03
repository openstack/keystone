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
from keystone.contrib import endpoint_filter
from keystone import exception
from keystone.i18n import _


class ProjectEndpoint(sql.ModelBase, sql.ModelDictMixin):
    """project-endpoint relationship table."""
    __tablename__ = 'project_endpoint'
    attributes = ['endpoint_id', 'project_id']
    endpoint_id = sql.Column(sql.String(64),
                             primary_key=True,
                             nullable=False)
    project_id = sql.Column(sql.String(64),
                            primary_key=True,
                            nullable=False)


class EndpointGroup(sql.ModelBase, sql.ModelDictMixin):
    """Endpoint Groups table."""
    __tablename__ = 'endpoint_group'
    attributes = ['id', 'name', 'description', 'filters']
    mutable_attributes = frozenset(['name', 'description', 'filters'])
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    description = sql.Column(sql.Text, nullable=True)
    filters = sql.Column(sql.JsonBlob(), nullable=False)


class ProjectEndpointGroupMembership(sql.ModelBase, sql.ModelDictMixin):
    """Project to Endpoint group relationship table."""
    __tablename__ = 'project_endpoint_group'
    attributes = ['endpoint_group_id', 'project_id']
    endpoint_group_id = sql.Column(sql.String(64),
                                   sql.ForeignKey('endpoint_group.id'),
                                   nullable=False)
    project_id = sql.Column(sql.String(64), nullable=False)
    __table_args__ = (sql.PrimaryKeyConstraint('endpoint_group_id',
                                               'project_id'), {})


class EndpointFilter(endpoint_filter.EndpointFilterDriverV8):

    @sql.handle_conflicts(conflict_type='project_endpoint')
    def add_endpoint_to_project(self, endpoint_id, project_id):
        session = sql.get_session()
        with session.begin():
            endpoint_filter_ref = ProjectEndpoint(endpoint_id=endpoint_id,
                                                  project_id=project_id)
            session.add(endpoint_filter_ref)

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
        session = sql.get_session()
        self._get_project_endpoint_ref(session, endpoint_id, project_id)

    def remove_endpoint_from_project(self, endpoint_id, project_id):
        session = sql.get_session()
        endpoint_filter_ref = self._get_project_endpoint_ref(
            session, endpoint_id, project_id)
        with session.begin():
            session.delete(endpoint_filter_ref)

    def list_endpoints_for_project(self, project_id):
        session = sql.get_session()
        query = session.query(ProjectEndpoint)
        query = query.filter_by(project_id=project_id)
        endpoint_filter_refs = query.all()
        return [ref.to_dict() for ref in endpoint_filter_refs]

    def list_projects_for_endpoint(self, endpoint_id):
        session = sql.get_session()
        query = session.query(ProjectEndpoint)
        query = query.filter_by(endpoint_id=endpoint_id)
        endpoint_filter_refs = query.all()
        return [ref.to_dict() for ref in endpoint_filter_refs]

    def delete_association_by_endpoint(self, endpoint_id):
        session = sql.get_session()
        with session.begin():
            query = session.query(ProjectEndpoint)
            query = query.filter_by(endpoint_id=endpoint_id)
            query.delete(synchronize_session=False)

    def delete_association_by_project(self, project_id):
        session = sql.get_session()
        with session.begin():
            query = session.query(ProjectEndpoint)
            query = query.filter_by(project_id=project_id)
            query.delete(synchronize_session=False)

    def create_endpoint_group(self, endpoint_group_id, endpoint_group):
        session = sql.get_session()
        with session.begin():
            endpoint_group_ref = EndpointGroup.from_dict(endpoint_group)
            session.add(endpoint_group_ref)
        return endpoint_group_ref.to_dict()

    def _get_endpoint_group(self, session, endpoint_group_id):
        endpoint_group_ref = session.query(EndpointGroup).get(
            endpoint_group_id)
        if endpoint_group_ref is None:
            raise exception.EndpointGroupNotFound(
                endpoint_group_id=endpoint_group_id)
        return endpoint_group_ref

    def get_endpoint_group(self, endpoint_group_id):
        session = sql.get_session()
        endpoint_group_ref = self._get_endpoint_group(session,
                                                      endpoint_group_id)
        return endpoint_group_ref.to_dict()

    def update_endpoint_group(self, endpoint_group_id, endpoint_group):
        session = sql.get_session()
        with session.begin():
            endpoint_group_ref = self._get_endpoint_group(session,
                                                          endpoint_group_id)
            old_endpoint_group = endpoint_group_ref.to_dict()
            old_endpoint_group.update(endpoint_group)
            new_endpoint_group = EndpointGroup.from_dict(old_endpoint_group)
            for attr in EndpointGroup.mutable_attributes:
                setattr(endpoint_group_ref, attr,
                        getattr(new_endpoint_group, attr))
        return endpoint_group_ref.to_dict()

    def delete_endpoint_group(self, endpoint_group_id):
        session = sql.get_session()
        endpoint_group_ref = self._get_endpoint_group(session,
                                                      endpoint_group_id)
        with session.begin():
            self._delete_endpoint_group_association_by_endpoint_group(
                session, endpoint_group_id)
            session.delete(endpoint_group_ref)

    def get_endpoint_group_in_project(self, endpoint_group_id, project_id):
        session = sql.get_session()
        ref = self._get_endpoint_group_in_project(session,
                                                  endpoint_group_id,
                                                  project_id)
        return ref.to_dict()

    @sql.handle_conflicts(conflict_type='project_endpoint_group')
    def add_endpoint_group_to_project(self, endpoint_group_id, project_id):
        session = sql.get_session()

        with session.begin():
            # Create a new Project Endpoint group entity
            endpoint_group_project_ref = ProjectEndpointGroupMembership(
                endpoint_group_id=endpoint_group_id, project_id=project_id)
            session.add(endpoint_group_project_ref)

    def _get_endpoint_group_in_project(self, session,
                                       endpoint_group_id, project_id):
        endpoint_group_project_ref = session.query(
            ProjectEndpointGroupMembership).get((endpoint_group_id,
                                                 project_id))
        if endpoint_group_project_ref is None:
            msg = _('Endpoint Group Project Association not found')
            raise exception.NotFound(msg)
        else:
            return endpoint_group_project_ref

    def list_endpoint_groups(self):
        session = sql.get_session()
        query = session.query(EndpointGroup)
        endpoint_group_refs = query.all()
        return [e.to_dict() for e in endpoint_group_refs]

    def list_endpoint_groups_for_project(self, project_id):
        session = sql.get_session()
        query = session.query(ProjectEndpointGroupMembership)
        query = query.filter_by(project_id=project_id)
        endpoint_group_refs = query.all()
        return [ref.to_dict() for ref in endpoint_group_refs]

    def remove_endpoint_group_from_project(self, endpoint_group_id,
                                           project_id):
        session = sql.get_session()
        endpoint_group_project_ref = self._get_endpoint_group_in_project(
            session, endpoint_group_id, project_id)
        with session.begin():
            session.delete(endpoint_group_project_ref)

    def list_projects_associated_with_endpoint_group(self, endpoint_group_id):
        session = sql.get_session()
        query = session.query(ProjectEndpointGroupMembership)
        query = query.filter_by(endpoint_group_id=endpoint_group_id)
        endpoint_group_refs = query.all()
        return [ref.to_dict() for ref in endpoint_group_refs]

    def _delete_endpoint_group_association_by_endpoint_group(
            self, session, endpoint_group_id):
        query = session.query(ProjectEndpointGroupMembership)
        query = query.filter_by(endpoint_group_id=endpoint_group_id)
        query.delete()

    def delete_endpoint_group_association_by_project(self, project_id):
        session = sql.get_session()
        with session.begin():
            query = session.query(ProjectEndpointGroupMembership)
            query = query.filter_by(project_id=project_id)
            query.delete()

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

from oslo_log import log

from keystone.common import driver_hints
from keystone.common import sql
from keystone import exception
from keystone.i18n import _LE, _LW
from keystone.resource.backends import base


LOG = log.getLogger(__name__)


class Resource(base.ResourceDriverBase):

    def default_assignment_driver(self):
        return 'sql'

    def _encode_domain_id(self, ref):
        if 'domain_id' in ref and ref['domain_id'] is None:
            new_ref = ref.copy()
            new_ref['domain_id'] = base.NULL_DOMAIN_ID
            return new_ref
        else:
            return ref

    def _is_hidden_ref(self, ref):
        return ref.id == base.NULL_DOMAIN_ID

    def _get_project(self, session, project_id):
        project_ref = session.query(Project).get(project_id)
        if project_ref is None or self._is_hidden_ref(project_ref):
            raise exception.ProjectNotFound(project_id=project_id)
        return project_ref

    def get_project(self, project_id):
        with sql.session_for_read() as session:
            return self._get_project(session, project_id).to_dict()

    def get_project_by_name(self, project_name, domain_id):
        with sql.session_for_read() as session:
            query = session.query(Project)
            query = query.filter_by(name=project_name)
            if domain_id is None:
                query = query.filter_by(
                    domain_id=base.NULL_DOMAIN_ID)
            else:
                query = query.filter_by(domain_id=domain_id)
            try:
                project_ref = query.one()
            except sql.NotFound:
                raise exception.ProjectNotFound(project_id=project_name)

            if self._is_hidden_ref(project_ref):
                raise exception.ProjectNotFound(project_id=project_name)
            return project_ref.to_dict()

    @driver_hints.truncated
    def list_projects(self, hints):
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
            query = session.query(Project)
            project_refs = sql.filter_limit_query(Project, query, hints)
            return [project_ref.to_dict() for project_ref in project_refs
                    if not self._is_hidden_ref(project_ref)]

    def list_projects_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.session_for_read() as session:
                query = session.query(Project)
                query = query.filter(Project.id.in_(ids))
                return [project_ref.to_dict() for project_ref in query.all()
                        if not self._is_hidden_ref(project_ref)]

    def list_project_ids_from_domain_ids(self, domain_ids):
        if not domain_ids:
            return []
        else:
            with sql.session_for_read() as session:
                query = session.query(Project.id)
                query = (
                    query.filter(Project.domain_id.in_(domain_ids)))
                return [x.id for x in query.all()
                        if not self._is_hidden_ref(x)]

    def list_projects_in_domain(self, domain_id):
        with sql.session_for_read() as session:
            try:
                self._get_project(session, domain_id)
            except exception.ProjectNotFound:
                raise exception.DomainNotFound(domain_id=domain_id)
            query = session.query(Project)
            project_refs = query.filter(Project.domain_id == domain_id)
            return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_acting_as_domain(self, hints):
        hints.add_filter('is_domain', True)
        return self.list_projects(hints)

    def _get_children(self, session, project_ids, domain_id=None):
        query = session.query(Project)
        query = query.filter(Project.parent_id.in_(project_ids))
        project_refs = query.all()
        return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_in_subtree(self, project_id):
        with sql.session_for_read() as session:
            children = self._get_children(session, [project_id])
            subtree = []
            examined = set([project_id])
            while children:
                children_ids = set()
                for ref in children:
                    if ref['id'] in examined:
                        msg = _LE('Circular reference or a repeated '
                                  'entry found in projects hierarchy - '
                                  '%(project_id)s.')
                        LOG.error(msg, {'project_id': ref['id']})
                        return
                    children_ids.add(ref['id'])

                examined.update(children_ids)
                subtree += children
                children = self._get_children(session, children_ids)
            return subtree

    def list_project_parents(self, project_id):
        with sql.session_for_read() as session:
            project = self._get_project(session, project_id).to_dict()
            parents = []
            examined = set()
            while project.get('parent_id') is not None:
                if project['id'] in examined:
                    msg = _LE('Circular reference or a repeated '
                              'entry found in projects hierarchy - '
                              '%(project_id)s.')
                    LOG.error(msg, {'project_id': project['id']})
                    return

                examined.add(project['id'])
                parent_project = self._get_project(
                    session, project['parent_id']).to_dict()
                parents.append(parent_project)
                project = parent_project
            return parents

    def is_leaf_project(self, project_id):
        with sql.session_for_read() as session:
            project_refs = self._get_children(session, [project_id])
            return not project_refs

    # CRUD
    @sql.handle_conflicts(conflict_type='project')
    def create_project(self, project_id, project):
        new_project = self._encode_domain_id(project)
        with sql.session_for_write() as session:
            project_ref = Project.from_dict(new_project)
            session.add(project_ref)
            return project_ref.to_dict()

    @sql.handle_conflicts(conflict_type='project')
    def update_project(self, project_id, project):
        update_project = self._encode_domain_id(project)
        with sql.session_for_write() as session:
            project_ref = self._get_project(session, project_id)
            old_project_dict = project_ref.to_dict()
            for k in update_project:
                old_project_dict[k] = update_project[k]
            # When we read the old_project_dict, any "null" domain_id will have
            # been decoded, so we need to re-encode it
            old_project_dict = self._encode_domain_id(old_project_dict)
            new_project = Project.from_dict(old_project_dict)
            for attr in Project.attributes:
                if attr != 'id':
                    setattr(project_ref, attr, getattr(new_project, attr))
            project_ref.extra = new_project.extra
            return project_ref.to_dict(include_extra_dict=True)

    @sql.handle_conflicts(conflict_type='project')
    def delete_project(self, project_id):
        with sql.session_for_write() as session:
            project_ref = self._get_project(session, project_id)
            session.delete(project_ref)

    @sql.handle_conflicts(conflict_type='project')
    def delete_projects_from_ids(self, project_ids):
        if not project_ids:
            return
        with sql.session_for_write() as session:
            query = session.query(Project).filter(Project.id.in_(
                project_ids))
            project_ids_from_bd = [p['id'] for p in query.all()]
            for project_id in project_ids:
                if (project_id not in project_ids_from_bd or
                        project_id == base.NULL_DOMAIN_ID):
                    LOG.warning(_LW('Project %s does not exist and was not '
                                    'deleted.') % project_id)
            query.delete(synchronize_session=False)


class Project(sql.ModelBase, sql.DictBase):
    # NOTE(henry-nash): From the manager and above perspective, the domain_id
    # is nullable.  However, to ensure uniqueness in multi-process
    # configurations, it is better to still use the sql uniqueness constraint.
    # Since the support for a nullable component of a uniqueness constraint
    # across different sql databases is mixed, we instead store a special value
    # to represent null, as defined in NULL_DOMAIN_ID above.

    def to_dict(self, include_extra_dict=False):
        d = super(Project, self).to_dict(
            include_extra_dict=include_extra_dict)
        if d['domain_id'] == base.NULL_DOMAIN_ID:
            d['domain_id'] = None
        return d

    __tablename__ = 'project'
    attributes = ['id', 'name', 'domain_id', 'description', 'enabled',
                  'parent_id', 'is_domain']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'),
                           nullable=False)
    description = sql.Column(sql.Text())
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    parent_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'))
    is_domain = sql.Column(sql.Boolean, default=False, nullable=False,
                           server_default='0')
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'),)

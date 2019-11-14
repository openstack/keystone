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
from sqlalchemy import orm
from sqlalchemy.sql import expression

from keystone.common import driver_hints
from keystone.common import resource_options
from keystone.common import sql
from keystone import exception
from keystone.resource.backends import base
from keystone.resource.backends import sql_model


LOG = log.getLogger(__name__)


class Resource(base.ResourceDriverBase):

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
        project_ref = session.query(sql_model.Project).get(project_id)
        if project_ref is None or self._is_hidden_ref(project_ref):
            raise exception.ProjectNotFound(project_id=project_id)
        return project_ref

    def get_project(self, project_id):
        with sql.session_for_read() as session:
            return self._get_project(session, project_id).to_dict()

    def get_project_by_name(self, project_name, domain_id):
        with sql.session_for_read() as session:
            query = session.query(sql_model.Project)
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
            query = session.query(sql_model.Project)
            query = query.filter(sql_model.Project.id != base.NULL_DOMAIN_ID)
            project_refs = sql.filter_limit_query(sql_model.Project, query,
                                                  hints)
            return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.session_for_read() as session:
                query = session.query(sql_model.Project)
                query = query.filter(sql_model.Project.id.in_(ids))
                return [project_ref.to_dict() for project_ref in query.all()
                        if not self._is_hidden_ref(project_ref)]

    def list_project_ids_from_domain_ids(self, domain_ids):
        if not domain_ids:
            return []
        else:
            with sql.session_for_read() as session:
                query = session.query(sql_model.Project.id)
                query = (
                    query.filter(sql_model.Project.domain_id.in_(domain_ids)))
                return [x.id for x in query.all()
                        if not self._is_hidden_ref(x)]

    def list_projects_in_domain(self, domain_id):
        with sql.session_for_read() as session:
            try:
                self._get_project(session, domain_id)
            except exception.ProjectNotFound:
                raise exception.DomainNotFound(domain_id=domain_id)
            query = session.query(sql_model.Project)
            project_refs = query.filter(
                sql_model.Project.domain_id == domain_id)
            return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_acting_as_domain(self, hints):
        hints.add_filter('is_domain', True)
        return self.list_projects(hints)

    def _get_children(self, session, project_ids, domain_id=None):
        query = session.query(sql_model.Project)
        query = query.filter(sql_model.Project.parent_id.in_(project_ids))
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
                        msg = ('Circular reference or a repeated '
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
                    msg = ('Circular reference or a repeated '
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

    def list_projects_by_tags(self, filters):
        filtered_ids = []
        with sql.session_for_read() as session:
            query = session.query(sql_model.ProjectTag)
            if 'tags' in filters.keys():
                filtered_ids += self._filter_ids_by_tags(
                    query, filters['tags'].split(','))
            if 'tags-any' in filters.keys():
                any_tags = filters['tags-any'].split(',')
                subq = query.filter(sql_model.ProjectTag.name.in_(any_tags))
                any_tags = [ptag['project_id'] for ptag in subq]
                if 'tags' in filters.keys():
                    any_tags = set(any_tags) & set(filtered_ids)
                filtered_ids = any_tags
            if 'not-tags' in filters.keys():
                blacklist_ids = self._filter_ids_by_tags(
                    query, filters['not-tags'].split(','))
                filtered_ids = self._filter_not_tags(session,
                                                     filtered_ids,
                                                     blacklist_ids)
            if 'not-tags-any' in filters.keys():
                any_tags = filters['not-tags-any'].split(',')
                subq = query.filter(sql_model.ProjectTag.name.in_(any_tags))
                blacklist_ids = [ptag['project_id'] for ptag in subq]
                if 'not-tags' in filters.keys():
                    filtered_ids += blacklist_ids
                else:
                    filtered_ids = self._filter_not_tags(session,
                                                         filtered_ids,
                                                         blacklist_ids)
            if not filtered_ids:
                return []
            query = session.query(sql_model.Project)
            query = query.filter(sql_model.Project.id.in_(filtered_ids))
            return [project_ref.to_dict() for project_ref in query.all()
                    if not self._is_hidden_ref(project_ref)]

    def _filter_ids_by_tags(self, query, tags):
        filtered_ids = []
        subq = query.filter(sql_model.ProjectTag.name.in_(tags))
        for ptag in subq:
            subq_tags = query.filter(sql_model.ProjectTag.project_id ==
                                     ptag['project_id'])
            result = map(lambda x: x['name'], subq_tags.all())
            if set(tags) <= set(result):
                filtered_ids.append(ptag['project_id'])
        return filtered_ids

    def _filter_not_tags(self, session, filtered_ids, blacklist_ids):
        subq = session.query(sql_model.Project)
        valid_ids = [q['id'] for q in subq if q['id'] not in blacklist_ids]
        if filtered_ids:
            valid_ids = list(set(valid_ids) & set(filtered_ids))
        return valid_ids

    # CRUD
    @sql.handle_conflicts(conflict_type='project')
    def create_project(self, project_id, project):
        new_project = self._encode_domain_id(project)
        with sql.session_for_write() as session:
            project_ref = sql_model.Project.from_dict(new_project)
            session.add(project_ref)
            # Set resource options passed on creation
            resource_options.resource_options_ref_to_mapper(
                project_ref, sql_model.ProjectOption
            )
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
            new_project = sql_model.Project.from_dict(old_project_dict)
            for attr in sql_model.Project.attributes:
                if attr != 'id':
                    setattr(project_ref, attr, getattr(new_project, attr))
            # Move the "_resource_options" attribute over to the real ref
            # so that resource_options.resource_options_ref_to_mapper can
            # handle the work.
            setattr(project_ref, '_resource_options',
                    getattr(new_project, '_resource_options', {}))

            # Move options into the proper attribute mapper construct
            resource_options.resource_options_ref_to_mapper(
                project_ref, sql_model.ProjectOption)
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
            query = session.query(sql_model.Project).filter(
                sql_model.Project.id.in_(project_ids))
            project_ids_from_bd = [p['id'] for p in query.all()]
            for project_id in project_ids:
                if (project_id not in project_ids_from_bd or
                        project_id == base.NULL_DOMAIN_ID):
                    LOG.warning('Project %s does not exist and was not '
                                'deleted.', project_id)
            query.delete(synchronize_session=False)

    def check_project_depth(self, max_depth):
        with sql.session_for_read() as session:
            obj_list = []
            # Using db table self outerjoin to find the project descendants.
            #
            # We'll only outerjoin the project table `max_depth` times to
            # check whether current project tree exceed the max depth limit.
            #
            # For example:
            #
            # If max_depth is 2, we will take the outerjoin 2 times, then the
            # SQL result may be like:
            #
            #  +---- +-------------+-------------+-------------+
            #  | No. | project1_id | project2_id | project3_id |
            #  +--- -+-------------+-------------+-------------+
            #  |  1  |  domain_x   |             |             |
            #  +- ---+-------------+-------------+-------------+
            #  |  2  |  project_a  |             |             |
            #  +- ---+-------------+-------------+-------------+
            #  |  3  |  domain_y   |  project_a  |             |
            #  +- ---+-------------+-------------+-------------+
            #  |  4  |  project_b  |  project_c  |             |
            #  +- ---+-------------+-------------+-------------+
            #  |  5  |  domain_y   |  project_b  |  project_c  |
            #  +- ---+-------------+-------------+-------------+
            #
            # `project1_id` column is the root. It is a project or a domain.
            # If `project1_id` is a project, there must exist a line that
            # `project1` is its domain.
            #
            # We got 5 lines here. It includes three scenarios:
            #
            # 1). The No.1 line means there is a domain `domain_x` which has no
            #     children. The depth is 1.
            #
            # 2). The No.2 and No.3 lines mean project `project_a` has no child
            # and its parent is domain `domain_y`. The depth is 2.
            #
            # 3). The No.4 and No.5 lines mean project `project_b` has a child
            #     `project_c` and its parent is domain `domain_y`. The depth is
            #     3. This tree hit the max depth
            #
            # So we can see that if column "project3_id" has value, it means
            # some trees hit the max depth limit.

            for _ in range(max_depth + 1):
                obj_list.append(orm.aliased(sql_model.Project))

            query = session.query(*obj_list)

            for index in range(max_depth):
                query = query.outerjoin(
                    obj_list[index + 1],
                    obj_list[index].id == obj_list[index + 1].parent_id)
            exceeded_lines = query.filter(
                obj_list[-1].id != expression.null())

            if exceeded_lines:
                return [line[max_depth].id for line in exceeded_lines]

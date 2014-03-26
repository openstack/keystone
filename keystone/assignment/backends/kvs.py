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

from keystone import assignment
from keystone import clean
from keystone.common import kvs
from keystone import exception
from keystone.openstack.common.gettextutils import _


class Assignment(kvs.Base, assignment.Driver):
    """KVS Assignment backend.

    This backend uses the following mappings to store data:

    * Domains:

      * domain_list -> [domain_id, ...]
      * domain-{id} -> domain_ref
      * domain_name-{name} -> domain_ref

    * Projects:

      * tenant-{id} -> project_ref
      * tenant_name-{name} -> project_ref

    * Roles:

      * role_list -> [role_id, ...]
      * role-{id} -> role_ref

    * Role assignments:

      * metadata_user-{target}-{user_id} ->
        {'roles': [{'id': role-id, ...}, ...]}
      * metadata_group-{target}-{group_id} ->
        {'roles': [{'id': role-id, ...}, ...]}

    """

    # Public interface

    def get_project(self, tenant_id):
        try:
            return self.db.get('tenant-%s' % tenant_id)
        except exception.NotFound:
            raise exception.ProjectNotFound(project_id=tenant_id)

    def _build_project_refs(self):
        project_keys = (k for k in self.db.keys() if k.startswith('tenant-'))
        return [self.db.get(key) for key in project_keys]

    def list_projects(self, hints):
        return self._build_project_refs()

    def list_projects_in_domain(self, domain_id):
        project_refs = self._build_project_refs()
        self.get_domain(domain_id)
        return [ref for ref in project_refs if domain_id in ref['domain_id']]

    def get_project_by_name(self, tenant_name, domain_id):
        try:
            return self.db.get('tenant_name-%s' % tenant_name)
        except exception.NotFound:
            raise exception.ProjectNotFound(project_id=tenant_name)

    def list_user_ids_for_project(self, tenant_id):
        self.get_project(tenant_id)

        user_ids = set()

        metadata_keys = (k for k in self.db.keys()
                         if k.startswith('metadata_user-'))
        for key in metadata_keys:
            i, meta_project_or_domain_id, meta_user_id = key.split('-')

            if meta_project_or_domain_id != tenant_id:
                # target is not the project, so on to next metadata.
                continue

            user_ids.add(meta_user_id)

        return list(user_ids)

    def _get_metadata(self, user_id=None, tenant_id=None,
                      domain_id=None, group_id=None):
        try:
            if user_id:
                if tenant_id:
                    return self.db.get('metadata_user-%s-%s' % (tenant_id,
                                                                user_id))
                else:
                    return self.db.get('metadata_user-%s-%s' % (domain_id,
                                                                user_id))
            else:
                if tenant_id:
                    return self.db.get('metadata_group-%s-%s' % (tenant_id,
                                                                 group_id))
                else:
                    return self.db.get('metadata_group-%s-%s' % (domain_id,
                                                                 group_id))
        except exception.NotFound:
            raise exception.MetadataNotFound()

    def get_role(self, role_id):
        try:
            return self.db.get('role-%s' % role_id)
        except exception.NotFound:
            raise exception.RoleNotFound(role_id=role_id)

    def list_roles(self, hints):
        return self._list_roles()

    def _list_roles(self):
        role_ids = self.db.get('role_list', [])
        return [self.get_role(x) for x in role_ids]

    def list_projects_for_user(self, user_id, group_ids, hints):
        # NOTE(henry-nash): The kvs backend is being deprecated, so no
        # support is provided for projects that the user has a role on solely
        # by virtue of group membership.

        project_ids = set()

        metadata_keys = (k for k in self.db.keys()
                         if k.startswith('metadata_user-'))
        for key in metadata_keys:
            i, meta_project_or_domain_id, meta_user_id = key.split('-')

            if meta_user_id != user_id:
                # Not the user, so on to next metadata.
                continue

            try:
                self.get_project(meta_project_or_domain_id)
            except exception.NotFound:
                # target is not a project, so on to next metadata.
                continue

            project_id = meta_project_or_domain_id
            project_ids.add(project_id)

        project_refs = []

        for project_id in project_ids:
            project_refs.append(self.get_project(project_id))

        return project_refs

    def get_roles_for_groups(self, group_ids, project_id=None, domain_id=None):
        raise exception.NotImplemented()

    def list_projects_for_groups(self, group_ids):
        raise exception.NotImplemented()

    def list_domains_for_groups(self, group_ids):
        raise exception.NotImplemented()

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        self.get_project(tenant_id)
        self.get_role(role_id)
        try:
            metadata_ref = self._get_metadata(user_id, tenant_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        try:
            metadata_ref['roles'] = self._add_role_to_role_dicts(
                role_id, False, metadata_ref.get('roles', []),
                allow_existing=False)
        except KeyError:
            msg = ('User %s already has role %s in tenant %s'
                   % (user_id, role_id, tenant_id))
            raise exception.Conflict(type='role grant', details=msg)

        self._update_metadata(user_id, tenant_id, metadata_ref)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        try:
            metadata_ref = self._get_metadata(user_id, tenant_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        try:
            metadata_ref['roles'] = self._remove_role_from_role_dicts(
                role_id, False, metadata_ref.get('roles', []))
        except KeyError:
            raise exception.RoleNotFound(message=_(
                'Cannot remove role that has not been granted, %s') %
                role_id)

        if metadata_ref['roles']:
            self._update_metadata(user_id, tenant_id, metadata_ref)
        else:
            self.db.delete('metadata_user-%s-%s' % (tenant_id, user_id))

    def list_role_assignments(self):
        """List the role assignments.

        We enumerate the metadata entries and extract the targets, actors, and
        roles.

        """
        assignment_list = []
        metadata_keys = (k for k in self.db.keys()
                         if k.startswith('metadata_user-'))
        for key in metadata_keys:
            template = {}
            i, meta_project_or_domain_id, template['user_id'] = key.split('-')
            try:
                self.get_project(meta_project_or_domain_id)
                template['project_id'] = meta_project_or_domain_id
            except exception.NotFound:
                template['domain_id'] = meta_project_or_domain_id

            entry = self.db.get(key)
            inherited = False
            for r in self._roles_from_role_dicts(entry.get('roles', {}),
                                                 inherited):
                role_assignment = template.copy()
                role_assignment['role_id'] = r
                assignment_list.append(role_assignment)

        metadata_keys = (k for k in self.db.keys()
                         if k.startswith('metadata_group-'))
        for key in metadata_keys:
            template = {}
            i, meta_project_or_domain_id, template['group_id'] = key.split('-')
            try:
                self.get_project(meta_project_or_domain_id)
                template['project_id'] = meta_project_or_domain_id
            except exception.NotFound:
                template['domain_id'] = meta_project_or_domain_id

            entry = self.db.get(key)
            inherited = False
            for r in self._roles_from_role_dicts(entry.get('roles', {}),
                                                 inherited):
                role_assignment = template.copy()
                role_assignment['role_id'] = r
                assignment_list.append(role_assignment)

        return assignment_list

    # CRUD
    def create_project(self, tenant_id, tenant):
        tenant['name'] = clean.project_name(tenant['name'])
        try:
            self.get_project(tenant_id)
        except exception.ProjectNotFound:
            pass
        else:
            msg = 'Duplicate ID, %s.' % tenant_id
            raise exception.Conflict(type='tenant', details=msg)

        try:
            self.get_project_by_name(tenant['name'], tenant['domain_id'])
        except exception.ProjectNotFound:
            pass
        else:
            msg = 'Duplicate name, %s.' % tenant['name']
            raise exception.Conflict(type='tenant', details=msg)

        self.db.set('tenant-%s' % tenant_id, tenant)
        self.db.set('tenant_name-%s' % tenant['name'], tenant)
        return tenant

    def update_project(self, tenant_id, tenant):
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])
            try:
                existing = self.db.get('tenant_name-%s' % tenant['name'])
                if existing and tenant_id != existing['id']:
                    msg = 'Duplicate name, %s.' % tenant['name']
                    raise exception.Conflict(type='tenant', details=msg)
            except exception.NotFound:
                pass
        # get the old name and delete it too
        try:
            old_project = self.db.get('tenant-%s' % tenant_id)
        except exception.NotFound:
            raise exception.ProjectNotFound(project_id=tenant_id)
        new_project = old_project.copy()
        new_project.update(tenant)
        new_project['id'] = tenant_id
        self.db.delete('tenant_name-%s' % old_project['name'])
        self.db.set('tenant-%s' % tenant_id, new_project)
        self.db.set('tenant_name-%s' % new_project['name'], new_project)
        return new_project

    def delete_project(self, tenant_id):
        try:
            old_project = self.db.get('tenant-%s' % tenant_id)
        except exception.NotFound:
            raise exception.ProjectNotFound(project_id=tenant_id)
        self.db.delete('tenant_name-%s' % old_project['name'])
        self.db.delete('tenant-%s' % tenant_id)

    def _create_metadata(self, user_id, tenant_id, metadata,
                         domain_id=None, group_id=None):

        return self._update_metadata(user_id, tenant_id, metadata,
                                     domain_id, group_id)

    def _update_metadata(self, user_id, tenant_id, metadata,
                         domain_id=None, group_id=None):
        if user_id:
            if tenant_id:
                self.db.set('metadata_user-%s-%s' % (tenant_id, user_id),
                            metadata)
            else:
                self.db.set('metadata_user-%s-%s' % (domain_id, user_id),
                            metadata)
        else:
            if tenant_id:
                self.db.set('metadata_group-%s-%s' % (tenant_id, group_id),
                            metadata)
            else:
                self.db.set('metadata_group-%s-%s' % (domain_id, group_id),
                            metadata)
        return metadata

    def create_role(self, role_id, role):
        try:
            self.get_role(role_id)
        except exception.RoleNotFound:
            pass
        else:
            msg = 'Duplicate ID, %s.' % role_id
            raise exception.Conflict(type='role', details=msg)

        for role_ref in self._list_roles():
            if role['name'] == role_ref['name']:
                msg = 'Duplicate name, %s.' % role['name']
                raise exception.Conflict(type='role', details=msg)
        self.db.set('role-%s' % role_id, role)
        role_list = set(self.db.get('role_list', []))
        role_list.add(role_id)
        self.db.set('role_list', list(role_list))
        return role

    def update_role(self, role_id, role):
        old_role_ref = None
        for role_ref in self._list_roles():
            if role['name'] == role_ref['name'] and role_id != role_ref['id']:
                msg = 'Duplicate name, %s.' % role['name']
                raise exception.Conflict(type='role', details=msg)
            if role_id == role_ref['id']:
                old_role_ref = role_ref
        if old_role_ref is None:
            raise exception.RoleNotFound(role_id=role_id)
        new_role = old_role_ref.copy()
        new_role.update(role)
        new_role['id'] = role_id
        self.db.set('role-%s' % role_id, new_role)
        return role

    def delete_role(self, role_id):
        self.get_role(role_id)

        metadata_keys = (k for k in self.db.keys()
                         if k.startswith('metadata_user-'))
        for key in metadata_keys:
            i, meta_project_or_domain_id, meta_user_id = key.split('-')
            try:
                self.delete_grant(role_id,
                                  project_id=meta_project_or_domain_id,
                                  user_id=meta_user_id)
            except exception.NotFound:
                pass
            try:
                self.delete_grant(role_id, domain_id=meta_project_or_domain_id,
                                  user_id=meta_user_id)
            except exception.NotFound:
                pass

        metadata_keys = (k for k in self.db.keys()
                         if k.startswith('metadata_group-'))
        for key in metadata_keys:
            i, meta_project_or_domain_id, meta_group_id = key.split('-')
            try:
                self.delete_grant(role_id,
                                  project_id=meta_project_or_domain_id,
                                  group_id=meta_group_id)
            except exception.NotFound:
                pass
            try:
                self.delete_grant(role_id, domain_id=meta_project_or_domain_id,
                                  group_id=meta_group_id)
            except exception.NotFound:
                pass

        self.db.delete('role-%s' % role_id)
        role_list = set(self.db.get('role_list', []))
        role_list.remove(role_id)
        self.db.set('role_list', list(role_list))

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):

        self.get_role(role_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        metadata_ref['roles'] = self._add_role_to_role_dicts(
            role_id, inherited_to_projects, metadata_ref.get('roles', []))

        self._update_metadata(user_id, project_id, metadata_ref,
                              domain_id, group_id)

    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        return [self.get_role(x) for x in
                self._roles_from_role_dicts(metadata_ref.get('roles', []),
                                            inherited_to_projects)]

    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        self.get_role(role_id)
        if group_id:
            self.get_group(group_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        role_ids = set(self._roles_from_role_dicts(
            metadata_ref.get('roles', []), inherited_to_projects))

        if role_id not in role_ids:
            raise exception.RoleNotFound(role_id=role_id)
        return self.get_role(role_id)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        self.get_role(role_id)
        if domain_id:
            self.get_domain(domain_id)
        if project_id:
            self.get_project(project_id)

        try:
            metadata_ref = self._get_metadata(user_id, project_id,
                                              domain_id, group_id)
        except exception.MetadataNotFound:
            metadata_ref = {}

        try:
            metadata_ref['roles'] = self._remove_role_from_role_dicts(
                role_id, inherited_to_projects, metadata_ref.get('roles', []))
        except KeyError:
            raise exception.RoleNotFound(role_id=role_id)

        self._update_metadata(user_id, project_id, metadata_ref,
                              domain_id, group_id)

    # domain crud

    def create_domain(self, domain_id, domain):
        try:
            self.get_domain(domain_id)
        except exception.DomainNotFound:
            pass
        else:
            msg = 'Duplicate ID, %s.' % domain_id
            raise exception.Conflict(type='domain', details=msg)

        try:
            self.get_domain_by_name(domain['name'])
        except exception.DomainNotFound:
            pass
        else:
            msg = 'Duplicate name, %s.' % domain['name']
            raise exception.Conflict(type='domain', details=msg)

        self.db.set('domain-%s' % domain_id, domain)
        self.db.set('domain_name-%s' % domain['name'], domain)
        domain_list = set(self.db.get('domain_list', []))
        domain_list.add(domain_id)
        self.db.set('domain_list', list(domain_list))
        return domain

    def list_domains(self, hints):
        domain_ids = self.db.get('domain_list', [])
        return [self.get_domain(x) for x in domain_ids]

    def get_domain(self, domain_id):
        try:
            return self.db.get('domain-%s' % domain_id)
        except exception.NotFound:
            raise exception.DomainNotFound(domain_id=domain_id)

    def get_domain_by_name(self, domain_name):
        try:
            return self.db.get('domain_name-%s' % domain_name)
        except exception.NotFound:
            raise exception.DomainNotFound(domain_id=domain_name)

    def update_domain(self, domain_id, domain):
        orig_domain = self.get_domain(domain_id)
        domain['id'] = domain_id
        self.db.set('domain-%s' % domain_id, domain)
        self.db.set('domain_name-%s' % domain['name'], domain)
        if domain['name'] != orig_domain['name']:
            self.db.delete('domain_name-%s' % orig_domain['name'])
        return domain

    def delete_domain(self, domain_id):
        domain = self.get_domain(domain_id)
        self.db.delete('domain-%s' % domain_id)
        self.db.delete('domain_name-%s' % domain['name'])
        domain_list = set(self.db.get('domain_list', []))
        domain_list.remove(domain_id)
        self.db.set('domain_list', list(domain_list))

    def delete_user(self, user_id):
        """Deletes all assignments for a user.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    def delete_group(self, group_id):
        """Deletes all assignments for a group.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

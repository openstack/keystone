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

from __future__ import absolute_import

import uuid

from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils

from keystone.common import clean
from keystone.common import driver_hints
from keystone.common import ldap as common_ldap
from keystone.common import models
from keystone import exception
from keystone.i18n import _
from keystone.identity.backends import ldap as ldap_identity
from keystone import resource


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Resource(resource.ResourceDriverV8):
    @versionutils.deprecated(
        versionutils.deprecated.LIBERTY,
        remove_in=+1,
        what='ldap resource')
    def __init__(self):
        super(Resource, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        # This is the only deep dependency from resource back to identity.
        # This is safe to do since if you are using LDAP for resource, it is
        # required that you are using it for identity as well.
        self.user = ldap_identity.UserApi(CONF)

        self.project = ProjectApi(CONF)

    def default_assignment_driver(self):
        return 'ldap'

    def _set_default_parent_project(self, ref):
        """If the parent project ID has not been set, set it to None."""
        if isinstance(ref, dict):
            if 'parent_id' not in ref:
                ref = dict(ref, parent_id=None)
            return ref
        elif isinstance(ref, list):
            return [self._set_default_parent_project(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _set_default_is_domain_project(self, ref):
        if isinstance(ref, dict):
            return dict(ref, is_domain=False)
        elif isinstance(ref, list):
            return [self._set_default_is_domain_project(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _validate_parent_project_is_none(self, ref):
        """If a parent_id different from None was given,
           raises InvalidProjectException.

        """
        parent_id = ref.get('parent_id')
        if parent_id is not None:
            raise exception.InvalidParentProject(parent_id)

    def _validate_is_domain_field_is_false(self, ref):
        is_domain = ref.pop('is_domain', None)
        if is_domain:
            raise exception.ValidationError(_('LDAP does not support projects '
                                              'with is_domain flag enabled'))

    def _set_default_attributes(self, project_ref):
        project_ref = self._set_default_domain(project_ref)
        project_ref = self._set_default_is_domain_project(project_ref)
        return self._set_default_parent_project(project_ref)

    def get_project(self, tenant_id):
        return self._set_default_attributes(
            self.project.get(tenant_id))

    def list_projects(self, hints):
        return self._set_default_attributes(
            self.project.get_all_filtered(hints))

    def list_projects_in_domain(self, domain_id):
        # We don't support multiple domains within this driver, so ignore
        # any domain specified
        return self.list_projects(driver_hints.Hints())

    def list_projects_in_subtree(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will never have children
        return []

    def list_project_parents(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will never have parents
        return []

    def is_leaf_project(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will always be a root and a leaf at the same time
        return True

    def list_projects_from_ids(self, ids):
        return [self.get_project(id) for id in ids]

    def list_project_ids_from_domain_ids(self, domain_ids):
        # We don't support multiple domains within this driver, so ignore
        # any domain specified
        return [x.id for x in self.list_projects(driver_hints.Hints())]

    def get_project_by_name(self, tenant_name, domain_id):
        self._validate_default_domain_id(domain_id)
        return self._set_default_attributes(
            self.project.get_by_name(tenant_name))

    def create_project(self, tenant_id, tenant):
        self.project.check_allow_create()
        self._validate_parent_project_is_none(tenant)
        self._validate_is_domain_field_is_false(tenant)
        tenant['name'] = clean.project_name(tenant['name'])
        data = tenant.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4().hex)
        if 'description' in data and data['description'] in ['', None]:
            data.pop('description')
        return self._set_default_attributes(
            self.project.create(data))

    def update_project(self, tenant_id, tenant):
        self.project.check_allow_update()
        tenant = self._validate_default_domain(tenant)
        self._validate_is_domain_field_is_false(tenant)
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])
        return self._set_default_attributes(
            self.project.update(tenant_id, tenant))

    def delete_project(self, tenant_id):
        self.project.check_allow_delete()
        if self.project.subtree_delete_enabled:
            self.project.deleteTree(tenant_id)
        else:
            # The manager layer will call assignments to delete the
            # role assignments, so we just have to delete the project itself.
            self.project.delete(tenant_id)

    def create_domain(self, domain_id, domain):
        if domain_id == CONF.identity.default_domain_id:
            msg = _('Duplicate ID, %s.') % domain_id
            raise exception.Conflict(type='domain', details=msg)
        raise exception.Forbidden(_('Domains are read-only against LDAP'))

    def get_domain(self, domain_id):
        self._validate_default_domain_id(domain_id)
        return resource.calc_default_domain()

    def update_domain(self, domain_id, domain):
        self._validate_default_domain_id(domain_id)
        raise exception.Forbidden(_('Domains are read-only against LDAP'))

    def delete_domain(self, domain_id):
        self._validate_default_domain_id(domain_id)
        raise exception.Forbidden(_('Domains are read-only against LDAP'))

    def list_domains(self, hints):
        return [resource.calc_default_domain()]

    def list_domains_from_ids(self, ids):
        return [resource.calc_default_domain()]

    def get_domain_by_name(self, domain_name):
        default_domain = resource.calc_default_domain()
        if domain_name != default_domain['name']:
            raise exception.DomainNotFound(domain_id=domain_name)
        return default_domain


# TODO(termie): turn this into a data object and move logic to driver
class ProjectApi(common_ldap.ProjectLdapStructureMixin,
                 common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap):

    model = models.Project

    def create(self, values):
        data = values.copy()
        if data.get('id') is None:
            data['id'] = uuid.uuid4().hex
        return super(ProjectApi, self).create(data)

    def update(self, project_id, values):
        old_obj = self.get(project_id)
        return super(ProjectApi, self).update(project_id, values, old_obj)

    def get_all_filtered(self, hints):
        query = self.filter_query(hints)
        return super(ProjectApi, self).get_all(query)

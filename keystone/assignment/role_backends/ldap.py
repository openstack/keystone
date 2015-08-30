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

from oslo_config import cfg
from oslo_log import log

from keystone import assignment
from keystone.common import ldap as common_ldap
from keystone.common import models
from keystone import exception
from keystone.i18n import _
from keystone.identity.backends import ldap as ldap_identity


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Role(assignment.RoleDriverV8):

    def __init__(self):
        super(Role, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        # This is the only deep dependency from resource back
        # to identity.  The assumption is that if you are using
        # LDAP for resource, you are using it for identity as well.
        self.user = ldap_identity.UserApi(CONF)
        self.role = RoleApi(CONF, self.user)

    def get_role(self, role_id):
        return self.role.get(role_id)

    def list_roles(self, hints):
        return self.role.get_all()

    def list_roles_from_ids(self, ids):
        return [self.get_role(id) for id in ids]

    def create_role(self, role_id, role):
        self.role.check_allow_create()
        try:
            self.get_role(role_id)
        except exception.NotFound:
            pass
        else:
            msg = _('Duplicate ID, %s.') % role_id
            raise exception.Conflict(type='role', details=msg)

        try:
            self.role.get_by_name(role['name'])
        except exception.NotFound:
            pass
        else:
            msg = _('Duplicate name, %s.') % role['name']
            raise exception.Conflict(type='role', details=msg)

        return self.role.create(role)

    def delete_role(self, role_id):
        self.role.check_allow_delete()
        return self.role.delete(role_id)

    def update_role(self, role_id, role):
        self.role.check_allow_update()
        self.get_role(role_id)
        return self.role.update(role_id, role)


# NOTE(heny-nash): A mixin class to enable the sharing of the LDAP structure
# between here and the assignment LDAP.
class RoleLdapStructureMixin(object):
    DEFAULT_OU = 'ou=Roles'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'organizationalRole'
    DEFAULT_MEMBER_ATTRIBUTE = 'roleOccupant'
    NotFound = exception.RoleNotFound
    options_name = 'role'
    attribute_options_names = {'name': 'name'}
    immutable_attrs = ['id']
    model = models.Role


# TODO(termie): turn this into a data object and move logic to driver
class RoleApi(RoleLdapStructureMixin, common_ldap.BaseLdap):

    def __init__(self, conf, user_api):
        super(RoleApi, self).__init__(conf)
        self._user_api = user_api

    def get(self, role_id, role_filter=None):
        model = super(RoleApi, self).get(role_id, role_filter)
        return model

    def create(self, values):
        return super(RoleApi, self).create(values)

    def update(self, role_id, role):
        new_name = role.get('name')
        if new_name is not None:
            try:
                old_role = self.get_by_name(new_name)
                if old_role['id'] != role_id:
                    raise exception.Conflict(
                        _('Cannot duplicate name %s') % old_role)
            except exception.NotFound:
                pass
        return super(RoleApi, self).update(role_id, role)

    def delete(self, role_id):
        super(RoleApi, self).delete(role_id)

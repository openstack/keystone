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
from __future__ import absolute_import
import uuid

import ldap.filter
from oslo_config import cfg
from oslo_log import log
import six

from keystone.common import clean
from keystone.common import driver_hints
from keystone.common import ldap as common_ldap
from keystone.common import models
from keystone import exception
from keystone.i18n import _
from keystone import identity


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Identity(identity.IdentityDriverV8):
    def __init__(self, conf=None):
        super(Identity, self).__init__()
        if conf is None:
            conf = CONF
        self.user = UserApi(conf)
        self.group = GroupApi(conf)

    def default_assignment_driver(self):
        return 'ldap'

    def is_domain_aware(self):
        return False

    def generates_uuids(self):
        return False

    # Identity interface

    def authenticate(self, user_id, password):
        try:
            user_ref = self._get_user(user_id)
        except exception.UserNotFound:
            raise AssertionError(_('Invalid user / password'))
        if not user_id or not password:
            raise AssertionError(_('Invalid user / password'))
        conn = None
        try:
            conn = self.user.get_connection(user_ref['dn'],
                                            password, end_user_auth=True)
            if not conn:
                raise AssertionError(_('Invalid user / password'))
        except Exception:
            raise AssertionError(_('Invalid user / password'))
        finally:
            if conn:
                conn.unbind_s()
        return self.user.filter_attributes(user_ref)

    def _get_user(self, user_id):
        return self.user.get(user_id)

    def get_user(self, user_id):
        return self.user.get_filtered(user_id)

    def list_users(self, hints):
        return self.user.get_all_filtered(hints)

    def get_user_by_name(self, user_name, domain_id):
        # domain_id will already have been handled in the Manager layer,
        # parameter left in so this matches the Driver specification
        return self.user.filter_attributes(self.user.get_by_name(user_name))

    # CRUD
    def create_user(self, user_id, user):
        self.user.check_allow_create()
        user_ref = self.user.create(user)
        return self.user.filter_attributes(user_ref)

    def update_user(self, user_id, user):
        self.user.check_allow_update()
        old_obj = self.user.get(user_id)
        if 'name' in user and old_obj.get('name') != user['name']:
            raise exception.Conflict(_('Cannot change user name'))

        if self.user.enabled_mask:
            self.user.mask_enabled_attribute(user)
        elif self.user.enabled_invert and not self.user.enabled_emulation:
            # We need to invert the enabled value for the old model object
            # to prevent the LDAP update code from thinking that the enabled
            # values are already equal.
            user['enabled'] = not user['enabled']
            old_obj['enabled'] = not old_obj['enabled']

        self.user.update(user_id, user, old_obj)
        return self.user.get_filtered(user_id)

    def delete_user(self, user_id):
        self.user.check_allow_delete()
        user = self.user.get(user_id)
        user_dn = user['dn']
        groups = self.group.list_user_groups(user_dn)
        for group in groups:
            self.group.remove_user(user_dn, group['id'], user_id)

        if hasattr(user, 'tenant_id'):
            self.project.remove_user(user.tenant_id, user_dn)
        self.user.delete(user_id)

    def create_group(self, group_id, group):
        self.group.check_allow_create()
        group['name'] = clean.group_name(group['name'])
        return common_ldap.filter_entity(self.group.create(group))

    def get_group(self, group_id):
        return self.group.get_filtered(group_id)

    def get_group_by_name(self, group_name, domain_id):
        # domain_id will already have been handled in the Manager layer,
        # parameter left in so this matches the Driver specification
        return self.group.get_filtered_by_name(group_name)

    def update_group(self, group_id, group):
        self.group.check_allow_update()
        if 'name' in group:
            group['name'] = clean.group_name(group['name'])
        return common_ldap.filter_entity(self.group.update(group_id, group))

    def delete_group(self, group_id):
        self.group.check_allow_delete()
        return self.group.delete(group_id)

    def add_user_to_group(self, user_id, group_id):
        user_ref = self._get_user(user_id)
        user_dn = user_ref['dn']
        self.group.add_user(user_dn, group_id, user_id)

    def remove_user_from_group(self, user_id, group_id):
        user_ref = self._get_user(user_id)
        user_dn = user_ref['dn']
        self.group.remove_user(user_dn, group_id, user_id)

    def list_groups_for_user(self, user_id, hints):
        user_ref = self._get_user(user_id)
        user_dn = user_ref['dn']
        return self.group.list_user_groups_filtered(user_dn, hints)

    def list_groups(self, hints):
        return self.group.get_all_filtered(hints)

    def list_users_in_group(self, group_id, hints):
        users = []
        for user_dn in self.group.list_group_users(group_id):
            user_id = self.user._dn_to_id(user_dn)
            try:
                users.append(self.user.get_filtered(user_id))
            except exception.UserNotFound:
                LOG.debug(("Group member '%(user_dn)s' not found in"
                           " '%(group_id)s'. The user should be removed"
                           " from the group. The user will be ignored."),
                          dict(user_dn=user_dn, group_id=group_id))
        return users

    def check_user_in_group(self, user_id, group_id):
        user_refs = self.list_users_in_group(group_id, driver_hints.Hints())
        for x in user_refs:
            if x['id'] == user_id:
                break
        else:
            # Try to fetch the user to see if it even exists.  This
            # will raise a more accurate exception.
            self.get_user(user_id)
            raise exception.NotFound(_("User '%(user_id)s' not found in"
                                       " group '%(group_id)s'") %
                                     {'user_id': user_id,
                                      'group_id': group_id})


# TODO(termie): turn this into a data object and move logic to driver
class UserApi(common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=Users'
    DEFAULT_STRUCTURAL_CLASSES = ['person']
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_OBJECTCLASS = 'inetOrgPerson'
    NotFound = exception.UserNotFound
    options_name = 'user'
    attribute_options_names = {'password': 'pass',
                               'email': 'mail',
                               'name': 'name',
                               'enabled': 'enabled',
                               'default_project_id': 'default_project_id'}
    immutable_attrs = ['id']

    model = models.User

    def __init__(self, conf):
        super(UserApi, self).__init__(conf)
        self.enabled_mask = conf.ldap.user_enabled_mask
        self.enabled_default = conf.ldap.user_enabled_default
        self.enabled_invert = conf.ldap.user_enabled_invert
        self.enabled_emulation = conf.ldap.user_enabled_emulation

    def _ldap_res_to_model(self, res):
        obj = super(UserApi, self)._ldap_res_to_model(res)
        if self.enabled_mask != 0:
            enabled = int(obj.get('enabled', self.enabled_default))
            obj['enabled'] = ((enabled & self.enabled_mask) !=
                              self.enabled_mask)
        elif self.enabled_invert and not self.enabled_emulation:
            # This could be a bool or a string.  If it's a string,
            # we need to convert it so we can invert it properly.
            enabled = obj.get('enabled', self.enabled_default)
            if isinstance(enabled, six.string_types):
                if enabled.lower() == 'true':
                    enabled = True
                else:
                    enabled = False
            obj['enabled'] = not enabled
        obj['dn'] = res[0]

        return obj

    def mask_enabled_attribute(self, values):
        value = values['enabled']
        values.setdefault('enabled_nomask', int(self.enabled_default))
        if value != ((values['enabled_nomask'] & self.enabled_mask) !=
                     self.enabled_mask):
            values['enabled_nomask'] ^= self.enabled_mask
        values['enabled'] = values['enabled_nomask']
        del values['enabled_nomask']

    def create(self, values):
        if self.enabled_mask:
            orig_enabled = values['enabled']
            self.mask_enabled_attribute(values)
        elif self.enabled_invert and not self.enabled_emulation:
            orig_enabled = values['enabled']
            if orig_enabled is not None:
                values['enabled'] = not orig_enabled
            else:
                values['enabled'] = self.enabled_default
        values = super(UserApi, self).create(values)
        if self.enabled_mask or (self.enabled_invert and
                                 not self.enabled_emulation):
            values['enabled'] = orig_enabled
        return values

    def get_filtered(self, user_id):
        user = self.get(user_id)
        return self.filter_attributes(user)

    def get_all_filtered(self, hints):
        query = self.filter_query(hints)
        return [self.filter_attributes(user) for user in self.get_all(query)]

    def filter_attributes(self, user):
        return identity.filter_user(common_ldap.filter_entity(user))

    def is_user(self, dn):
        """Returns True if the entry is a user."""

        # NOTE(blk-u): It's easy to check if the DN is under the User tree,
        # but may not be accurate. A more accurate test would be to fetch the
        # entry to see if it's got the user objectclass, but this could be
        # really expensive considering how this is used.

        return common_ldap.dn_startswith(dn, self.tree_dn)


class GroupApi(common_ldap.BaseLdap):
    DEFAULT_OU = 'ou=UserGroups'
    DEFAULT_STRUCTURAL_CLASSES = []
    DEFAULT_OBJECTCLASS = 'groupOfNames'
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_MEMBER_ATTRIBUTE = 'member'
    NotFound = exception.GroupNotFound
    options_name = 'group'
    attribute_options_names = {'description': 'desc',
                               'name': 'name'}
    immutable_attrs = ['name']
    model = models.Group

    def _ldap_res_to_model(self, res):
        model = super(GroupApi, self)._ldap_res_to_model(res)
        model['dn'] = res[0]
        return model

    def __init__(self, conf):
        super(GroupApi, self).__init__(conf)
        self.member_attribute = (conf.ldap.group_member_attribute
                                 or self.DEFAULT_MEMBER_ATTRIBUTE)

    def create(self, values):
        data = values.copy()
        if data.get('id') is None:
            data['id'] = uuid.uuid4().hex
        if 'description' in data and data['description'] in ['', None]:
            data.pop('description')
        return super(GroupApi, self).create(data)

    def delete(self, group_id):
        if self.subtree_delete_enabled:
            super(GroupApi, self).deleteTree(group_id)
        else:
            # TODO(spzala): this is only placeholder for group and domain
            # role support which will be added under bug 1101287

            group_ref = self.get(group_id)
            group_dn = group_ref['dn']
            if group_dn:
                self._delete_tree_nodes(group_dn, ldap.SCOPE_ONELEVEL)
            super(GroupApi, self).delete(group_id)

    def update(self, group_id, values):
        old_obj = self.get(group_id)
        return super(GroupApi, self).update(group_id, values, old_obj)

    def add_user(self, user_dn, group_id, user_id):
        group_ref = self.get(group_id)
        group_dn = group_ref['dn']
        try:
            super(GroupApi, self).add_member(user_dn, group_dn)
        except exception.Conflict:
            raise exception.Conflict(_(
                'User %(user_id)s is already a member of group %(group_id)s') %
                {'user_id': user_id, 'group_id': group_id})

    def remove_user(self, user_dn, group_id, user_id):
        group_ref = self.get(group_id)
        group_dn = group_ref['dn']
        try:
            super(GroupApi, self).remove_member(user_dn, group_dn)
        except ldap.NO_SUCH_ATTRIBUTE:
            raise exception.UserNotFound(user_id=user_id)

    def list_user_groups(self, user_dn):
        """Return a list of groups for which the user is a member."""

        user_dn_esc = ldap.filter.escape_filter_chars(user_dn)
        query = '(%s=%s)%s' % (self.member_attribute,
                               user_dn_esc,
                               self.ldap_filter or '')
        return self.get_all(query)

    def list_user_groups_filtered(self, user_dn, hints):
        """Return a filtered list of groups for which the user is a member."""

        user_dn_esc = ldap.filter.escape_filter_chars(user_dn)
        query = '(%s=%s)%s' % (self.member_attribute,
                               user_dn_esc,
                               self.ldap_filter or '')
        return self.get_all_filtered(hints, query)

    def list_group_users(self, group_id):
        """Return a list of user dns which are members of a group."""
        group_ref = self.get(group_id)
        group_dn = group_ref['dn']

        try:
            attrs = self._ldap_get_list(group_dn, ldap.SCOPE_BASE,
                                        attrlist=[self.member_attribute])
        except ldap.NO_SUCH_OBJECT:
            raise self.NotFound(group_id=group_id)

        users = []
        for dn, member in attrs:
            user_dns = member.get(self.member_attribute, [])
            for user_dn in user_dns:
                if self._is_dumb_member(user_dn):
                    continue
                users.append(user_dn)
        return users

    def get_filtered(self, group_id):
        group = self.get(group_id)
        return common_ldap.filter_entity(group)

    def get_filtered_by_name(self, group_name):
        group = self.get_by_name(group_name)
        return common_ldap.filter_entity(group)

    def get_all_filtered(self, hints, query=None):
        query = self.filter_query(hints, query)
        return [common_ldap.filter_entity(group)
                for group in self.get_all(query)]

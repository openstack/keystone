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

from keystone.common import kvs
from keystone.common import utils
from keystone import exception
from keystone import identity
from keystone.openstack.common.gettextutils import _


class _UserIdToDomainId(object):
    """User ID to domain ID mapping.

    Stores the user ID to domain ID mapping so that the domain for a user can
    be looked up quickly.

    """

    def __init__(self, db):
        self.db = db

    def _calc_key(self, user_id):
        """Calculate the key name for the "user ID to domain ID" field."""
        return ('user_domain-%s' % (user_id))

    def notify_user_created(self, user_id, domain_id):
        """Indicates that a user was created."""
        self.db.set(self._calc_key(user_id), domain_id)

    def notify_user_deleted(self, user_id):
        """Indicates that a user was deleted.

        This needs to be called when a user is deleted to keep the database
        clean.

        """
        self.db.delete(self._calc_key(user_id))

    def get(self, user_id):
        """Return the domain ID for a user."""
        return self.db.get(self._calc_key(user_id))


class Identity(kvs.Base, identity.Driver):
    def __init__(self):
        super(Identity, self).__init__()
        self._user_id_to_domain_id = _UserIdToDomainId(self.db)

    def default_assignment_driver(self):
        return "keystone.assignment.backends.kvs.Assignment"

    def is_domain_aware(self):
        return True

    # Public interface
    def authenticate(self, user_id, password):
        user_ref = None
        try:
            user_ref = self._get_user(user_id)
        except exception.UserNotFound:
            raise AssertionError(_('Invalid user / password'))
        if not utils.check_password(password, user_ref.get('password')):
            raise AssertionError(_('Invalid user / password'))
        return identity.filter_user(user_ref)

    def _get_user(self, user_id):
        try:
            return self.db.get('user-%s' % user_id)
        except exception.NotFound:
            raise exception.UserNotFound(user_id=user_id)

    def _calc_user_name_key(self, name, domain_id):
        """Calculate the name of the "user name" key.

        Calculates the name of the key used to store the mapping of user name
        and domain to user ID. This allows quick lookup of the user ID given
        a user name and domain ID.

        """
        return ('user_name-%s-%s' % (domain_id, name))

    def _get_user_by_name(self, user_name, domain_id):
        try:
            return self.db.get(self._calc_user_name_key(user_name, domain_id))
        except exception.NotFound:
            raise exception.UserNotFound(user_id=user_name)

    def get_user(self, user_id):
        return identity.filter_user(self._get_user(user_id))

    def get_user_by_name(self, user_name, domain_id):
        return identity.filter_user(
            self._get_user_by_name(user_name, domain_id))

    def list_users(self, hints):
        user_ids = self.db.get('user_list', [])
        return [self.get_user(x) for x in user_ids]

    # CRUD
    def create_user(self, user_id, user):
        try:
            self.get_user(user_id)
        except exception.UserNotFound:
            pass
        else:
            msg = _('Duplicate ID, %s.') % user_id
            raise exception.Conflict(type='user', details=msg)

        try:
            self.get_user_by_name(user['name'], user['domain_id'])
        except exception.UserNotFound:
            pass
        else:
            msg = _('Duplicate name, %s.') % user['name']
            raise exception.Conflict(type='user', details=msg)

        user = utils.hash_user_password(user)
        new_user = user.copy()

        new_user.setdefault('groups', [])

        self.db.set('user-%s' % user_id, new_user)
        domain_id = user['domain_id']
        user_name_key = self._calc_user_name_key(new_user['name'], domain_id)
        self.db.set(user_name_key, new_user)
        self._user_id_to_domain_id.notify_user_created(user_id, domain_id)
        user_list = set(self.db.get('user_list', []))
        user_list.add(user_id)
        self.db.set('user_list', list(user_list))
        return identity.filter_user(new_user)

    def update_user(self, user_id, user):
        try:
            domain_id = self._user_id_to_domain_id.get(user_id)
        except exception.NotFound:
            raise exception.UserNotFound(user_id=user_id)
        if 'name' in user:
            user_key = self._calc_user_name_key(user['name'], domain_id)
            existing = self.db.get(user_key, False)
            if existing and user_id != existing['id']:
                msg = _('Duplicate name, %s.') % user['name']
                raise exception.Conflict(type='user', details=msg)
        # get the old name and delete it too
        old_user = self.db.get('user-%s' % user_id)
        new_user = old_user.copy()
        user = utils.hash_user_password(user)
        new_user.update(user)
        if new_user['id'] != user_id:
            raise exception.ValidationError('Cannot change user ID')
        self.db.delete(self._calc_user_name_key(old_user['name'], domain_id))
        self.db.set('user-%s' % user_id, new_user)
        user_name_key = self._calc_user_name_key(new_user['name'], domain_id)
        self.db.set(user_name_key, new_user)
        return identity.filter_user(new_user)

    def add_user_to_group(self, user_id, group_id):
        self.get_group(group_id)
        user_ref = self._get_user(user_id)
        groups = set(user_ref.get('groups', []))
        groups.add(group_id)
        self.update_user(user_id, {'groups': list(groups)})

    def check_user_in_group(self, user_id, group_id):
        self.get_group(group_id)
        user_ref = self._get_user(user_id)
        if group_id not in set(user_ref.get('groups', [])):
            raise exception.NotFound(_('User not found in group'))

    def remove_user_from_group(self, user_id, group_id):
        self.get_group(group_id)
        user_ref = self._get_user(user_id)
        groups = set(user_ref.get('groups', []))
        try:
            groups.remove(group_id)
        except KeyError:
            raise exception.NotFound(_('User not found in group'))
        self.update_user(user_id, {'groups': list(groups)})

    def list_users_in_group(self, group_id, hints):
        self.get_group(group_id)
        user_keys = (k for k in self.db.keys() if k.startswith('user-'))
        user_refs = (self.db.get(key) for key in user_keys)
        user_refs_for_group = (ref for ref in user_refs
                               if group_id in ref['groups'])
        return [identity.filter_user(x) for x in user_refs_for_group]

    def list_groups_for_user(self, user_id, hints):
        user_ref = self._get_user(user_id)
        group_ids = user_ref.get('groups', [])
        return [self.get_group(x) for x in group_ids]

    def delete_user(self, user_id):
        try:
            old_user = self.db.get('user-%s' % user_id)
        except exception.NotFound:
            raise exception.UserNotFound(user_id=user_id)
        domain_id = self._user_id_to_domain_id.get(user_id)
        self.db.delete(self._calc_user_name_key(old_user['name'], domain_id))
        self.db.delete('user-%s' % user_id)
        self._user_id_to_domain_id.notify_user_deleted(user_id)
        user_list = set(self.db.get('user_list', []))
        user_list.remove(user_id)
        self.db.set('user_list', list(user_list))

    # group crud

    def create_group(self, group_id, group):
        try:
            return self.db.get('group-%s' % group_id)
        except exception.NotFound:
            pass
        else:
            msg = _('Duplicate ID, %s.') % group_id
            raise exception.Conflict(type='group', details=msg)
        try:
            self.db.get('group_name-%s' % group['name'])
        except exception.NotFound:
            pass
        else:
            msg = _('Duplicate name, %s.') % group['name']
            raise exception.Conflict(type='group', details=msg)

        self.db.set('group-%s' % group_id, group)
        self.db.set('group_name-%s' % group['name'], group)
        group_list = set(self.db.get('group_list', []))
        group_list.add(group_id)
        self.db.set('group_list', list(group_list))
        return group

    def list_groups(self, hints):
        group_ids = self.db.get('group_list', [])
        return [self.get_group(x) for x in group_ids]

    def get_group(self, group_id):
        try:
            return self.db.get('group-%s' % group_id)
        except exception.NotFound:
            raise exception.GroupNotFound(group_id=group_id)

    def update_group(self, group_id, group):
        # First, make sure we are not trying to change the
        # name to one that is already in use
        try:
            self.db.get('group_name-%s' % group['name'])
        except exception.NotFound:
            pass
        else:
            msg = _('Duplicate name, %s.') % group['name']
            raise exception.Conflict(type='group', details=msg)

        # Now, get the old name and delete it
        try:
            old_group = self.db.get('group-%s' % group_id)
        except exception.NotFound:
            raise exception.GroupNotFound(group_id=group_id)
        self.db.delete('group_name-%s' % old_group['name'])

        # Finally, actually do the update
        self.db.set('group-%s' % group_id, group)
        self.db.set('group_name-%s' % group['name'], group)
        return group

    def delete_group(self, group_id):
        try:
            group = self.db.get('group-%s' % group_id)
        except exception.NotFound:
            raise exception.GroupNotFound(group_id=group_id)
        # Delete any entries in the group lists of all users
        user_keys = (k for k in self.db.keys() if k.startswith('user-'))
        user_refs = (self.db.get(key) for key in user_keys)
        for user_ref in user_refs:
            groups = set(user_ref.get('groups', []))
            if group_id in groups:
                groups.remove(group_id)
                self.update_user(user_ref['id'], {'groups': list(groups)})

        # Now delete the group itself
        self.db.delete('group-%s' % group_id)
        self.db.delete('group_name-%s' % group['name'])
        group_list = set(self.db.get('group_list', []))
        group_list.remove(group_id)
        self.db.set('group_list', list(group_list))

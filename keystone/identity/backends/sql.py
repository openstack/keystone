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

import datetime

from oslo_db import api as oslo_db_api
import sqlalchemy

from keystone.common import driver_hints
from keystone.common import password_hashing
from keystone.common import resource_options
from keystone.common import sql
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.identity.backends import base
from keystone.identity.backends import resource_options as options
from keystone.identity.backends import sql_model as model


CONF = keystone.conf.CONF


def _stale_data_exception_checker(exc):
    return isinstance(exc, sqlalchemy.orm.exc.StaleDataError)


class Identity(base.IdentityDriverBase):
    # NOTE(henry-nash): Override the __init__() method so as to take a
    # config parameter to enable sql to be used as a domain-specific driver.
    def __init__(self, conf=None):
        self.conf = conf
        super(Identity, self).__init__()

    @property
    def is_sql(self):
        return True

    def _check_password(self, password, user_ref):
        """Check the specified password against the data store.

        Note that we'll pass in the entire user_ref in case the subclass
        needs things like user_ref.get('name')
        For further justification, please see the follow up suggestion at
        https://blueprints.launchpad.net/keystone/+spec/sql-identiy-pam

        """
        return password_hashing.check_password(password, user_ref.password)

    # Identity interface
    def authenticate(self, user_id, password):
        with sql.session_for_read() as session:
            try:
                user_ref = self._get_user(session, user_id)
                user_dict = base.filter_user(user_ref.to_dict())
            except exception.UserNotFound:
                raise AssertionError(_('Invalid user / password'))
        if self._is_account_locked(user_id, user_ref):
            raise exception.AccountLocked(user_id=user_id)
        elif not self._check_password(password, user_ref):
            self._record_failed_auth(user_id)
            raise AssertionError(_('Invalid user / password'))
        elif not user_ref.enabled:
            raise exception.UserDisabled(user_id=user_id)
        elif user_ref.password_is_expired:
            raise exception.PasswordExpired(user_id=user_id)
        # successful auth, reset failed count if present
        if user_ref.local_user.failed_auth_count:
            self._reset_failed_auth(user_id)
        return user_dict

    def _is_account_locked(self, user_id, user_ref):
        """Check if the user account is locked.

        Checks if the user account is locked based on the number of failed
        authentication attempts.

        :param user_id: The user ID
        :param user_ref: Reference to the user object
        :returns Boolean: True if the account is locked; False otherwise

        """
        ignore_option = user_ref.get_resource_option(
            options.IGNORE_LOCKOUT_ATTEMPT_OPT.option_id)
        if ignore_option and ignore_option.option_value is True:
            return False

        attempts = user_ref.local_user.failed_auth_count or 0
        max_attempts = CONF.security_compliance.lockout_failure_attempts
        lockout_duration = CONF.security_compliance.lockout_duration
        if max_attempts and (attempts >= max_attempts):
            if not lockout_duration:
                return True
            else:
                delta = datetime.timedelta(seconds=lockout_duration)
                last_failure = user_ref.local_user.failed_auth_at
                if (last_failure + delta) > datetime.datetime.utcnow():
                    return True
                else:
                    self._reset_failed_auth(user_id)
        return False

    def _record_failed_auth(self, user_id):
        with sql.session_for_write() as session:
            user_ref = session.query(model.User).get(user_id)
            if not user_ref.local_user.failed_auth_count:
                user_ref.local_user.failed_auth_count = 0
            user_ref.local_user.failed_auth_count += 1
            user_ref.local_user.failed_auth_at = datetime.datetime.utcnow()

    def _reset_failed_auth(self, user_id):
        with sql.session_for_write() as session:
            user_ref = session.query(model.User).get(user_id)
            user_ref.local_user.failed_auth_count = 0
            user_ref.local_user.failed_auth_at = None

    # user crud

    @sql.handle_conflicts(conflict_type='user')
    def create_user(self, user_id, user):
        with sql.session_for_write() as session:
            user_ref = model.User.from_dict(user)
            if self._change_password_required(user_ref):
                user_ref.password_ref.expires_at = datetime.datetime.utcnow()
            user_ref.created_at = datetime.datetime.utcnow()
            session.add(user_ref)
            # Set resource options passed on creation
            resource_options.resource_options_ref_to_mapper(
                user_ref, model.UserOption)
            return base.filter_user(user_ref.to_dict())

    def _change_password_required(self, user):
        if not CONF.security_compliance.change_password_upon_first_use:
            return False
        ignore_option = user.get_resource_option(
            options.IGNORE_CHANGE_PASSWORD_OPT.option_id)
        return not (ignore_option and ignore_option.option_value is True)

    def _create_password_expires_query(self, session, query, hints):
        for filter_ in hints.filters:
            if 'password_expires_at' == filter_['name']:
                # Filter on users who's password expires based on the operator
                # specified in `filter_['comparator']`
                query = query.filter(sqlalchemy.and_(
                    model.LocalUser.id == model.Password.local_user_id,
                    filter_['comparator'](model.Password.expires_at,
                                          filter_['value'])))
        # Removes the `password_expired_at` filters so there are no errors
        # if the call is filtered further. This is because the
        # `password_expires_at` value is not stored in the `User` table but
        # derived from the `Password` table's value `expires_at`.
        hints.filters = [x for x in hints.filters if x['name'] !=
                         'password_expires_at']
        return query, hints

    @staticmethod
    def _apply_limits_to_list(collection, hints):
        if not hints.limit:
            return collection

        return collection[:hints.limit['limit']]

    @driver_hints.truncated
    def list_users(self, hints):
        with sql.session_for_read() as session:
            query = session.query(model.User).outerjoin(model.LocalUser)
            query, hints = self._create_password_expires_query(session, query,
                                                               hints)
            user_refs = sql.filter_limit_query(model.User, query, hints)
            return [base.filter_user(x.to_dict()) for x in user_refs]

    def unset_default_project_id(self, project_id):
        with sql.session_for_write() as session:
            query = session.query(model.User)
            query = query.filter(model.User.default_project_id == project_id)

            for user in query:
                user.default_project_id = None

    def _get_user(self, session, user_id):
        user_ref = session.query(model.User).get(user_id)
        if not user_ref:
            raise exception.UserNotFound(user_id=user_id)
        return user_ref

    def get_user(self, user_id):
        with sql.session_for_read() as session:
            return base.filter_user(
                self._get_user(session, user_id).to_dict())

    def get_user_by_name(self, user_name, domain_id):
        with sql.session_for_read() as session:
            query = session.query(model.User).join(model.LocalUser)
            query = query.filter(sqlalchemy.and_(
                model.LocalUser.name == user_name,
                model.LocalUser.domain_id == domain_id))
            try:
                user_ref = query.one()
            except sql.NotFound:
                raise exception.UserNotFound(user_id=user_name)
            return base.filter_user(user_ref.to_dict())

    @sql.handle_conflicts(conflict_type='user')
    # Explicitly retry on StaleDataErrors, which can happen if two clients
    # update the same user's password and the second client has stale password
    # information.
    @oslo_db_api.wrap_db_retry(exception_checker=_stale_data_exception_checker)
    def update_user(self, user_id, user):
        with sql.session_for_write() as session:
            user_ref = self._get_user(session, user_id)
            old_user_dict = user_ref.to_dict()
            for k in user:
                old_user_dict[k] = user[k]
            new_user = model.User.from_dict(old_user_dict)
            for attr in model.User.attributes:
                if attr not in model.User.readonly_attributes:
                    setattr(user_ref, attr, getattr(new_user, attr))
            # Move the "_resource_options" attribute over to the real user_ref
            # so that resource_options.resource_options_ref_to_mapper can
            # handle the work.
            setattr(user_ref, '_resource_options',
                    getattr(new_user, '_resource_options', {}))

            # Move options into the proper attribute mapper construct
            resource_options.resource_options_ref_to_mapper(
                user_ref, model.UserOption)

            if 'password' in user:
                user_ref.password = user['password']
                if self._change_password_required(user_ref):
                    expires_now = datetime.datetime.utcnow()
                    user_ref.password_ref.expires_at = expires_now

            user_ref.extra = new_user.extra
            return base.filter_user(
                user_ref.to_dict(include_extra_dict=True))

    def _validate_password_history(self, password, user_ref):
        unique_cnt = CONF.security_compliance.unique_last_password_count
        # Validate the new password against the remaining passwords.
        if unique_cnt > 0:
            for password_ref in user_ref.local_user.passwords[-unique_cnt:]:
                if password_hashing.check_password(
                        password, password_ref.password_hash):
                    raise exception.PasswordHistoryValidationError(
                        unique_count=unique_cnt)

    def change_password(self, user_id, new_password):
        with sql.session_for_write() as session:
            user_ref = session.query(model.User).get(user_id)
            lock_pw_opt = user_ref.get_resource_option(
                options.LOCK_PASSWORD_OPT.option_id)
            if lock_pw_opt is not None and lock_pw_opt.option_value is True:
                raise exception.PasswordSelfServiceDisabled()
            if user_ref.password_ref and user_ref.password_ref.self_service:
                self._validate_minimum_password_age(user_ref)
            self._validate_password_history(new_password, user_ref)
            user_ref.password = new_password
            user_ref.password_ref.self_service = True

    def _validate_minimum_password_age(self, user_ref):
        min_age_days = CONF.security_compliance.minimum_password_age
        min_age = (user_ref.password_created_at +
                   datetime.timedelta(days=min_age_days))
        if datetime.datetime.utcnow() < min_age:
            days_left = (min_age - datetime.datetime.utcnow()).days
            raise exception.PasswordAgeValidationError(
                min_age_days=min_age_days, days_left=days_left)

    def add_user_to_group(self, user_id, group_id):
        with sql.session_for_write() as session:
            self.get_group(group_id)
            self.get_user(user_id)
            query = session.query(model.UserGroupMembership)
            query = query.filter_by(user_id=user_id)
            query = query.filter_by(group_id=group_id)
            rv = query.first()
            if rv:
                return

            session.add(model.UserGroupMembership(user_id=user_id,
                                                  group_id=group_id))

    def check_user_in_group(self, user_id, group_id):
        with sql.session_for_read() as session:
            self.get_group(group_id)
            self.get_user(user_id)

            # Note(knikolla): Check for normal group membership
            query = session.query(model.UserGroupMembership)
            query = query.filter_by(user_id=user_id)
            query = query.filter_by(group_id=group_id)
            if query.first():
                return

            # Note(knikolla): Check for expiring group membership
            query = session.query(model.ExpiringUserGroupMembership)
            query = query.filter(
                model.ExpiringUserGroupMembership.user_id == user_id)
            query = query.filter(
                model.ExpiringUserGroupMembership.group_id == group_id)
            active = [q for q in query.all() if not q.expired]
            if active:
                return

            raise exception.NotFound(_("User '%(user_id)s' not found in"
                                       " group '%(group_id)s'") %
                                     {'user_id': user_id,
                                      'group_id': group_id})

    def remove_user_from_group(self, user_id, group_id):
        # We don't check if user or group are still valid and let the remove
        # be tried anyway - in case this is some kind of clean-up operation
        with sql.session_for_write() as session:
            query = session.query(model.UserGroupMembership)
            query = query.filter_by(user_id=user_id)
            query = query.filter_by(group_id=group_id)
            membership_ref = query.first()
            if membership_ref is None:
                # Check if the group and user exist to return descriptive
                # exceptions.
                self.get_group(group_id)
                self.get_user(user_id)
                raise exception.NotFound(_("User '%(user_id)s' not found in"
                                           " group '%(group_id)s'") %
                                         {'user_id': user_id,
                                          'group_id': group_id})
            session.delete(membership_ref)

    def list_groups_for_user(self, user_id, hints):
        def row_to_group_dict(row):
            group = row.group.to_dict()
            group['membership_expires_at'] = row.expires
            return group

        with sql.session_for_read() as session:
            self.get_user(user_id)
            query = session.query(model.Group).join(model.UserGroupMembership)
            query = query.filter(model.UserGroupMembership.user_id == user_id)
            query = sql.filter_limit_query(model.Group, query, hints)
            groups = [g.to_dict() for g in query]

            # Note(knikolla): We must use the ExpiringGroupMembership model
            # so that we can access the expired property.
            query = session.query(model.ExpiringUserGroupMembership)
            query = query.filter(
                model.ExpiringUserGroupMembership.user_id == user_id)
            query = sql.filter_limit_query(
                model.UserGroupMembership, query, hints)
            expiring_groups = [row_to_group_dict(r) for r in query.all()
                               if not r.expired]

            # Note(knikolla): I would have loved to be able to merge the two
            # queries together and use filter_limit_query on the union, but
            # I haven't found a generic way to express expiration in a SQL
            # query, therefore we have to apply the limits here again.
            return self._apply_limits_to_list(groups + expiring_groups, hints)

    def list_users_in_group(self, group_id, hints):
        with sql.session_for_read() as session:
            self.get_group(group_id)
            query = session.query(model.User).outerjoin(model.LocalUser)
            query = query.join(model.UserGroupMembership)
            query = query.filter(
                model.UserGroupMembership.group_id == group_id)
            query, hints = self._create_password_expires_query(session, query,
                                                               hints)
            query = sql.filter_limit_query(model.User, query, hints)
            return [base.filter_user(u.to_dict()) for u in query]

    @oslo_db_api.wrap_db_retry(retry_on_deadlock=True)
    def delete_user(self, user_id):
        with sql.session_for_write() as session:
            ref = self._get_user(session, user_id)

            q = session.query(model.UserGroupMembership)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            session.delete(ref)

    # group crud

    @sql.handle_conflicts(conflict_type='group')
    def create_group(self, group_id, group):
        with sql.session_for_write() as session:
            ref = model.Group.from_dict(group)
            session.add(ref)
            return ref.to_dict()

    @driver_hints.truncated
    def list_groups(self, hints):
        with sql.session_for_read() as session:
            query = session.query(model.Group)
            refs = sql.filter_limit_query(model.Group, query, hints)
            return [ref.to_dict() for ref in refs]

    def _get_group(self, session, group_id):
        ref = session.query(model.Group).get(group_id)
        if not ref:
            raise exception.GroupNotFound(group_id=group_id)
        return ref

    def get_group(self, group_id):
        with sql.session_for_read() as session:
            return self._get_group(session, group_id).to_dict()

    def get_group_by_name(self, group_name, domain_id):
        with sql.session_for_read() as session:
            query = session.query(model.Group)
            query = query.filter_by(name=group_name)
            query = query.filter_by(domain_id=domain_id)
            try:
                group_ref = query.one()
            except sql.NotFound:
                raise exception.GroupNotFound(group_id=group_name)
            return group_ref.to_dict()

    @sql.handle_conflicts(conflict_type='group')
    def update_group(self, group_id, group):
        with sql.session_for_write() as session:
            ref = self._get_group(session, group_id)
            old_dict = ref.to_dict()
            for k in group:
                old_dict[k] = group[k]
            new_group = model.Group.from_dict(old_dict)
            for attr in model.Group.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_group, attr))
            ref.extra = new_group.extra
            return ref.to_dict()

    def delete_group(self, group_id):
        with sql.session_for_write() as session:
            ref = self._get_group(session, group_id)

            q = session.query(model.UserGroupMembership)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            session.delete(ref)

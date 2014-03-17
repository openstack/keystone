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

"""Main entry point into the Identity service."""

import abc
import functools
import os

from oslo.config import cfg
import six

from keystone import clean
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone import notifications
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import importutils
from keystone.openstack.common import log
from keystone.openstack.common import versionutils


CONF = config.CONF

LOG = log.getLogger(__name__)


def moved_to_assignment(f):
    name = f.__name__
    deprecated = versionutils.deprecated(versionutils.deprecated.ICEHOUSE,
                                         what="identity_api." + name,
                                         in_favor_of="assignment_api." + name,
                                         remove_in=+1)
    return deprecated(f)


def filter_user(user_ref):
    """Filter out private items in a user dict.

    'password', 'tenants' and 'groups' are never returned.

    :returns: user_ref

    """
    if user_ref:
        user_ref = user_ref.copy()
        user_ref.pop('password', None)
        user_ref.pop('tenants', None)
        user_ref.pop('groups', None)
        user_ref.pop('domains', None)
        try:
            user_ref['extra'].pop('password', None)
            user_ref['extra'].pop('tenants', None)
        except KeyError:
            pass
    return user_ref


class DomainConfigs(dict):
    """Discover, store and provide access to domain specific configs.

    The setup_domain_drivers() call will be made via the wrapper from
    the first call to any driver function handled by this manager. This
    setup call it will scan the domain config directory for files of the form

    keystone.<domain_name>.conf

    For each file, the domain_name will be turned into a domain_id and then
    this class will:

    - Create a new config structure, adding in the specific additional options
      defined in this config file
    - Initialise a new instance of the required driver with this new config.

    """
    configured = False
    driver = None

    def _load_driver(self, assignment_api, domain_id):
        domain_config = self[domain_id]
        domain_config['driver'] = (
            importutils.import_object(
                domain_config['cfg'].identity.driver, domain_config['cfg']))
        domain_config['driver'].assignment_api = assignment_api

    def _load_config(self, assignment_api, file_list, domain_name):
        try:
            domain_ref = assignment_api.get_domain_by_name(domain_name)
        except exception.DomainNotFound:
            LOG.warning(
                _('Invalid domain name (%s) found in config file name'),
                domain_name)
            return

        # Create a new entry in the domain config dict, which contains
        # a new instance of both the conf environment and driver using
        # options defined in this set of config files.  Later, when we
        # service calls via this Manager, we'll index via this domain
        # config dict to make sure we call the right driver
        domain = domain_ref['id']
        self[domain] = {}
        self[domain]['cfg'] = cfg.ConfigOpts()
        config.configure(conf=self[domain]['cfg'])
        self[domain]['cfg'](args=[], project='keystone',
                            default_config_files=file_list)
        self._load_driver(assignment_api, domain)

    def setup_domain_drivers(self, standard_driver, assignment_api):
        # This is called by the api call wrapper
        self.configured = True
        self.driver = standard_driver

        conf_dir = CONF.identity.domain_config_dir
        if not os.path.exists(conf_dir):
            LOG.warning(_('Unable to locate domain config directory: %s'),
                        conf_dir)
            return

        for r, d, f in os.walk(conf_dir):
            for fname in f:
                if fname.startswith('keystone.') and fname.endswith('.conf'):
                    names = fname.split('.')
                    if len(names) == 3:
                        self._load_config(assignment_api,
                                          [os.path.join(r, fname)],
                                          names[1])
                    else:
                        LOG.debug(_('Ignoring file (%s) while scanning domain '
                                    'config directory'),
                                  fname)

    def get_domain_driver(self, domain_id):
        if domain_id in self:
            return self[domain_id]['driver']

    def get_domain_conf(self, domain_id):
        if domain_id in self:
            return self[domain_id]['cfg']

    def reload_domain_driver(self, assignment_api, domain_id):
        # Only used to support unit tests that want to set
        # new config values.  This should only be called once
        # the domains have been configured, since it relies on
        # the fact that the configuration files have already been
        # read.
        if self.configured:
            if domain_id in self:
                self._load_driver(assignment_api, domain_id)
            else:
                # The standard driver
                self.driver = self.driver()
                self.driver.assignment_api = assignment_api


def domains_configured(f):
    """Wraps API calls to lazy load domain configs after init.

    This is required since the assignment manager needs to be initialized
    before this manager, and yet this manager's init wants to be
    able to make assignment calls (to build the domain configs).  So
    instead, we check if the domains have been initialized on entry
    to each call, and if requires load them,

    """
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        if (not self.domain_configs.configured and
                CONF.identity.domain_specific_drivers_enabled):
            LOG.warning(_(
                'Running an experimental and unsupported configuration '
                '(domain_specific_drivers_enabled = True); '
                'this will result in known issues.'))
            self.domain_configs.setup_domain_drivers(
                self.driver, self.assignment_api)
        return f(self, *args, **kwargs)
    return wrapper


@dependency.provider('identity_api')
@dependency.optional('revoke_api')
@dependency.requires('assignment_api', 'credential_api', 'token_api')
class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    This class also handles the support of domain specific backends, by using
    the DomainConfigs class. The setup call for DomainConfigs is called
    from with the @domains_configured wrapper in a lazy loading fashion
    to get around the fact that we can't satisfy the assignment api it needs
    from within our __init__() function since the assignment driver is not
    itself yet initialized.

    Each of the identity calls are pre-processed here to choose, based on
    domain, which of the drivers should be called. The non-domain-specific
    driver is still in place, and is used if there is no specific driver for
    the domain in question.

    """
    _USER = 'user'
    _GROUP = 'group'

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)
        self.domain_configs = DomainConfigs()

    # Domain ID normalization methods

    def _set_domain_id(self, ref, domain_id):
        if isinstance(ref, dict):
            ref = ref.copy()
            ref['domain_id'] = domain_id
            return ref
        elif isinstance(ref, list):
            return [self._set_domain_id(x, domain_id) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _clear_domain_id(self, ref):
        # Clear the domain_id, and then check to ensure that if this
        # was not the default domain, it is being handled by its own
        # backend driver.
        ref = ref.copy()
        domain_id = ref.pop('domain_id', CONF.identity.default_domain_id)
        if (domain_id != CONF.identity.default_domain_id and
                domain_id not in self.domain_configs):
                    raise exception.DomainNotFound(domain_id=domain_id)
        return ref

    def _normalize_scope(self, domain_scope):
        if domain_scope is None:
            return CONF.identity.default_domain_id
        else:
            return domain_scope

    def _select_identity_driver(self, domain_id):
        driver = self.domain_configs.get_domain_driver(domain_id)
        if driver:
            return driver
        else:
            self.assignment_api.get_domain(domain_id)
            return self.driver

    def _get_domain_id_and_driver(self, domain_scope):
        domain_id = self._normalize_scope(domain_scope)
        driver = self._select_identity_driver(domain_id)
        return (domain_id, driver)

    def _mark_domain_id_filter_satisfied(self, hints):
        if hints:
            for filter in hints.filters():
                if (filter['name'] == 'domain_id' and
                        filter['comparator'] == 'equals'):
                    hints.remove(filter)

    # The actual driver calls - these are pre/post processed here as
    # part of the Manager layer to make sure we:
    #
    # - select the right driver for this domain
    # - clear/set domain_ids for drivers that do not support domains

    @notifications.emit_event('authenticate')
    @domains_configured
    def authenticate(self, context, user_id, password, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        ref = driver.authenticate(user_id, password)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @notifications.created(_USER)
    @domains_configured
    def create_user(self, user_id, user_ref):
        user = user_ref.copy()
        user['name'] = clean.user_name(user['name'])
        user.setdefault('enabled', True)
        user['enabled'] = clean.user_enabled(user['enabled'])

        # For creating a user, the domain is in the object itself
        domain_id = user_ref['domain_id']
        driver = self._select_identity_driver(domain_id)
        if not driver.is_domain_aware():
            user = self._clear_domain_id(user)
        ref = driver.create_user(user_id, user)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @domains_configured
    def get_user(self, user_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        ref = driver.get_user(user_id)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @domains_configured
    def get_user_by_name(self, user_name, domain_id):
        driver = self._select_identity_driver(domain_id)
        ref = driver.get_user_by_name(user_name, domain_id)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @manager.response_truncated
    @domains_configured
    def list_users(self, domain_scope=None, hints=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        if not driver.is_domain_aware():
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_users(hints or driver_hints.Hints())
        if not driver.is_domain_aware():
            ref_list = self._set_domain_id(ref_list, domain_id)
        return ref_list

    @notifications.updated(_USER)
    @domains_configured
    def update_user(self, user_id, user_ref, domain_scope=None):
        user = user_ref.copy()
        if 'name' in user:
            user['name'] = clean.user_name(user['name'])
        if 'enabled' in user:
            user['enabled'] = clean.user_enabled(user['enabled'])

        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        if not driver.is_domain_aware():
            user = self._clear_domain_id(user)
        ref = driver.update_user(user_id, user)
        if user.get('enabled') is False or user.get('password') is not None:
            if self.revoke_api:
                self.revoke_api.revoke_by_user(user_id)
            self.token_api.delete_tokens_for_user(user_id)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @notifications.deleted(_USER)
    @domains_configured
    def delete_user(self, user_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        driver.delete_user(user_id)
        self.credential_api.delete_credentials_for_user(user_id)
        self.token_api.delete_tokens_for_user(user_id)

    @notifications.created(_GROUP)
    @domains_configured
    def create_group(self, group_id, group_ref):
        group = group_ref.copy()
        group.setdefault('description', '')

        # For creating a group, the domain is in the object itself
        domain_id = group_ref['domain_id']
        driver = self._select_identity_driver(domain_id)
        if not driver.is_domain_aware():
            group = self._clear_domain_id(group)
        ref = driver.create_group(group_id, group)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @domains_configured
    def get_group(self, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        ref = driver.get_group(group_id)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @notifications.updated(_GROUP)
    @domains_configured
    def update_group(self, group_id, group, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        if not driver.is_domain_aware():
            group = self._clear_domain_id(group)
        ref = driver.update_group(group_id, group)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    def revoke_tokens_for_group(self, group_id, domain_scope):
        # We get the list of users before we attempt the group
        # deletion, so that we can remove these tokens after we know
        # the group deletion succeeded.

        # TODO(ayoung): revoke based on group and roleids instead
        user_ids = []
        for u in self.list_users_in_group(group_id, domain_scope):
            user_ids.append(u['id'])
            if self.revoke_api:
                self.revoke_api.revoke_by_user(u['id'])
        self.token_api.delete_tokens_for_users(user_ids)

    @notifications.deleted(_GROUP)
    @domains_configured
    def delete_group(self, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        # As well as deleting the group, we need to invalidate
        # any tokens for the users who are members of the group.
        self.revoke_tokens_for_group(group_id, domain_scope)
        driver.delete_group(group_id)

    @domains_configured
    def add_user_to_group(self, user_id, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        driver.add_user_to_group(user_id, group_id)
        self.token_api.delete_tokens_for_user(user_id)

    @domains_configured
    def remove_user_from_group(self, user_id, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        driver.remove_user_from_group(user_id, group_id)
        # TODO(ayoung) revoking all tokens for a user based on group
        # membership is overkill, as we only would need to revoke tokens
        # that had role assignments via the group.  Calculating those
        # assignments would have to be done by the assignment backend.
        if self.revoke_api:
            self.revoke_api.revoke_by_user(user_id)
        self.token_api.delete_tokens_for_user(user_id)

    @manager.response_truncated
    @domains_configured
    def list_groups_for_user(self, user_id, domain_scope=None,
                             hints=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        if not driver.is_domain_aware():
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_groups_for_user(
            user_id, hints or driver_hints.Hints())
        if not driver.is_domain_aware():
            ref_list = self._set_domain_id(ref_list, domain_id)
        return ref_list

    @manager.response_truncated
    @domains_configured
    def list_groups(self, domain_scope=None, hints=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        if not driver.is_domain_aware():
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_groups(hints or driver_hints.Hints())
        if not driver.is_domain_aware():
            ref_list = self._set_domain_id(ref_list, domain_id)
        return ref_list

    @manager.response_truncated
    @domains_configured
    def list_users_in_group(self, group_id, domain_scope=None,
                            hints=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        if not driver.is_domain_aware():
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_users_in_group(
            group_id, hints or driver_hints.Hints())
        if not driver.is_domain_aware():
            ref_list = self._set_domain_id(ref_list, domain_id)
        return ref_list

    @domains_configured
    def check_user_in_group(self, user_id, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        driver.check_user_in_group(user_id, group_id)

    @domains_configured
    def change_password(self, context, user_id, original_password,
                        new_password, domain_scope):

        # authenticate() will raise an AssertionError if authentication fails
        self.authenticate(context, user_id, original_password,
                          domain_scope=domain_scope)

        update_dict = {'password': new_password}
        self.update_user(user_id, update_dict, domain_scope=domain_scope)

    # TODO(morganfainberg): Remove the following deprecated methods once
    # Icehouse is released.  Maintain identity -> assignment proxy for 1
    # release.
    @moved_to_assignment
    def get_domain_by_name(self, domain_name):
        return self.assignment_api.get_domain_by_name(domain_name)

    @moved_to_assignment
    def get_domain(self, domain_id):
        return self.assignment_api.get_domain(domain_id)

    @moved_to_assignment
    def update_domain(self, domain_id, domain):
        return self.assignment_api.update_domain(domain_id, domain)

    @moved_to_assignment
    def list_domains(self, hints=None):
        return self.assignment_api.list_domains(hints=hints)

    @moved_to_assignment
    def delete_domain(self, domain_id):
        return self.assignment_api.delete_domain(domain_id)

    @moved_to_assignment
    def create_domain(self, domain_id, domain):
        return self.assignment_api.create_domain(domain_id, domain)

    @moved_to_assignment
    def list_projects_for_user(self, user_id):
        return self.assignment_api.list_projects_for_user(user_id)

    @moved_to_assignment
    def add_user_to_project(self, tenant_id, user_id):
        return self.assignment_api.add_user_to_project(tenant_id, user_id)

    @moved_to_assignment
    def remove_user_from_project(self, tenant_id, user_id):
        return self.assignment_api.remove_user_from_project(tenant_id, user_id)

    @moved_to_assignment
    def get_project(self, tenant_id):
        return self.assignment_api.get_project(tenant_id)

    @moved_to_assignment
    def list_projects(self, hints=None):
        return self.assignment_api.list_projects(hints=hints)

    @moved_to_assignment
    def get_role(self, role_id):
        return self.assignment_api.get_role(role_id)

    @moved_to_assignment
    def list_roles(self, hints=None):
        return self.assignment_api.list_roles(hints=hints)

    @moved_to_assignment
    def get_project_users(self, tenant_id):
        return self.assignment_api.get_project_users(tenant_id)

    @moved_to_assignment
    def get_roles_for_user_and_project(self, user_id, tenant_id):
        return self.assignment_api.get_roles_for_user_and_project(
            user_id, tenant_id)

    @moved_to_assignment
    def get_roles_for_user_and_domain(self, user_id, domain_id):
        return (self.assignment_api.get_roles_for_user_and_domain
                (user_id, domain_id))

    @moved_to_assignment
    def add_role_to_user_and_project(self, user_id,
                                     tenant_id, role_id):
        return (self.assignment_api.add_role_to_user_and_project
                (user_id, tenant_id, role_id))

    @moved_to_assignment
    def create_role(self, role_id, role):
        return self.assignment_api.create_role(role_id, role)

    @moved_to_assignment
    def delete_role(self, role_id):
        return self.assignment_api.delete_role(role_id)

    @moved_to_assignment
    def remove_role_from_user_and_project(self, user_id,
                                          tenant_id, role_id):
        return (self.assignment_api.remove_role_from_user_and_project
                (user_id, tenant_id, role_id))

    @moved_to_assignment
    def update_role(self, role_id, role):
        return self.assignment_api.update_role(role_id, role)

    @moved_to_assignment
    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        return (self.assignment_api.create_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    @moved_to_assignment
    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        return (self.assignment_api.list_grants
                (user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    @moved_to_assignment
    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        return (self.assignment_api.get_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    @moved_to_assignment
    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        return (self.assignment_api.delete_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an Identity driver."""

    def _get_list_limit(self):
        return CONF.identity.list_limit or CONF.list_limit

    @abc.abstractmethod
    def authenticate(self, user_id, password):
        """Authenticate a given user and password.
        :returns: user_ref
        :raises: AssertionError
        """
        raise exception.NotImplemented()

    # user crud

    @abc.abstractmethod
    def create_user(self, user_id, user):
        """Creates a new user.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_users(self, hints):
        """List users in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_users_in_group(self, group_id, hints):
        """List users in a group.

        :param group_id: the group in question
        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_user(self, user_id):
        """Get a user by ID.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_user(self, user_id, user):
        """Updates an existing user.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def add_user_to_group(self, user_id, group_id):
        """Adds a user to a group.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def check_user_in_group(self, user_id, group_id):
        """Checks if a user is a member of a group.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def remove_user_from_group(self, user_id, group_id):
        """Removes a user from a group.

        :raises: keystone.exception.NotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_user(self, user_id):
        """Deletes an existing user.

        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_user_by_name(self, user_name, domain_id):
        """Get a user by name.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()

    # group crud

    @abc.abstractmethod
    def create_group(self, group_id, group):
        """Creates a new group.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_groups(self, hints):
        """List groups in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_groups_for_user(self, user_id, hints):
        """List groups a user is in

        :param user_id: the user in question
        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_group(self, group_id):
        """Get a group by ID.

        :returns: group_ref
        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_group(self, group_id, group):
        """Updates an existing group.

        :raises: keystone.exceptionGroupNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_group(self, group_id):
        """Deletes an existing group.

        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def is_domain_aware(self):
        """Indicates if Driver supports domains."""
        raise exception.NotImplemented()

    #end of identity

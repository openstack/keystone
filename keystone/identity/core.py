# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
from keystone.common import controller
from keystone.common import dependency
from keystone.common import manager
from keystone.common import utils
from keystone import config
from keystone import exception
from keystone import notifications
from keystone.openstack.common import importutils
from keystone.openstack.common import log as logging


CONF = config.CONF

LOG = logging.getLogger(__name__)


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

    The setup_domain_drives() call will be made via the wrapper from
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

        if domain_ref:
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
@dependency.requires('assignment_api')
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

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)
        self.domain_configs = DomainConfigs()

    @staticmethod
    def v3_to_v2_user(ref):
        """Convert a user_ref from v3 to v2 compatible.

        * v2.0 users are not domain aware, and should have domain_id removed
        * v2.0 users expect the use of tenantId instead of default_project_id

        This method should only be applied to user_refs being returned from the
        v2.0 controller(s).

        If ref is a list type, we will iterate through each element and do the
        conversion.
        """

        def _format_default_project_id(ref):
            """Convert default_project_id to tenantId for v2 calls."""
            default_project_id = ref.pop('default_project_id', None)
            if default_project_id is not None:
                ref['tenantId'] = default_project_id
            elif 'tenantId' in ref:
                # NOTE(morganfainberg): To avoid v2.0 confusion if somehow a
                # tenantId property sneaks its way into the extra blob on the
                # user, we remove it here.  If default_project_id is set, we
                # would override it in either case.
                del ref['tenantId']

        def _normalize_and_filter_user_properties(ref):
            """Run through the various filter/normalization methods."""
            _format_default_project_id(ref)
            controller.V2Controller.filter_domain_id(ref)
            return ref

        if isinstance(ref, dict):
            return _normalize_and_filter_user_properties(ref)
        elif isinstance(ref, list):
            return [_normalize_and_filter_user_properties(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

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

    def _get_domain_conf(self, domain_id):
        conf = self.domain_configs.get_domain_conf(domain_id)
        if conf:
            return conf
        else:
            return CONF

    def _get_domain_id_and_driver(self, domain_scope):
        domain_id = self._normalize_scope(domain_scope)
        driver = self._select_identity_driver(domain_id)
        return (domain_id, driver)

    # The actual driver calls - these are pre/post processed here as
    # part of the Manager layer to make sure we:
    #
    # - select the right driver for this domain
    # - clear/set domain_ids for drivers that do not support domains

    @domains_configured
    def authenticate(self, user_id, password, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        ref = driver.authenticate(user_id, password)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @notifications.created('user')
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

    @domains_configured
    def list_users(self, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        user_list = driver.list_users()
        if not driver.is_domain_aware():
            user_list = self._set_domain_id(user_list, domain_id)
        return user_list

    @notifications.updated('user')
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
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @notifications.deleted('user')
    @domains_configured
    def delete_user(self, user_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        driver.delete_user(user_id)

    @notifications.created('group')
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

    @notifications.updated('group')
    @domains_configured
    def update_group(self, group_id, group, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        if not driver.is_domain_aware():
            group = self._clear_domain_id(group)
        ref = driver.update_group(group_id, group)
        if not driver.is_domain_aware():
            ref = self._set_domain_id(ref, domain_id)
        return ref

    @notifications.deleted('group')
    @domains_configured
    def delete_group(self, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        driver.delete_group(group_id)

    @domains_configured
    def add_user_to_group(self, user_id, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        driver.add_user_to_group(user_id, group_id)

    @domains_configured
    def remove_user_from_group(self, user_id, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        driver.remove_user_from_group(user_id, group_id)

    @domains_configured
    def list_groups_for_user(self, user_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        group_list = driver.list_groups_for_user(user_id)
        if not driver.is_domain_aware():
            group_list = self._set_domain_id(group_list, domain_id)
        return group_list

    @domains_configured
    def list_groups(self, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        group_list = driver.list_groups()
        if not driver.is_domain_aware():
            group_list = self._set_domain_id(group_list, domain_id)
        return group_list

    @domains_configured
    def list_users_in_group(self, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        user_list = driver.list_users_in_group(group_id)
        if not driver.is_domain_aware():
            user_list = self._set_domain_id(user_list, domain_id)
        return user_list

    @domains_configured
    def check_user_in_group(self, user_id, group_id, domain_scope=None):
        domain_id, driver = self._get_domain_id_and_driver(domain_scope)
        return driver.check_user_in_group(user_id, group_id)

    # TODO(morganfainberg): Remove the following deprecated methods once
    # Icehouse is released.  Maintain identity -> assignment proxy for 1
    # release.
    @utils.deprecated('I', in_favor_of='assignment_api.get_domain_by_name',
                      remove_in=1, what='identity_api.get_domain_by_name')
    def get_domain_by_name(self, domain_name):
        return self.assignment_api.get_domain_by_name(domain_name)

    @utils.deprecated('I', in_favor_of='assignment_api.get_domain',
                      remove_in=1, what='identity_api.get_domain')
    def get_domain(self, domain_id):
        return self.assignment_api.get_domain(domain_id)

    @utils.deprecated('I', in_favor_of='assignment_api.update_domain',
                      remove_in=1, what='identity_api.update_domain')
    def update_domain(self, domain_id, domain):
        return self.assignment_api.update_domain(domain_id, domain)

    @utils.deprecated('I', in_favor_of='assignment_api.list_domains',
                      remove_in=1, what='identity_api.list_domains')
    def list_domains(self):
        return self.assignment_api.list_domains()

    @utils.deprecated('I', in_favor_of='assignment_api.delete_domain',
                      remove_in=1, what='identity_api.delete_domain')
    def delete_domain(self, domain_id):
        return self.assignment_api.delete_domain(domain_id)

    @utils.deprecated('I', in_favor_of='assignment_api.create_domain',
                      remove_in=1, what='identity_api.create_domain')
    def create_domain(self, domain_id, domain):
        return self.assignment_api.create_domain(domain_id, domain)

    @utils.deprecated('I', in_favor_of='assignment_api.list_projects_for_user',
                      remove_in=1, what='identity_api.list_projects_for_user')
    def list_projects_for_user(self, user_id):
        return self.assignment_api.list_projects_for_user(user_id)

    @utils.deprecated('I', in_favor_of='assignment_api.add_user_to_project',
                      remove_in=1, what='identity_api.add_user_to_project')
    def add_user_to_project(self, tenant_id, user_id):
        return self.assignment_api.add_user_to_project(tenant_id, user_id)

    @utils.deprecated('I',
                      in_favor_of='assignment_api.remove_user_from_project',
                      remove_in=1,
                      what='identity_api.remove_user_from_project')
    def remove_user_from_project(self, tenant_id, user_id):
        return self.assignment_api.remove_user_from_project(tenant_id, user_id)

    @utils.deprecated('I', in_favor_of='assignment_api.get_project',
                      remove_in=1, what='identity_api.get_project')
    def get_project(self, tenant_id):
        return self.assignment_api.get_project(tenant_id)

    @utils.deprecated('I', in_favor_of='assignment_api.list_projects',
                      remove_in=1, what='identity_api.list_projects')
    def list_projects(self, domain_id=None):
        return self.assignment_api.list_projects(domain_id)

    @utils.deprecated('I', in_favor_of='assignment_api.get_role',
                      remove_in=1, what='identity_api.get_role')
    def get_role(self, role_id):
        return self.assignment_api.get_role(role_id)

    @utils.deprecated('I', in_favor_of='assignment_api.list_roles',
                      remove_in=1, what='identity_api.list_roles')
    def list_roles(self):
        return self.assignment_api.list_roles()

    @utils.deprecated('I', in_favor_of='assignment_api.get_project_users',
                      remove_in=1, what='identity_api.get_project_users')
    def get_project_users(self, tenant_id):
        return self.assignment_api.get_project_users(tenant_id)

    @utils.deprecated('I', in_favor_of='assignment_api.list_projects_for_user',
                      remove_in=1, what='identity_api.list_projects_for_user')
    def get_roles_for_user_and_project(self, user_id, tenant_id):
        return self.assignment_api.get_roles_for_user_and_project(
            user_id, tenant_id)

    @utils.deprecated(
        'I', in_favor_of='assignment_api.get_roles_for_user_and_domain',
        remove_in=1, what='identity_api.get_roles_for_user_and_domain')
    def get_roles_for_user_and_domain(self, user_id, domain_id):
        return (self.assignment_api.get_roles_for_user_and_domain
                (user_id, domain_id))

    @utils.deprecated(
        'I', in_favor_of='assignment_api.add_role_to_user_and_project',
        remove_in=1, what='identity_api.add_role_to_user_and_project')
    def add_role_to_user_and_project(self, user_id,
                                     tenant_id, role_id):
        return (self.assignment_api.add_role_to_user_and_project
                (user_id, tenant_id, role_id))

    @utils.deprecated('I', in_favor_of='assignment_api.create_role',
                      remove_in=1, what='identity_api.create_role')
    def create_role(self, role_id, role):
        return self.assignment_api.create_role(role_id, role)

    @utils.deprecated('I', in_favor_of='assignment_api.delete_role',
                      remove_in=1, what='identity_api.delete_role')
    def delete_role(self, role_id):
        return self.assignment_api.delete_role(role_id)

    @utils.deprecated(
        'I', in_favor_of='assignment_api.remove_role_from_user_and_project',
        remove_in=1, what='identity_api.remove_role_from_user_and_project')
    def remove_role_from_user_and_project(self, user_id,
                                          tenant_id, role_id):
        return (self.assignment_api.remove_role_from_user_and_project
                (user_id, tenant_id, role_id))

    @utils.deprecated('I', in_favor_of='assignment_api.update_role',
                      remove_in=1, what='identity_api.update_role')
    def update_role(self, role_id, role):
        return self.assignment_api.update_role(role_id, role)

    @utils.deprecated('I', in_favor_of='assignment_api.create_grant',
                      remove_in=1, what='identity_api.create_grant')
    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        return (self.assignment_api.create_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    @utils.deprecated('I', in_favor_of='assignment_api.list_grants',
                      remove_in=1, what='identity_api.list_grants')
    def list_grants(self, user_id=None, group_id=None,
                    domain_id=None, project_id=None,
                    inherited_to_projects=False):
        return (self.assignment_api.list_grants
                (user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    @utils.deprecated('I', in_favor_of='assignment_api.get_grant',
                      remove_in=1, what='identity_api.get_grant')
    def get_grant(self, role_id, user_id=None, group_id=None,
                  domain_id=None, project_id=None,
                  inherited_to_projects=False):
        return (self.assignment_api.get_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))

    @utils.deprecated('I', in_favor_of='assignment_api.delete_grant',
                      remove_in=1, what='identity_api.delete_grant')
    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        return (self.assignment_api.delete_grant
                (role_id, user_id, group_id, domain_id, project_id,
                 inherited_to_projects))


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an Identity driver."""

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
    def list_users(self):
        """List all users in the system.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_users_in_group(self, group_id):
        """List all users in a group.

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
    def list_groups(self):
        """List all groups in the system.

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_groups_for_user(self, user_id):
        """List all groups a user is in

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

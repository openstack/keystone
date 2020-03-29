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

import copy
import functools
import itertools
import operator
import os
import threading
import uuid

from oslo_config import cfg
from oslo_log import log
from pycadf import reason

from keystone import assignment  # TODO(lbragstad): Decouple this dependency
from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import provider_api
from keystone.common.validation import validators
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.identity.mapping_backends import mapping
from keystone import notifications
from oslo_utils import timeutils


CONF = keystone.conf.CONF

LOG = log.getLogger(__name__)

PROVIDERS = provider_api.ProviderAPIs

MEMOIZE = cache.get_memoization_decorator(group='identity')

ID_MAPPING_REGION = cache.create_region(name='id mapping')
MEMOIZE_ID_MAPPING = cache.get_memoization_decorator(group='identity',
                                                     region=ID_MAPPING_REGION)

DOMAIN_CONF_FHEAD = 'keystone.'
DOMAIN_CONF_FTAIL = '.conf'

# The number of times we will attempt to register a domain to use the SQL
# driver, if we find that another process is in the middle of registering or
# releasing at the same time as us.
REGISTRATION_ATTEMPTS = 10

# Config Registration Types
SQL_DRIVER = 'SQL'


class DomainConfigs(provider_api.ProviderAPIMixin, dict):
    """Discover, store and provide access to domain specific configs.

    The setup_domain_drivers() call will be made via the wrapper from
    the first call to any driver function handled by this manager.

    Domain specific configurations are only supported for the identity backend
    and the individual configurations are either specified in the resource
    database or in individual domain configuration files, depending on the
    setting of the 'domain_configurations_from_database' config option.

    The result will be that for each domain with a specific configuration,
    this class will hold a reference to a ConfigOpts and driver object that
    the identity manager and driver can use.

    """

    configured = False
    driver = None
    _any_sql = False
    lock = threading.Lock()

    def _load_driver(self, domain_config):
        return manager.load_driver(Manager.driver_namespace,
                                   domain_config['cfg'].identity.driver,
                                   domain_config['cfg'])

    def _load_config_from_file(self, resource_api, file_list, domain_name):

        def _assert_no_more_than_one_sql_driver(new_config, config_file):
            """Ensure there is no more than one sql driver.

            Check to see if the addition of the driver in this new config
            would cause there to be more than one sql driver.

            """
            if (new_config['driver'].is_sql and
                    (self.driver.is_sql or self._any_sql)):
                # The addition of this driver would cause us to have more than
                # one sql driver, so raise an exception.
                raise exception.MultipleSQLDriversInConfig(source=config_file)
            self._any_sql = self._any_sql or new_config['driver'].is_sql

        try:
            domain_ref = resource_api.get_domain_by_name(domain_name)
        except exception.DomainNotFound:
            LOG.warning('Invalid domain name (%s) found in config file name',
                        domain_name)
            return

        # Create a new entry in the domain config dict, which contains
        # a new instance of both the conf environment and driver using
        # options defined in this set of config files.  Later, when we
        # service calls via this Manager, we'll index via this domain
        # config dict to make sure we call the right driver
        domain_config = {}
        domain_config['cfg'] = cfg.ConfigOpts()
        keystone.conf.configure(conf=domain_config['cfg'])
        domain_config['cfg'](args=[], project='keystone',
                             default_config_files=file_list,
                             default_config_dirs=[])
        domain_config['driver'] = self._load_driver(domain_config)
        _assert_no_more_than_one_sql_driver(domain_config, file_list)
        self[domain_ref['id']] = domain_config

    def _setup_domain_drivers_from_files(self, standard_driver, resource_api):
        """Read the domain specific configuration files and load the drivers.

        Domain configuration files are stored in the domain config directory,
        and must be named of the form:

        keystone.<domain_name>.conf

        For each file, call the load config method where the domain_name
        will be turned into a domain_id and then:

        - Create a new config structure, adding in the specific additional
          options defined in this config file
        - Initialise a new instance of the required driver with this new config

        """
        conf_dir = CONF.identity.domain_config_dir
        if not os.path.exists(conf_dir):
            LOG.warning('Unable to locate domain config directory: %s',
                        conf_dir)
            return

        for r, d, f in os.walk(conf_dir):
            for fname in f:
                if (fname.startswith(DOMAIN_CONF_FHEAD) and
                        fname.endswith(DOMAIN_CONF_FTAIL)):
                    if fname.count('.') >= 2:
                        self._load_config_from_file(
                            resource_api, [os.path.join(r, fname)],
                            fname[len(DOMAIN_CONF_FHEAD):
                                  -len(DOMAIN_CONF_FTAIL)])
                    else:
                        LOG.debug(('Ignoring file (%s) while scanning domain '
                                   'config directory'),
                                  fname)

    def _load_config_from_database(self, domain_id, specific_config):

        def _assert_no_more_than_one_sql_driver(domain_id, new_config):
            """Ensure adding driver doesn't push us over the limit of 1.

            The checks we make in this method need to take into account that
            we may be in a multiple process configuration and ensure that
            any race conditions are avoided.

            """
            if not new_config['driver'].is_sql:
                PROVIDERS.domain_config_api.release_registration(domain_id)
                return

            # To ensure the current domain is the only SQL driver, we attempt
            # to register our use of SQL. If we get it we know we are good,
            # if we fail to register it then we should:
            #
            # - First check if another process has registered for SQL for our
            #   domain, in which case we are fine
            # - If a different domain has it, we should check that this domain
            #   is still valid, in case, for example, domain deletion somehow
            #   failed to remove its registration (i.e. we self heal for these
            #   kinds of issues).

            domain_registered = 'Unknown'
            for attempt in range(REGISTRATION_ATTEMPTS):
                if PROVIDERS.domain_config_api.obtain_registration(
                        domain_id, SQL_DRIVER):
                    LOG.debug('Domain %s successfully registered to use the '
                              'SQL driver.', domain_id)
                    return

                # We failed to register our use, let's find out who is using it
                try:
                    domain_registered = (
                        PROVIDERS.domain_config_api.read_registration(
                            SQL_DRIVER))
                except exception.ConfigRegistrationNotFound:
                    msg = ('While attempting to register domain %(domain)s to '
                           'use the SQL driver, another process released it, '
                           'retrying (attempt %(attempt)s).')
                    LOG.debug(msg, {'domain': domain_id,
                                    'attempt': attempt + 1})
                    continue

                if domain_registered == domain_id:
                    # Another process already registered it for us, so we are
                    # fine. In the race condition when another process is
                    # in the middle of deleting this domain, we know the domain
                    # is already disabled and hence telling the caller that we
                    # are registered is benign.
                    LOG.debug('While attempting to register domain %s to use '
                              'the SQL driver, found that another process had '
                              'already registered this domain. This is normal '
                              'in multi-process configurations.', domain_id)
                    return

                # So we don't have it, but someone else does...let's check that
                # this domain is still valid
                try:
                    PROVIDERS.resource_api.get_domain(domain_registered)
                except exception.DomainNotFound:
                    msg = ('While attempting to register domain %(domain)s to '
                           'use the SQL driver, found that it was already '
                           'registered to a domain that no longer exists '
                           '(%(old_domain)s). Removing this stale '
                           'registration and retrying (attempt %(attempt)s).')
                    LOG.debug(msg, {'domain': domain_id,
                                    'old_domain': domain_registered,
                                    'attempt': attempt + 1})
                    PROVIDERS.domain_config_api.release_registration(
                        domain_registered, type=SQL_DRIVER)
                    continue

                # The domain is valid, so we really do have an attempt at more
                # than one SQL driver.
                details = (
                    _('Config API entity at /domains/%s/config') % domain_id)
                raise exception.MultipleSQLDriversInConfig(source=details)

            # We fell out of the loop without either registering our domain or
            # being able to find who has it...either we were very very very
            # unlucky or something is awry.
            msg = _('Exceeded attempts to register domain %(domain)s to use '
                    'the SQL driver, the last domain that appears to have '
                    'had it is %(last_domain)s, giving up') % {
                        'domain': domain_id, 'last_domain': domain_registered}
            raise exception.UnexpectedError(msg)

        domain_config = {}
        domain_config['cfg'] = cfg.ConfigOpts()
        keystone.conf.configure(conf=domain_config['cfg'])
        domain_config['cfg'](args=[], project='keystone',
                             default_config_files=[],
                             default_config_dirs=[])

        # Override any options that have been passed in as specified in the
        # database.
        for group in specific_config:
            for option in specific_config[group]:
                domain_config['cfg'].set_override(
                    option, specific_config[group][option], group)

        domain_config['cfg_overrides'] = specific_config
        domain_config['driver'] = self._load_driver(domain_config)
        _assert_no_more_than_one_sql_driver(domain_id, domain_config)
        self[domain_id] = domain_config

    def _setup_domain_drivers_from_database(self, standard_driver,
                                            resource_api):
        """Read domain specific configuration from database and load drivers.

        Domain configurations are stored in the domain-config backend,
        so we go through each domain to find those that have a specific config
        defined, and for those that do we:

        - Create a new config structure, overriding any specific options
          defined in the resource backend
        - Initialise a new instance of the required driver with this new config

        """
        for domain in resource_api.list_domains():
            domain_config_options = (
                PROVIDERS.domain_config_api.
                get_config_with_sensitive_info(domain['id']))
            if domain_config_options:
                self._load_config_from_database(domain['id'],
                                                domain_config_options)

    def setup_domain_drivers(self, standard_driver, resource_api):
        # This is called by the api call wrapper
        self.driver = standard_driver

        if CONF.identity.domain_configurations_from_database:
            self._setup_domain_drivers_from_database(standard_driver,
                                                     resource_api)
        else:
            self._setup_domain_drivers_from_files(standard_driver,
                                                  resource_api)
        self.configured = True

    def get_domain_driver(self, domain_id):
        self.check_config_and_reload_domain_driver_if_required(domain_id)
        if domain_id in self:
            return self[domain_id]['driver']

    def get_domain_conf(self, domain_id):
        self.check_config_and_reload_domain_driver_if_required(domain_id)
        if domain_id in self:
            return self[domain_id]['cfg']
        else:
            return CONF

    def reload_domain_driver(self, domain_id):
        # Only used to support unit tests that want to set
        # new config values.  This should only be called once
        # the domains have been configured, since it relies on
        # the fact that the configuration files/database have already been
        # read.
        if self.configured:
            if domain_id in self:
                self[domain_id]['driver'] = (
                    self._load_driver(self[domain_id]))
            else:
                # The standard driver
                self.driver = self.driver()

    def check_config_and_reload_domain_driver_if_required(self, domain_id):
        """Check for, and load, any new domain specific config for this domain.

        This is only supported for the database-stored domain specific
        configuration.

        When the domain specific drivers were set up, we stored away the
        specific config for this domain that was available at that time. So we
        now read the current version and compare. While this might seem
        somewhat inefficient, the sensitive config call is cached, so should be
        light weight. More importantly, when the cache timeout is reached, we
        will get any config that has been updated from any other keystone
        process.

        This cache-timeout approach works for both multi-process and
        multi-threaded keystone configurations. In multi-threaded
        configurations, even though we might remove a driver object (that
        could be in use by another thread), this won't actually be thrown away
        until all references to it have been broken. When that other
        thread is released back and is restarted with another command to
        process, next time it accesses the driver it will pickup the new one.

        """
        if (not CONF.identity.domain_specific_drivers_enabled or
                not CONF.identity.domain_configurations_from_database):
            # If specific drivers are not enabled, then there is nothing to do.
            # If we are not storing the configurations in the database, then
            # we'll only re-read the domain specific config files on startup
            # of keystone.
            return

        latest_domain_config = (
            PROVIDERS.domain_config_api.
            get_config_with_sensitive_info(domain_id))
        domain_config_in_use = domain_id in self

        if latest_domain_config:
            if (not domain_config_in_use or
                    latest_domain_config != self[domain_id]['cfg_overrides']):
                self._load_config_from_database(domain_id,
                                                latest_domain_config)
        elif domain_config_in_use:
            # The domain specific config has been deleted, so should remove the
            # specific driver for this domain.
            try:
                del self[domain_id]
            except KeyError:  # nosec
                # Allow this error in case we are unlucky and in a
                # multi-threaded situation, two threads happen to be running
                # in lock step.
                pass
        # If we fall into the else condition, this means there is no domain
        # config set, and there is none in use either, so we have nothing
        # to do.


def domains_configured(f):
    """Wrap API calls to lazy load domain configs after init.

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
            # If domain specific driver has not been configured, acquire the
            # lock and proceed with loading the driver.
            with self.domain_configs.lock:
                # Check again just in case some other thread has already
                # completed domain config.
                if not self.domain_configs.configured:
                    self.domain_configs.setup_domain_drivers(
                        self.driver, PROVIDERS.resource_api)
        return f(self, *args, **kwargs)
    return wrapper


def exception_translated(exception_type):
    """Wrap API calls to map to correct exception."""
    def _exception_translated(f):
        @functools.wraps(f)
        def wrapper(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except exception.PublicIDNotFound as e:
                if exception_type == 'user':
                    raise exception.UserNotFound(user_id=str(e))
                elif exception_type == 'group':
                    raise exception.GroupNotFound(group_id=str(e))
                elif exception_type == 'assertion':
                    raise AssertionError(_('Invalid user / password'))
                else:
                    raise
        return wrapper
    return _exception_translated


@notifications.listener
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
    the domain in question (or we are not using multiple domain drivers).

    Starting with Juno, in order to be able to obtain the domain from
    just an ID being presented as part of an API call, a public ID to domain
    and local ID mapping is maintained.  This mapping also allows for the local
    ID of drivers that do not provide simple UUIDs (such as LDAP) to be
    referenced via a public facing ID.  The mapping itself is automatically
    generated as entities are accessed via the driver.

    This mapping is only used when:
    - the entity is being handled by anything other than the default driver, or
    - the entity is being handled by the default LDAP driver and backward
    compatible IDs are not required.

    This means that in the standard case of a single SQL backend or the default
    settings of a single LDAP backend (since backward compatible IDs is set to
    True by default), no mapping is used. An alternative approach would be to
    always use the mapping table, but in the cases where we don't need it to
    make the public and local IDs the same. It is felt that not using the
    mapping by default is a more prudent way to introduce this functionality.

    """

    driver_namespace = 'keystone.identity'
    _provides_api = 'identity_api'

    _USER = 'user'
    _GROUP = 'group'

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)
        self.domain_configs = DomainConfigs()
        notifications.register_event_callback(
            notifications.ACTIONS.internal, notifications.DOMAIN_DELETED,
            self._domain_deleted
        )
        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'project': [self._unset_default_project],
            },
        }

    def _domain_deleted(self, service, resource_type, operation,
                        payload):
        domain_id = payload['resource_info']

        driver = self._select_identity_driver(domain_id)

        if driver.is_sql:
            group_refs = self.list_groups(domain_scope=domain_id)
            for group in group_refs:
                # Cleanup any existing groups.
                try:
                    self.delete_group(group['id'])
                except exception.GroupNotFound:
                    LOG.debug(('Group %(groupid)s not found when deleting '
                               'domain contents for %(domainid)s, continuing '
                               'with cleanup.'),
                              {'groupid': group['id'], 'domainid': domain_id})

        # And finally, delete the users themselves
        user_refs = self.list_users(domain_scope=domain_id)

        for user in user_refs:
            try:
                if not driver.is_sql:
                    PROVIDERS.shadow_users_api.delete_user(user['id'])
                else:
                    self.delete_user(user['id'])
            except exception.UserNotFound:
                LOG.debug(('User %(userid)s not found when deleting domain '
                           'contents for %(domainid)s, continuing with '
                           'cleanup.'),
                          {'userid': user['id'], 'domainid': domain_id})

    def _unset_default_project(self, service, resource_type, operation,
                               payload):
        """Callback, clears user default_project_id after project deletion.

        Notifications are used to unset a user's default project because
        there is no foreign key to the project. Projects can be in a non-SQL
        backend, making FKs impossible.

        """
        project_id = payload['resource_info']
        drivers = itertools.chain(
            self.domain_configs.values(), [{'driver': self.driver}]
        )
        for d in drivers:
            try:
                d['driver'].unset_default_project_id(project_id)
            except exception.Forbidden:
                # NOTE(lbragstad): If the driver throws a Forbidden, it's
                # because the driver doesn't support writes. This is the case
                # with the in-tree LDAP implementation since it is read-only.
                # This also ensures consistency for out-of-tree backends that
                # might be read-only.
                pass

    # Domain ID normalization methods
    def _set_domain_id_and_mapping(self, ref, domain_id, driver,
                                   entity_type):
        """Patch the domain_id/public_id into the resulting entity(ies).

        :param ref: the entity or list of entities to post process
        :param domain_id: the domain scope used for the call
        :param driver: the driver used to execute the call
        :param entity_type: whether this is a user or group

        :returns: post processed entity or list or entities

        Called to post-process the entity being returned, using a mapping
        to substitute a public facing ID as necessary. This method must
        take into account:

        - If the driver is not domain aware, then we must set the domain
          attribute of all entities irrespective of mapping.
        - If the driver does not support UUIDs, then we always want to provide
          a mapping, except for the special case of this being the default
          driver and backward_compatible_ids is set to True. This is to ensure
          that entity IDs do not change for an existing LDAP installation (only
          single domain/driver LDAP configurations were previously supported).
        - If the driver does support UUIDs, then we always create a mapping
          entry, but use the local UUID as the public ID.  The exception to
          this is that if we just have single driver (i.e. not using specific
          multi-domain configs), then we don't bother with the mapping at all.

        """
        conf = CONF.identity

        if not self._needs_post_processing(driver):
            # a classic case would be when running with a single SQL driver
            return ref

        LOG.debug('ID Mapping - Domain ID: %(domain)s, '
                  'Default Driver: %(driver)s, '
                  'Domains: %(aware)s, UUIDs: %(generate)s, '
                  'Compatible IDs: %(compat)s',
                  {'domain': domain_id,
                   'driver': (driver == self.driver),
                   'aware': driver.is_domain_aware(),
                   'generate': driver.generates_uuids(),
                   'compat': CONF.identity_mapping.backward_compatible_ids})

        if isinstance(ref, dict):
            return self._set_domain_id_and_mapping_for_single_ref(
                ref, domain_id, driver, entity_type, conf)
        elif isinstance(ref, list):
            return self._set_domain_id_and_mapping_for_list(
                ref, domain_id, driver, entity_type, conf)
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _needs_post_processing(self, driver):
        """Return whether entity from driver needs domain added or mapping."""
        return (driver is not self.driver or not driver.generates_uuids() or
                not driver.is_domain_aware())

    def _insert_new_public_id(self, local_entity, ref, driver):
        # Need to create a mapping. If the driver generates UUIDs
        # then pass the local UUID in as the public ID to use.
        public_id = None
        if driver.generates_uuids():
            public_id = ref['id']
        ref['id'] = PROVIDERS.id_mapping_api.create_id_mapping(
            local_entity, public_id)
        LOG.debug('Created new mapping to public ID: %s', ref['id'])

    def _set_domain_id_and_mapping_for_single_ref(self, ref, domain_id,
                                                  driver, entity_type, conf):
        LOG.debug('Local ID: %s', ref['id'])
        ref = ref.copy()

        if not driver.is_domain_aware():
            if not domain_id:
                domain_id = CONF.identity.default_domain_id
            ref['domain_id'] = domain_id

        if self._is_mapping_needed(driver):
            local_entity = {'domain_id': ref['domain_id'],
                            'local_id': ref['id'],
                            'entity_type': entity_type}
            public_id = PROVIDERS.id_mapping_api.get_public_id(local_entity)
            if public_id:
                ref['id'] = public_id
                LOG.debug('Found existing mapping to public ID: %s',
                          ref['id'])
            else:
                self._insert_new_public_id(local_entity, ref, driver)
        return ref

    def _set_domain_id_and_mapping_for_list(self, ref_list, domain_id, driver,
                                            entity_type, conf):
        """Set domain id and mapping for a list of refs.

        The method modifies refs in-place.
        """
        if not ref_list:
            return []

        # If the domain_id is None that means we are running in a single
        # backend mode, so to remain backwards compatible we will use the
        # default domain ID.
        if not domain_id:
            domain_id = CONF.identity.default_domain_id

        if not driver.is_domain_aware():
            for ref in ref_list:
                ref['domain_id'] = domain_id

        if not self._is_mapping_needed(driver):
            return ref_list

        # build a map of refs for fast look-up
        refs_map = {}
        for r in ref_list:
            refs_map[(r['id'], entity_type, r['domain_id'])] = r

        # fetch all mappings for the domain, lookup the user at the map built
        # at previous step and replace his id.
        domain_mappings = PROVIDERS.id_mapping_api.get_domain_mapping_list(
            domain_id, entity_type=entity_type)
        for _mapping in domain_mappings:
            idx = (_mapping.local_id, _mapping.entity_type, _mapping.domain_id)
            try:
                ref = refs_map.pop(idx)
                # due to python specifics, `ref` still points to an item in
                # `ref_list`. That's why when we change it here, it gets
                # changed in `ref_list`.
                ref['id'] = _mapping.public_id
            except KeyError:
                pass  # some old entry, skip it

        # at this point, all known refs were granted a public_id. For the refs
        # left, there are no mappings. They need to be created.
        for ref in refs_map.values():
            local_entity = {'domain_id': ref['domain_id'],
                            'local_id': ref['id'],
                            'entity_type': entity_type}
            self._insert_new_public_id(local_entity, ref, driver)
        return ref_list

    def _is_mapping_needed(self, driver):
        """Return whether mapping is needed.

        There are two situations where we must use the mapping:
        - this isn't the default driver (i.e. multiple backends), or
        - we have a single backend that doesn't use UUIDs
        The exception to the above is that we must honor backward
        compatibility if this is the default driver (e.g. to support
        current LDAP)
        """
        is_not_default_driver = driver is not self.driver
        return (is_not_default_driver or (
            not driver.generates_uuids() and
            not CONF.identity_mapping.backward_compatible_ids))

    def _clear_domain_id_if_domain_unaware(self, driver, ref):
        """Clear domain_id details if driver is not domain aware."""
        if not driver.is_domain_aware() and 'domain_id' in ref:
            ref = ref.copy()
            ref.pop('domain_id')
        return ref

    def _select_identity_driver(self, domain_id):
        """Choose a backend driver for the given domain_id.

        :param domain_id: The domain_id for which we want to find a driver.  If
                          the domain_id is specified as None, then this means
                          we need a driver that handles multiple domains.

        :returns: chosen backend driver

        If there is a specific driver defined for this domain then choose it.
        If the domain is None, or there no specific backend for the given
        domain is found, then we chose the default driver.

        """
        if domain_id is None:
            driver = self.driver
        else:
            driver = (self.domain_configs.get_domain_driver(domain_id) or
                      self.driver)

        # If the driver is not domain aware (e.g. LDAP) then check to
        # ensure we are not mapping multiple domains onto it - the only way
        # that would happen is that the default driver is LDAP and the
        # domain is anything other than None or the default domain.
        if (not driver.is_domain_aware() and driver == self.driver and
            domain_id != CONF.identity.default_domain_id and
                domain_id is not None):
            LOG.warning('Found multiple domains being mapped to a '
                        'driver that does not support that (e.g. '
                        'LDAP) - Domain ID: %(domain)s, '
                        'Default Driver: %(driver)s',
                        {'domain': domain_id,
                         'driver': (driver == self.driver)})
            raise exception.DomainNotFound(domain_id=domain_id)
        return driver

    def _get_domain_driver_and_entity_id(self, public_id):
        """Look up details using the public ID.

        :param public_id: the ID provided in the call

        :returns: domain_id, which can be None to indicate that the driver
                  in question supports multiple domains
                  driver selected based on this domain
                  entity_id which will is understood by the driver.

        Use the mapping table to look up the domain, driver and local entity
        that is represented by the provided public ID.  Handle the situations
        where we do not use the mapping (e.g. single driver that understands
        UUIDs etc.)

        """
        conf = CONF.identity
        # First, since we don't know anything about the entity yet, we must
        # assume it needs mapping, so long as we are using domain specific
        # drivers.
        if conf.domain_specific_drivers_enabled:
            local_id_ref = PROVIDERS.id_mapping_api.get_id_mapping(public_id)
            if local_id_ref:
                return (
                    local_id_ref['domain_id'],
                    self._select_identity_driver(local_id_ref['domain_id']),
                    local_id_ref['local_id'])

        # So either we are using multiple drivers but the public ID is invalid
        # (and hence was not found in the mapping table), or the public ID is
        # being handled by the default driver.  Either way, the only place left
        # to look is in that standard driver. However, we don't yet know if
        # this driver also needs mapping (e.g. LDAP in non backward
        # compatibility mode).
        driver = self.driver
        if driver.generates_uuids():
            if driver.is_domain_aware:
                # No mapping required, and the driver can handle the domain
                # information itself.  The classic case of this is the
                # current SQL driver.
                return (None, driver, public_id)
            else:
                # Although we don't have any drivers of this type, i.e. that
                # understand UUIDs but not domains, conceptually you could.
                return (conf.default_domain_id, driver, public_id)

        # So the only place left to find the ID is in the default driver which
        # we now know doesn't generate UUIDs
        if not CONF.identity_mapping.backward_compatible_ids:
            # We are not running in backward compatibility mode, so we
            # must use a mapping.
            local_id_ref = PROVIDERS.id_mapping_api.get_id_mapping(public_id)
            if local_id_ref:
                return (
                    local_id_ref['domain_id'],
                    driver,
                    local_id_ref['local_id'])
            else:
                raise exception.PublicIDNotFound(id=public_id)

        # If we reach here, this means that the default driver
        # requires no mapping - but also doesn't understand domains
        # (e.g. the classic single LDAP driver situation). Hence we pass
        # back the public_ID unmodified and use the default domain (to
        # keep backwards compatibility with existing installations).
        #
        # It is still possible that the public ID is just invalid in
        # which case we leave this to the caller to check.
        return (conf.default_domain_id, driver, public_id)

    def _assert_user_and_group_in_same_backend(
            self, user_entity_id, user_driver, group_entity_id, group_driver):
        """Ensure that user and group IDs are backed by the same backend.

        Raise a CrossBackendNotAllowed exception if they are not from the same
        backend, otherwise return None.

        """
        if user_driver is not group_driver:
            # Determine first if either IDs don't exist by calling
            # the driver.get methods (which will raise a NotFound
            # exception).
            user_driver.get_user(user_entity_id)
            group_driver.get_group(group_entity_id)
            # If we get here, then someone is attempting to create a cross
            # backend membership, which is not allowed.
            raise exception.CrossBackendNotAllowed(group_id=group_entity_id,
                                                   user_id=user_entity_id)

    def _mark_domain_id_filter_satisfied(self, hints):
        if hints:
            for filter in hints.filters:
                if (filter['name'] == 'domain_id' and
                        filter['comparator'] == 'equals'):
                    hints.filters.remove(filter)

    def _ensure_domain_id_in_hints(self, hints, domain_id):
        if (domain_id is not None and
                not hints.get_exact_filter_by_name('domain_id')):
            hints.add_filter('domain_id', domain_id)

    def _set_list_limit_in_hints(self, hints, driver):
        """Set list limit in hints from driver.

        If a hints list is provided, the wrapper will insert the relevant
        limit into the hints so that the underlying driver call can try and
        honor it. If the driver does truncate the response, it will update the
        'truncated' attribute in the 'limit' entry in the hints list, which
        enables the caller of this function to know if truncation has taken
        place. If, however, the driver layer is unable to perform truncation,
        the 'limit' entry is simply left in the hints list for the caller to
        handle.

        A _get_list_limit() method is required to be present in the object
        class hierarchy, which returns the limit for this backend to which
        we will truncate.

        If a hints list is not provided in the arguments of the wrapped call
        then any limits set in the config file are ignored.  This allows
        internal use of such wrapped methods where the entire data set is
        needed as input for the calculations of some other API (e.g. get role
        assignments for a given project).

        This method, specific to identity manager, is used instead of more
        general response_truncated, because the limit for identity entities
        can be overridden in domain-specific config files. The driver to use
        is determined during processing of the passed parameters and
        response_truncated is designed to set the limit before any processing.
        """
        if hints is None:
            return

        list_limit = driver._get_list_limit()
        if list_limit:
            hints.set_limit(list_limit)

    # The actual driver calls - these are pre/post processed here as
    # part of the Manager layer to make sure we:
    #
    # - select the right driver for this domain
    # - clear/set domain_ids for drivers that do not support domains
    # - create any ID mapping that might be required
    @notifications.emit_event('authenticate')
    @domains_configured
    @exception_translated('assertion')
    def authenticate(self, user_id, password):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        ref = driver.authenticate(entity_id, password)
        ref = self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)
        ref = self._shadow_nonlocal_user(ref)
        PROVIDERS.shadow_users_api.set_last_active_at(ref['id'])
        return ref

    def _assert_default_project_id_is_not_domain(self, default_project_id):
        if default_project_id:
            # make sure project is not a domain
            try:
                project_ref = PROVIDERS.resource_api.get_project(
                    default_project_id
                )
                if project_ref['is_domain'] is True:
                    msg = _("User's default project ID cannot be a "
                            "domain ID: %s")
                    raise exception.ValidationError(
                        message=(msg % default_project_id))
            except exception.ProjectNotFound:
                # should be idempotent if project is not found so that it is
                # backward compatible
                pass

    def _validate_federated_objects(self, fed_obj_list):
        # Validate that the ipd and protocols exist
        for fed_obj in fed_obj_list:
            try:
                self.federation_api.get_idp(fed_obj['idp_id'])
            except exception.IdentityProviderNotFound:
                msg = (_("Could not find Identity Provider: %s")
                       % fed_obj['idp_id'])
                raise exception.ValidationError(msg)
            for protocol in fed_obj['protocols']:
                try:
                    self.federation_api.get_protocol(fed_obj['idp_id'],
                                                     protocol['protocol_id'])
                except exception.FederatedProtocolNotFound:
                    msg = (_("Could not find federated protocol "
                             "%(protocol)s for Identity Provider: %(idp)s.")
                           % {'protocol': protocol['protocol_id'],
                              'idp': fed_obj['idp_id']})
                    raise exception.ValidationError(msg)

    def _create_federated_objects(self, user_ref, fed_obj_list):
        for fed_obj in fed_obj_list:
            for protocols in fed_obj['protocols']:
                federated_dict = {
                    'user_id': user_ref['id'],
                    'idp_id': fed_obj['idp_id'],
                    'protocol_id': protocols['protocol_id'],
                    'unique_id': protocols['unique_id'],
                    'display_name': user_ref['name']
                }
                self.shadow_users_api.create_federated_object(
                    federated_dict)

    def _create_user_with_federated_objects(self, user, driver):
        # If the user did not pass a federated object along inside the user
        # object then we simply create the user as normal.
        if not user.get('federated'):
            if 'federated' in user:
                del user['federated']
            user = driver.create_user(user['id'], user)
            return user
        # Otherwise, validate the federated object and create the user.
        else:
            user_ref = user.copy()
            del user['federated']
            self._validate_federated_objects(user_ref['federated'])
            user = driver.create_user(user['id'], user)
            self._create_federated_objects(user_ref, user_ref['federated'])
            user['federated'] = user_ref['federated']
            return user

    @domains_configured
    @exception_translated('user')
    def create_user(self, user_ref, initiator=None):
        user = user_ref.copy()
        if 'password' in user:
            validators.validate_password(user['password'])
        user['name'] = user['name'].strip()
        user.setdefault('enabled', True)
        domain_id = user['domain_id']
        PROVIDERS.resource_api.get_domain(domain_id)

        self._assert_default_project_id_is_not_domain(
            user_ref.get('default_project_id'))

        # For creating a user, the domain is in the object itself
        domain_id = user_ref['domain_id']
        driver = self._select_identity_driver(domain_id)
        user = self._clear_domain_id_if_domain_unaware(driver, user)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        user['id'] = uuid.uuid4().hex
        ref = self._create_user_with_federated_objects(user, driver)
        notifications.Audit.created(self._USER, user['id'], initiator)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @domains_configured
    @exception_translated('user')
    @MEMOIZE
    def get_user(self, user_id):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        ref = driver.get_user(entity_id)
        # Add user's federated objects
        fed_objects = self.shadow_users_api.get_federated_objects(user_id)
        if fed_objects:
            ref['federated'] = fed_objects
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    def assert_user_enabled(self, user_id, user=None):
        """Assert the user and the user's domain are enabled.

        :raise AssertionError if the user or the user's domain is disabled.
        """
        if user is None:
            user = self.get_user(user_id)
        PROVIDERS.resource_api.assert_domain_enabled(user['domain_id'])
        if not user.get('enabled', True):
            raise AssertionError(_('User is disabled: %s') % user_id)

    @domains_configured
    @exception_translated('user')
    @MEMOIZE
    def get_user_by_name(self, user_name, domain_id):
        driver = self._select_identity_driver(domain_id)
        ref = driver.get_user_by_name(user_name, domain_id)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    def _translate_expired_password_hints(self, hints):
        """Clean Up Expired Password Hints.

        Any `password_expires_at` filters on the `list_users` or
        `list_users_in_group` queries are modified so the call will
        return valid data.

        The filters `comparator` is changed to the operator specified in
        the call, otherwise it is assumed to be `equals`. The filters
        `value` becomes the timestamp specified. Both the operator and
        timestamp are validated, and will raise a InvalidOperatorError
        or ValidationTimeStampError exception respectively if invalid.

        """
        operators = {'lt': operator.lt, 'gt': operator.gt,
                     'eq': operator.eq, 'lte': operator.le,
                     'gte': operator.ge, 'neq': operator.ne}
        for filter_ in hints.filters:
            if 'password_expires_at' == filter_['name']:
                # password_expires_at must be in the format
                # 'lt:2016-11-06T15:32:17Z'. So we can assume the position
                # of the ':' otherwise assign the operator to equals.
                if ':' in filter_['value'][2:4]:
                    op, timestamp = filter_['value'].split(':', 1)
                else:
                    op = 'eq'
                    timestamp = filter_['value']

                try:
                    filter_['value'] = timeutils.parse_isotime(timestamp)
                except ValueError:
                    raise exception.ValidationTimeStampError

                try:
                    filter_['comparator'] = operators[op]
                except KeyError:
                    raise exception.InvalidOperatorError(_op=op)
        return hints

    def _handle_shadow_and_local_users(self, driver, hints):
        federated_attributes = {'idp_id', 'protocol_id', 'unique_id'}
        fed_res = []
        for filter_ in hints.filters:
            if filter_['name'] in federated_attributes:
                return PROVIDERS.shadow_users_api.get_federated_users(hints)
            # Note: If the filters contain 'name', we should get the user from
            # both local user and shadow user backend.
            if filter_['name'] == 'name':
                fed_hints = copy.deepcopy(hints)
                fed_res = PROVIDERS.shadow_users_api.get_federated_users(
                    fed_hints)
                break
        return driver.list_users(hints) + fed_res

    @domains_configured
    @exception_translated('user')
    def list_users(self, domain_scope=None, hints=None):
        driver = self._select_identity_driver(domain_scope)
        self._set_list_limit_in_hints(hints, driver)
        hints = hints or driver_hints.Hints()
        if driver.is_domain_aware():
            # Force the domain_scope into the hint to ensure that we only get
            # back domains for that scope.
            self._ensure_domain_id_in_hints(hints, domain_scope)
        else:
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter.
            self._mark_domain_id_filter_satisfied(hints)
        hints = self._translate_expired_password_hints(hints)
        ref_list = self._handle_shadow_and_local_users(driver, hints)
        return self._set_domain_id_and_mapping(
            ref_list, domain_scope, driver, mapping.EntityType.USER)

    def _require_matching_domain_id(self, new_ref, orig_ref):
        """Ensure the current domain ID matches the reference one, if any.

        Provided we want domain IDs to be immutable, check whether any
        domain_id specified in the ref dictionary matches the existing
        domain_id for this entity.

        :param new_ref: the dictionary of new values proposed for this entity
        :param orig_ref: the dictionary of original values proposed for this
                         entity
        :raises: :class:`keystone.exception.ValidationError`
        """
        if 'domain_id' in new_ref:
            if new_ref['domain_id'] != orig_ref['domain_id']:
                raise exception.ValidationError(_('Cannot change Domain ID'))

    def _update_user_with_federated_objects(self, user, driver, entity_id):
        # If the user did not pass a federated object along inside the user
        # object then we simply update the user as normal and add the
        # currently associated federated objects to user to be added to the
        # dictionary.
        if not user.get('federated'):
            if 'federated' in user:
                del user['federated']
            user = driver.update_user(entity_id, user)
            fed_objects = self.shadow_users_api.get_federated_objects(
                user['id'])
            if fed_objects:
                user['federated'] = fed_objects
            return user
        # Otherwise, we validate, remove the previous user's federated objects,
        # and update the user along with their updated federated objects.
        else:
            user_ref = user.copy()
            self._validate_federated_objects(user_ref['federated'])
            self.shadow_users_api.delete_federated_object(entity_id)
            del user['federated']
            user = driver.update_user(entity_id, user)
            self._create_federated_objects(user, user_ref['federated'])
            user['federated'] = user_ref['federated']
            return user

    @domains_configured
    @exception_translated('user')
    def update_user(self, user_id, user_ref, initiator=None):
        old_user_ref = self.get_user(user_id)
        user = user_ref.copy()
        self._require_matching_domain_id(user, old_user_ref)
        if 'password' in user:
            validators.validate_password(user['password'])
        if 'name' in user:
            user['name'] = user['name'].strip()
        if 'id' in user:
            if user_id != user['id']:
                raise exception.ValidationError(_('Cannot change user ID'))
            # Since any ID in the user dict is now irrelevant, remove its so as
            # the driver layer won't be confused by the fact the this is the
            # public ID not the local ID
            user.pop('id')

        self._assert_default_project_id_is_not_domain(
            user_ref.get('default_project_id'))

        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        user = self._clear_domain_id_if_domain_unaware(driver, user)
        self.get_user.invalidate(self, old_user_ref['id'])
        self.get_user_by_name.invalidate(self, old_user_ref['name'],
                                         old_user_ref['domain_id'])

        ref = self._update_user_with_federated_objects(user, driver, entity_id)

        notifications.Audit.updated(self._USER, user_id, initiator)

        enabled_change = ((user.get('enabled') is False) and
                          user['enabled'] != old_user_ref.get('enabled'))
        if enabled_change or user.get('password') is not None:
            self._persist_revocation_event_for_user(user_id)
            reason = (
                'Invalidating the token cache because user %(user_id)s was '
                'enabled or disabled. Authorization will be calculated and '
                'enforced accordingly the next time they authenticate or '
                'validate a token.' % {'user_id': user_id}
            )
            notifications.invalidate_token_cache_notification(reason)

        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER)

    @domains_configured
    @exception_translated('user')
    def delete_user(self, user_id, initiator=None):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        # Get user details to invalidate the cache.
        user_old = self.get_user(user_id)

        hints = driver_hints.Hints()
        hints.add_filter('user_id', user_id)
        fed_users = PROVIDERS.shadow_users_api.list_federated_users_info(hints)

        driver.delete_user(entity_id)
        PROVIDERS.assignment_api.delete_user_assignments(user_id)
        self.get_user.invalidate(self, user_id)
        self.get_user_by_name.invalidate(self, user_old['name'],
                                         user_old['domain_id'])
        for fed_user in fed_users:
            self._shadow_federated_user.invalidate(
                self, fed_user['idp_id'], fed_user['protocol_id'],
                fed_user['unique_id'], fed_user['display_name'],
                user_old.get('extra', {}).get('email'))

        PROVIDERS.credential_api.delete_credentials_for_user(user_id)
        PROVIDERS.id_mapping_api.delete_id_mapping(user_id)
        notifications.Audit.deleted(self._USER, user_id, initiator)

        # Invalidate user role assignments cache region, as it may be caching
        # role assignments where the actor is the specified user
        assignment.COMPUTED_ASSIGNMENTS_REGION.invalidate()

    @domains_configured
    @exception_translated('group')
    def create_group(self, group_ref, initiator=None):
        group = group_ref.copy()
        group.setdefault('description', '')
        domain_id = group['domain_id']
        PROVIDERS.resource_api.get_domain(domain_id)

        # For creating a group, the domain is in the object itself
        domain_id = group_ref['domain_id']
        driver = self._select_identity_driver(domain_id)
        group = self._clear_domain_id_if_domain_unaware(driver, group)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        group['id'] = uuid.uuid4().hex
        group['name'] = group['name'].strip()
        ref = driver.create_group(group['id'], group)

        notifications.Audit.created(self._GROUP, group['id'], initiator)

        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.GROUP)

    @domains_configured
    @exception_translated('group')
    @MEMOIZE
    def get_group(self, group_id):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        ref = driver.get_group(entity_id)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.GROUP)

    @domains_configured
    @exception_translated('group')
    def get_group_by_name(self, group_name, domain_id):
        driver = self._select_identity_driver(domain_id)
        ref = driver.get_group_by_name(group_name, domain_id)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.GROUP)

    @domains_configured
    @exception_translated('group')
    def update_group(self, group_id, group, initiator=None):
        old_group_ref = self.get_group(group_id)
        self._require_matching_domain_id(group, old_group_ref)
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        group = self._clear_domain_id_if_domain_unaware(driver, group)
        if 'name' in group:
            group['name'] = group['name'].strip()
        ref = driver.update_group(entity_id, group)
        self.get_group.invalidate(self, group_id)
        notifications.Audit.updated(self._GROUP, group_id, initiator)
        return self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.GROUP)

    @domains_configured
    @exception_translated('group')
    def delete_group(self, group_id, initiator=None):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        roles = PROVIDERS.assignment_api.list_role_assignments(
            group_id=group_id
        )
        user_ids = (u['id'] for u in self.list_users_in_group(group_id))
        driver.delete_group(entity_id)
        self.get_group.invalidate(self, group_id)
        PROVIDERS.id_mapping_api.delete_id_mapping(group_id)
        PROVIDERS.assignment_api.delete_group_assignments(group_id)

        notifications.Audit.deleted(self._GROUP, group_id, initiator)

        # If the group has been created and has users but has no role
        # assignment for the group then we do not need to revoke all the users
        # tokens and can just delete the group.
        if roles:
            for user_id in user_ids:
                self._persist_revocation_event_for_user(user_id)

        # Invalidate user role assignments cache region, as it may be caching
        # role assignments expanded from the specified group to its users
        assignment.COMPUTED_ASSIGNMENTS_REGION.invalidate()

    @domains_configured
    @exception_translated('group')
    def add_user_to_group(self, user_id, group_id, initiator=None):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_domain_driver_and_entity_id(public_id)

        _domain_id, group_driver, group_entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _domain_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        group_driver.add_user_to_group(user_entity_id, group_entity_id)

        # Invalidate user role assignments cache region, as it may now need to
        # include role assignments from the specified group to its users
        assignment.COMPUTED_ASSIGNMENTS_REGION.invalidate()
        notifications.Audit.added_to(self._GROUP, group_id, self._USER,
                                     user_id, initiator)

    @domains_configured
    @exception_translated('group')
    def remove_user_from_group(self, user_id, group_id, initiator=None):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_domain_driver_and_entity_id(public_id)

        _domain_id, group_driver, group_entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _domain_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        group_driver.remove_user_from_group(user_entity_id, group_entity_id)
        self._persist_revocation_event_for_user(user_id)

        # Invalidate user role assignments cache region, as it may be caching
        # role assignments expanded from this group to this user
        assignment.COMPUTED_ASSIGNMENTS_REGION.invalidate()
        notifications.Audit.removed_from(self._GROUP, group_id, self._USER,
                                         user_id, initiator)

    def _persist_revocation_event_for_user(self, user_id):
        """Emit a notification to invoke a revocation event callback.

        Fire off an internal notification that will be consumed by the
        revocation API to store a revocation record for a specific user.

        :param user_id: user identifier
        :type user_id: string
        """
        notifications.Audit.internal(
            notifications.PERSIST_REVOCATION_EVENT_FOR_USER, user_id
        )

    @domains_configured
    @exception_translated('user')
    def list_groups_for_user(self, user_id, hints=None):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        self._set_list_limit_in_hints(hints, driver)
        hints = hints or driver_hints.Hints()
        if not driver.is_domain_aware():
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_groups_for_user(entity_id, hints)
        for ref in ref_list:
            if 'membership_expires_at' not in ref:
                ref['membership_expires_at'] = None
        return self._set_domain_id_and_mapping(
            ref_list, domain_id, driver, mapping.EntityType.GROUP)

    @domains_configured
    @exception_translated('group')
    def list_groups(self, domain_scope=None, hints=None):
        driver = self._select_identity_driver(domain_scope)
        self._set_list_limit_in_hints(hints, driver)
        hints = hints or driver_hints.Hints()
        if driver.is_domain_aware():
            # Force the domain_scope into the hint to ensure that we only get
            # back domains for that scope.
            self._ensure_domain_id_in_hints(hints, domain_scope)
        else:
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter.
            self._mark_domain_id_filter_satisfied(hints)
        ref_list = driver.list_groups(hints)
        return self._set_domain_id_and_mapping(
            ref_list, domain_scope, driver, mapping.EntityType.GROUP)

    @domains_configured
    @exception_translated('group')
    def list_users_in_group(self, group_id, hints=None):
        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        self._set_list_limit_in_hints(hints, driver)
        hints = hints or driver_hints.Hints()
        if not driver.is_domain_aware():
            # We are effectively satisfying any domain_id filter by the above
            # driver selection, so remove any such filter
            self._mark_domain_id_filter_satisfied(hints)
        hints = self._translate_expired_password_hints(hints)
        ref_list = driver.list_users_in_group(entity_id, hints)
        return self._set_domain_id_and_mapping(
            ref_list, domain_id, driver, mapping.EntityType.USER)

    @domains_configured
    @exception_translated('group')
    def check_user_in_group(self, user_id, group_id):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_domain_driver_and_entity_id(public_id)

        _domain_id, group_driver, group_entity_id = (
            self._get_domain_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _domain_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        return group_driver.check_user_in_group(user_entity_id,
                                                group_entity_id)

    @domains_configured
    def change_password(self, user_id, original_password,
                        new_password, initiator=None):

        # authenticate() will raise an AssertionError if authentication fails
        try:
            self.authenticate(user_id, original_password)
        except exception.PasswordExpired:
            # If a password has expired, we want users to be able to change it
            pass

        domain_id, driver, entity_id = (
            self._get_domain_driver_and_entity_id(user_id))
        try:
            validators.validate_password(new_password)
            driver.change_password(entity_id, new_password)
        except exception.PasswordValidationError as ex:
            audit_reason = reason.Reason(str(ex), str(ex.code))
            notifications.Audit.updated(self._USER, user_id,
                                        initiator, reason=audit_reason)
            raise

        notifications.Audit.updated(self._USER, user_id, initiator)
        self._persist_revocation_event_for_user(user_id)

    @MEMOIZE
    def _shadow_nonlocal_user(self, user):
        try:
            return PROVIDERS.shadow_users_api.get_user(user['id'])
        except exception.UserNotFound:
            return PROVIDERS.shadow_users_api.create_nonlocal_user(user)

    @MEMOIZE
    def _shadow_federated_user(self, idp_id, protocol_id, unique_id,
                               display_name, email=None):
        user_dict = {}
        try:
            PROVIDERS.shadow_users_api.update_federated_user_display_name(
                idp_id, protocol_id, unique_id, display_name)
            user_dict = PROVIDERS.shadow_users_api.get_federated_user(
                idp_id, protocol_id, unique_id)
            if email:
                user_ref = {"email": email}
                self.update_user(user_dict['id'], user_ref)
                user_dict.update({"email": email})
        except exception.UserNotFound:
            idp = PROVIDERS.federation_api.get_idp(idp_id)
            federated_dict = {
                'idp_id': idp_id,
                'protocol_id': protocol_id,
                'unique_id': unique_id,
                'display_name': display_name
            }
            user_dict = (
                PROVIDERS.shadow_users_api.create_federated_user(
                    idp['domain_id'], federated_dict, email=email
                )
            )
        PROVIDERS.shadow_users_api.set_last_active_at(user_dict['id'])
        return user_dict

    def shadow_federated_user(self, idp_id, protocol_id, unique_id,
                              display_name, email=None, group_ids=None):
        """Map a federated user to a user.

        :param idp_id: identity provider id
        :param protocol_id: protocol id
        :param unique_id: unique id for the user within the IdP
        :param display_name: user's display name
        :param email: user's email
        :param group_ids: list of group ids to add the user to

        :returns: dictionary of the mapped User entity
        """
        user_dict = self._shadow_federated_user(
            idp_id, protocol_id, unique_id, display_name, email)
        # Note(knikolla): The shadowing operation can be cached,
        # however we need to update the expiring group memberships.
        if group_ids:
            for group_id in group_ids:
                PROVIDERS.shadow_users_api.add_user_to_group_expires(
                    user_dict['id'], group_id)
        return user_dict


class MappingManager(manager.Manager):
    """Default pivot point for the ID Mapping backend."""

    driver_namespace = 'keystone.identity.id_mapping'
    _provides_api = 'id_mapping_api'

    def __init__(self):
        super(MappingManager, self).__init__(CONF.identity_mapping.driver)

    @MEMOIZE_ID_MAPPING
    def _get_public_id(self, domain_id, local_id, entity_type):
        return self.driver.get_public_id({'domain_id': domain_id,
                                          'local_id': local_id,
                                          'entity_type': entity_type})

    def get_public_id(self, local_entity):
        return self._get_public_id(local_entity['domain_id'],
                                   local_entity['local_id'],
                                   local_entity['entity_type'])

    @MEMOIZE_ID_MAPPING
    def get_id_mapping(self, public_id):
        return self.driver.get_id_mapping(public_id)

    def create_id_mapping(self, local_entity, public_id=None):
        public_id = self.driver.create_id_mapping(local_entity, public_id)
        if MEMOIZE_ID_MAPPING.should_cache(public_id):
            self._get_public_id.set(public_id, self,
                                    local_entity['domain_id'],
                                    local_entity['local_id'],
                                    local_entity['entity_type'])
            self.get_id_mapping.set(local_entity, self, public_id)
        return public_id

    def delete_id_mapping(self, public_id):
        local_entity = self.get_id_mapping.get(self, public_id)
        self.driver.delete_id_mapping(public_id)
        # Delete the key of entity from cache
        if local_entity:
            self._get_public_id.invalidate(self, local_entity['domain_id'],
                                           local_entity['local_id'],
                                           local_entity['entity_type'])
        self.get_id_mapping.invalidate(self, public_id)

    def purge_mappings(self, purge_filter):
        # Purge mapping is rarely used and only used by the command client,
        # it's quite complex to invalidate part of the cache based on the purge
        # filters, so here invalidate the whole cache when purging mappings.
        self.driver.purge_mappings(purge_filter)
        ID_MAPPING_REGION.invalidate()


class ShadowUsersManager(manager.Manager):
    """Default pivot point for the Shadow Users backend."""

    driver_namespace = 'keystone.identity.shadow_users'
    _provides_api = 'shadow_users_api'

    def __init__(self):
        shadow_driver = CONF.shadow_users.driver

        super(ShadowUsersManager, self).__init__(shadow_driver)

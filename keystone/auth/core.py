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
from oslo_log import versionutils
from oslo_utils import importutils
import six
import stevedore

from keystone.common import dependency
import keystone.conf
from keystone import exception
from keystone.i18n import _, _LI, _LE
from keystone.identity.backends import resource_options as ro


LOG = log.getLogger(__name__)

CONF = keystone.conf.CONF

# registry of authentication methods
AUTH_METHODS = {}
AUTH_PLUGINS_LOADED = False


def load_auth_method(method):
    plugin_name = CONF.auth.get(method) or 'default'
    namespace = 'keystone.auth.%s' % method
    try:
        driver_manager = stevedore.DriverManager(namespace, plugin_name,
                                                 invoke_on_load=True)
        return driver_manager.driver
    except RuntimeError:
        LOG.debug('Failed to load the %s driver (%s) using stevedore, will '
                  'attempt to load using import_object instead.',
                  method, plugin_name)

    driver = importutils.import_object(plugin_name)

    msg = (_(
        'Direct import of auth plugin %(name)r is deprecated as of Liberty in '
        'favor of its entrypoint from %(namespace)r and may be removed in '
        'N.') %
        {'name': plugin_name, 'namespace': namespace})
    versionutils.report_deprecated_feature(LOG, msg)

    return driver


def load_auth_methods():
    global AUTH_PLUGINS_LOADED

    if AUTH_PLUGINS_LOADED:
        # Only try and load methods a single time.
        return
    # config.setup_authentication should be idempotent, call it to ensure we
    # have setup all the appropriate configuration options we may need.
    keystone.conf.auth.setup_authentication()
    for plugin in set(CONF.auth.methods):
        AUTH_METHODS[plugin] = load_auth_method(plugin)
    AUTH_PLUGINS_LOADED = True


def get_auth_method(method_name):
    global AUTH_METHODS
    if method_name not in AUTH_METHODS:
        raise exception.AuthMethodNotSupported()
    return AUTH_METHODS[method_name]


@dependency.requires('identity_api')
class UserMFARulesValidator(object):
    """Helper object that can validate the MFA Rules."""

    @property
    def _auth_methods(self):
        if AUTH_PLUGINS_LOADED:
            return set(AUTH_METHODS.keys())
        raise RuntimeError(_('Auth Method Plugins are not loaded.'))

    def check_auth_methods_against_rules(self, user_id, auth_methods):
        """Validate the MFA rules against the successful auth methods.

        :param user_id: The user's ID (uuid).
        :type user_id: str
        :param auth_methods: List of methods that were used for auth
        :type auth_methods: set
        :returns: Boolean, ``True`` means rules match and auth may proceed,
                  ``False`` means rules do not match.
        """
        user_ref = self.identity_api.get_user(user_id)
        mfa_rules = user_ref['options'].get(ro.MFA_RULES_OPT.option_name, [])
        mfa_rules_enabled = user_ref['options'].get(
            ro.MFA_ENABLED_OPT.option_name, True)
        rules = self._parse_rule_structure(mfa_rules, user_ref['id'])

        if not rules or not mfa_rules_enabled:
            # return quickly if the rules are disabled for the user or not set
            LOG.debug('MFA Rules not processed for user `%(user_id)s`. '
                      'Rule list: `%(rules)s` (Enabled: `%(enabled)s`).',
                      {'user_id': user_id,
                       'rules': mfa_rules,
                       'enabled': mfa_rules_enabled})
            return True

        for r in rules:
            # NOTE(notmorgan): We only check against the actually loaded
            # auth methods meaning that the keystone administrator may
            # disable an auth method, and a rule will still pass making it
            # impossible to accidently lock-out a subset of users with a
            # bad keystone.conf
            r_set = set(r).intersection(self._auth_methods)
            if set(auth_methods).issuperset(r_set):
                # Rule Matches no need to continue, return here.
                LOG.debug('Auth methods for user `%(user_id)s`, `%(methods)s` '
                          'matched MFA rule `%(rule)s`. Loaded '
                          'auth_methods: `%(loaded)s`',
                          {'user_id': user_id,
                           'rule': list(r_set),
                           'methods': auth_methods,
                           'loaded': self._auth_methods})
                return True

        LOG.debug('Auth methods for user `%(user_id)s`, `%(methods)s` did not '
                  'match a MFA rule in `%(rules)s`.',
                  {'user_id': user_id,
                   'methods': auth_methods,
                   'rules': rules})
        return False

    @staticmethod
    def _parse_rule_structure(rules, user_id):
        """Validate and parse the rule data structure.

        Rule sets must be in the form of list of lists. The lists may not
        have duplicates and must not be empty. The top-level list may be empty
        indicating that no rules exist.

        :param rules: The list of rules from the user_ref
        :type rules: list
        :param user_id: the user_id, used for logging purposes
        :type user_id: str
        :returns: list of list, duplicates are stripped
        """
        # NOTE(notmorgan): Most of this is done at the API request validation
        # and in the storage layer, it makes sense to also validate here and
        # ensure the data returned from the DB is sane, This will not raise
        # any exceptions, but just produce a usable set of data for rules
        # processing.
        rule_set = []
        found_rules = set()
        if not isinstance(rules, list):
            LOG.error(_LE('Corrupt rule data structure for user %(user_id)s, '
                          'no rules loaded.'),
                      {'user_id': user_id})
            return rule_set
        elif not rules:
            return rule_set

        for r_list in rules:
            if not isinstance(r_list, list):
                LOG.info(_LI('Ignoring Rule %(rule)r; rule must be a list of '
                             'strings.'),
                         {'type': type(r_list)})
                continue

            if r_list:
                # No empty rules are allowed.
                _ok_rule = True
                for item in r_list:
                    if not isinstance(item, six.string_types):
                        # Rules may only contain strings for method names
                        # Reject a rule with non-string values
                        LOG.info(_LI('Ignoring Rule %(rule)r; rule contains '
                                     'non-string values.'),
                                 {'rule': r_list})
                        _ok_rule = False
                        break
                if _ok_rule:
                    # De-dupe rule and add to the return value
                    rule_string = ';'.join(sorted(r_list))
                    if rule_string not in found_rules:
                        found_rules.add(rule_string)
                    r_list = list(set(r_list))
                    rule_set.append(r_list)

        return rule_set

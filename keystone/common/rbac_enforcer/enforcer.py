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

import functools

import flask
from oslo_log import log
from oslo_policy import opts
from oslo_policy import policy as common_policy
from oslo_utils import strutils

from keystone.common import authorization
from keystone.common import context
from keystone.common import policies
from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDER_APIS = provider_api.ProviderAPIs


_POSSIBLE_TARGET_ACTIONS = frozenset([
    rule.name for
    rule in policies.list_rules() if not rule.deprecated_for_removal
])
_ENFORCEMENT_CHECK_ATTR = 'keystone:RBAC:enforcement_called'


# TODO(gmann): Remove setting the default value of config policy_file
# once oslo_policy change the default value to 'policy.yaml'.
# https://github.com/openstack/oslo.policy/blob/a626ad12fe5a3abd49d70e3e5b95589d279ab578/oslo_policy/opts.py#L49
DEFAULT_POLICY_FILE = 'policy.yaml'
opts.set_defaults(CONF, DEFAULT_POLICY_FILE)


class RBACEnforcer(object):
    """Enforce RBAC on API calls."""

    __shared_state__ = {}
    __ENFORCER = None
    ACTION_STORE_ATTR = 'keystone:RBAC:action_name'
    # FOR TESTS ONLY
    suppress_deprecation_warnings = False

    def __init__(self):
        # NOTE(morgan): All Enforcer Instances use the same shared state;
        # BORG pattern.
        self.__dict__ = self.__shared_state__

    def _check_deprecated_rule(self, action):
        def _name_is_changing(rule):
            deprecated_rule = rule.deprecated_rule
            return (deprecated_rule and
                    deprecated_rule.name != rule.name and
                    deprecated_rule.name in self._enforcer.file_rules)

        def _check_str_is_changing(rule):
            deprecated_rule = rule.deprecated_rule
            return (deprecated_rule and
                    deprecated_rule.check_str != rule.check_str and
                    rule.name not in self._enforcer.file_rules)

        def _is_deprecated_for_removal(rule):
            return (rule.deprecated_for_removal and
                    rule.name in self._enforcer.file_rules)

        def _emit_warning():
            if not self._enforcer._warning_emitted:
                LOG.warning("Deprecated policy rules found. Use "
                            "oslopolicy-policy-generator and "
                            "oslopolicy-policy-upgrade to detect and resolve "
                            "deprecated policies in your configuration.")
                self._enforcer._warning_emitted = True

        registered_rule = self._enforcer.registered_rules.get(action)

        if not registered_rule:
            return
        if (_name_is_changing(registered_rule) or
                _check_str_is_changing(registered_rule) or
                _is_deprecated_for_removal(registered_rule)):
            _emit_warning()

    def _enforce(self, credentials, action, target, do_raise=True):
        """Verify that the action is valid on the target in this context.

        This method is for cases that exceed the base enforcer
        functionality (notably for compatibility with `@protected` style
        decorators.

        :param credentials: user credentials
        :param action: string representing the action to be checked, which
                       should be colon separated for clarity.
        :param target: dictionary representing the object of the action for
                       object creation this should be a dictionary
                       representing the location of the object e.g.
                       {'project_id': object.project_id}
        :raises keystone.exception.Forbidden: If verification fails.

        Actions should be colon separated for clarity. For example:

        * identity:list_users
        """
        # Add the exception arguments if asked to do a raise
        extra = {}
        if do_raise:
            extra.update(exc=exception.ForbiddenAction, action=action,
                         do_raise=do_raise)

        try:
            result = self._enforcer.enforce(
                rule=action, target=target, creds=credentials, **extra)
            self._check_deprecated_rule(action)
            return result
        except common_policy.InvalidScope:
            raise exception.ForbiddenAction(action=action)

    def _reset(self):
        # NOTE(morgan): Used for TEST purposes only.
        self.__ENFORCER = None

    @property
    def _enforcer(self):
        # The raw oslo-policy enforcer object
        if self.__ENFORCER is None:
            self.__ENFORCER = common_policy.Enforcer(CONF)
            # NOTE(cmurphy) when running in the keystone server, suppress
            # deprecation warnings for individual policy rules. Instead, we log
            # a single notification at enforcement time indicating the
            # oslo.policy tools the operator can use to detect and resolve
            # deprecated policies. If there is no request context here, that
            # means external tooling such as the oslo.policy tools are running
            # this code, in which case we do want the full deprecation warnings
            # emitted for individual polcy rules.
            if flask.has_request_context():
                self.__ENFORCER.suppress_deprecation_warnings = True
            # NOTE(cmurphy) Tests may explicitly disable these warnings to
            # prevent an explosion of test logs
            if self.suppress_deprecation_warnings:
                self.__ENFORCER.suppress_deprecation_warnings = True
            self.register_rules(self.__ENFORCER)
            self.__ENFORCER._warning_emitted = False
        return self.__ENFORCER

    @staticmethod
    def _extract_filter_values(filters):
        """Extract filter data from query params for RBAC enforcement."""
        filters = filters or []
        target = {i: flask.request.args[i] for
                  i in filters if i in flask.request.args}
        if target:
            if LOG.logger.getEffectiveLevel() <= log.DEBUG:
                LOG.debug(
                    'RBAC: Adding query filter params (%s)',
                    ', '.join(['%s=%s' % (k, v) for k, v in target.items()]))
        return target

    @staticmethod
    def _extract_member_target_data(member_target_type, member_target):
        """Build some useful target data.

        :param member_target_type: what type of target, e.g. 'user'
        :type member_target_type: str or None
        :param member_target: reference of the target data
        :type member_target: dict or None
        :returns: constructed target dict or empty dict
        :rtype: dict
        """
        ret_dict = {}
        if ((member_target is not None and member_target_type is None) or
                (member_target is None and member_target_type is not None)):
            LOG.warning('RBAC: Unknown target type or target reference. '
                        'Rejecting as unauthorized. '
                        '(member_target_type=%(target_type)r, '
                        'member_target=%(target_ref)r)',
                        {'target_type': member_target_type,
                         'target_ref': member_target})
            # Fast exit.
            return ret_dict

        if member_target is not None and member_target_type is not None:
            ret_dict['target'] = {member_target_type: member_target}
        else:
            # Try and do some magic loading based upon the resource we've
            # matched in our route. This is mostly so we can have a level of
            # automatic pulling in the resource; strictly for some added
            # DRY capabilities. In an ideal world the target is always passed
            # in explicitly.
            if flask.request.endpoint:
                # This only works for cases of Flask-RESTful, or carefully
                # crafted endpoints that live on a class. Ultimately, there
                # should be more protection against something wonky
                # here.
                resource = flask.current_app.view_functions[
                    flask.request.endpoint].view_class
                try:
                    member_name = getattr(resource, 'member_key', None)
                except ValueError:
                    # NOTE(morgan): In the case that the ResourceBase keystone
                    # class is used, we raise a value error when member_key
                    # has not been set on the class. This is perfectly
                    # normal and acceptable. Set member_name to None as though
                    # it wasn't set.
                    member_name = None
                func = getattr(
                    resource, 'get_member_from_driver', None)
                if member_name is not None and callable(func):
                    key = '%s_id' % member_name
                    if key in (flask.request.view_args or {}):
                        # NOTE(morgan): For most correct setup, instantiate the
                        # view_class. There is no current support for passing
                        # extra args to the constructor of the view_class like
                        # .as_view() method would actually do. In this case
                        # perform a simple instantiation to represent the
                        # `self` pass to the unbound method.
                        #
                        # TODO(morgan): add (future) support for passing class
                        # instantiation args.
                        ret_dict['target'] = {
                            member_name: func(flask.request.view_args[key])
                        }
        return ret_dict

    @staticmethod
    def _extract_policy_check_credentials():
        # Pull out the auth context
        return flask.request.environ.get(authorization.AUTH_CONTEXT_ENV, {})

    @classmethod
    def _extract_subject_token_target_data(cls):
        ret_dict = {}
        window_seconds = 0
        # NOTE(morgan): Populate the subject token data into
        # the policy dict at "target.token". In all liklyhood
        # it is un-interesting to populate this data outside
        # of the auth paths.
        target = 'token'
        subject_token = flask.request.headers.get('X-Subject-Token')
        access_rules_support = flask.request.headers.get(
            authorization.ACCESS_RULES_HEADER)
        if subject_token is not None:
            allow_expired = (strutils.bool_from_string(
                flask.request.args.get('allow_expired', False),
                default=False))
            if allow_expired:
                window_seconds = CONF.token.allow_expired_window
            token = PROVIDER_APIS.token_provider_api.validate_token(
                subject_token,
                window_seconds=window_seconds,
                access_rules_support=access_rules_support
            )
            # TODO(morgan): Expand extracted data from the subject token.
            ret_dict[target] = {}
            ret_dict[target]['user_id'] = token.user_id
            try:
                user_domain_id = token.user['domain_id']
            except exception.UnexpectedError:
                user_domain_id = None
            if user_domain_id:
                ret_dict[target].setdefault('user', {})
                ret_dict[target]['user'].setdefault('domain', {})
                ret_dict[target]['user']['domain']['id'] = user_domain_id
        return ret_dict

    @staticmethod
    def _get_oslo_req_context():
        return flask.request.environ.get(context.REQUEST_CONTEXT_ENV, None)

    @classmethod
    def _assert_is_authenticated(cls):
        ctx = cls._get_oslo_req_context()
        if ctx is None:
            LOG.warning('RBAC: Error reading the request context generated by '
                        'the Auth Middleware (there is no context). Rejecting '
                        'request as unauthorized.')
            raise exception.Unauthorized(
                _('Internal error processing authentication and '
                  'authorization.'))
        if not ctx.authenticated:
            raise exception.Unauthorized(
                _('auth_context did not decode anything useful'))

    @classmethod
    def _shared_admin_auth_token_set(cls):
        ctx = cls._get_oslo_req_context()
        return getattr(ctx, 'is_admin', False)

    @classmethod
    def enforce_call(cls, enforcer=None, action=None, target_attr=None,
                     member_target_type=None, member_target=None,
                     filters=None, build_target=None):
        """Enforce RBAC on the current request.

        This will do some legwork and then instantiate the Enforcer if an
        enforcer is not passed in.

        :param enforcer: A pre-instantiated Enforcer object (optional)
        :type enforcer: :class:`RBACEnforcer`
        :param action: the name of the rule/policy enforcement to be checked
                       against, e.g. `identity:get_user` (optional may be
                       replaced by decorating the method/function with
                       `policy_enforcer_action`.
        :type action: str
        :param target_attr: complete override of the target data. This will
                            replace all other generated target data meaning
                            `member_target_type` and `member_target` are
                            ignored. This will also prevent extraction of
                            data from the X-Subject-Token. The `target` dict
                            should contain a series of key-value pairs such
                            as `{'user': user_ref_dict}`.
        :type target_attr: dict
        :param member_target_type: the type of the target, e.g. 'user'. Both
                                   this and `member_target` must be passed if
                                   either is passed.
        :type member_target_type: str
        :param member_target: the (dict form) reference of the member object.
                              Both this and `member_target_type` must be passed
                              if either is passed.
        :type member_target: dict
        :param filters: A variable number of optional string filters, these are
                        used to extract values from the query params. The
                        filters are added to the request data that is passed to
                        the enforcer and may be used to determine policy
                        action. In practice these are mainly supplied in the
                        various "list" APIs and are un-used in the default
                        supplied policies.
        :type filters: iterable
        :param build_target: A function to build the target for enforcement.
                             This is explicitly done after authentication
                             in order to not leak existance data before
                             auth.
        :type build_target: function
        """
        # NOTE(morgan) everything in the policy_dict may be used by the policy
        # DSL to action on RBAC and request information/response data.
        policy_dict = {}

        # If "action" has not explicitly been overridden, see if it is set in
        # Flask.g app-context (per-request thread local) meaning the
        # @policy_enforcer_action decorator was used.
        action = action or getattr(flask.g, cls.ACTION_STORE_ATTR, None)
        if action not in _POSSIBLE_TARGET_ACTIONS:
            LOG.warning('RBAC: Unknown enforcement action name `%s`. '
                        'Rejecting as Forbidden, this is a programming error '
                        'and a bug should be filed with as much information '
                        'about the request that caused this as possible.',
                        action)
            # NOTE(morgan): While this is an internal error, a 500 is never
            # desirable, we have handled the case and the most appropriate
            # response here is to issue a 403 (FORBIDDEN) to any API calling
            # enforce_call with an inappropriate action/name to look up the
            # policy rule. This is simply a short-circuit as the enforcement
            # code raises a 403 on an unknown action (in keystone) by default.
            raise exception.Forbidden(
                message=_(
                    'Internal RBAC enforcement error, invalid rule (action) '
                    'name.'))

        # Mark flask.g as "enforce_call" has been called. This should occur
        # before anything except the "is this a valid action" check, ensuring
        # all proper "after request" checks pass, showing that the API has
        # enforcement.
        setattr(flask.g, _ENFORCEMENT_CHECK_ATTR, True)

        # Assert we are actually authenticated
        cls._assert_is_authenticated()

        # Check if "is_admin", this is in support of the old "admin auth token"
        # middleware with a shared "admin" token for auth
        if cls._shared_admin_auth_token_set():
            LOG.warning('RBAC: Bypassing authorization')
            return

        # NOTE(morgan): !!! ORDER OF THESE OPERATIONS IS IMPORTANT !!!
        # The lowest priority values are set first and the highest priority
        # values are set last.

        # Populate the input attributes (view args) directly to the policy
        # dict. This is to allow the policy engine to have access to the
        # view args for substitution. This is to mirror the old @protected
        # mechanism and ensure current policy files continue to work as
        # expected.
        policy_dict.update(flask.request.view_args)

        # Get the Target Data Set.
        if target_attr is None and build_target is None:
            try:
                policy_dict.update(cls._extract_member_target_data(
                    member_target_type, member_target))
            except exception.NotFound:
                # DEBUG LOG and bubble up the 404 error. This is expected
                # behavior. This likely should be specific in each API. This
                # should be revisited in the future and each API should make
                # the explicit "existence" checks before enforcement.
                LOG.debug('Extracting inferred target data resulted in '
                          '"NOT FOUND (404)".')
                raise
            except Exception as e:  # nosec
                # NOTE(morgan): Errors should never bubble up at this point,
                # if there is an error getting the target, log it and move
                # on. Raise an explicit 403, we have failed policy checks.
                LOG.warning('Unable to extract inferred target data during '
                            'enforcement')
                LOG.debug(e, exc_info=True)
                raise exception.ForbiddenAction(action=action)

            # Special Case, extract and add subject_token data.
            subj_token_target_data = cls._extract_subject_token_target_data()
            if subj_token_target_data:
                policy_dict.setdefault('target', {}).update(
                    subj_token_target_data)
        else:
            if target_attr and build_target:
                raise ValueError('Programming Error: A target_attr or '
                                 'build_target must be provided, but not both')

            policy_dict['target'] = target_attr or build_target()

        # Pull the data from the submitted json body to generate
        # appropriate input/target attributes, we take an explicit copy here
        # to ensure we're not somehow corrupting
        json_input = flask.request.get_json(force=True, silent=True) or {}
        policy_dict.update(json_input.copy())

        # Generate the filter_attr dataset.
        policy_dict.update(cls._extract_filter_values(filters))

        flattened = utils.flatten_dict(policy_dict)
        if LOG.logger.getEffectiveLevel() <= log.DEBUG:
            # LOG the Args
            args_str = ', '.join(
                ['%s=%s' % (k, v) for
                 k, v in (flask.request.view_args or {}).items()])
            args_str = strutils.mask_password(args_str)
            LOG.debug('RBAC: Authorizing `%(action)s(%(args)s)`',
                      {'action': action, 'args': args_str})

        ctxt = cls._get_oslo_req_context()
        # Instantiate the enforcer object if needed.
        enforcer_obj = enforcer or cls()
        enforcer_obj._enforce(
            credentials=ctxt, action=action, target=flattened)
        LOG.debug('RBAC: Authorization granted')

    @classmethod
    def policy_enforcer_action(cls, action):
        """Decorator to set policy enforcement action name."""
        if action not in _POSSIBLE_TARGET_ACTIONS:
            raise ValueError('PROGRAMMING ERROR: Action must reference a '
                             'valid Keystone policy enforcement name.')

        def wrapper(f):
            @functools.wraps(f)
            def inner(*args, **kwargs):
                # Set the action in g on a known attr so we can reference it
                # later.
                setattr(flask.g, cls.ACTION_STORE_ATTR, action)
                return f(*args, **kwargs)
            return inner
        return wrapper

    @staticmethod
    def register_rules(enforcer):
        enforcer.register_defaults(policies.list_rules())

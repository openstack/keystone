# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import functools
import uuid

from oslo_log import log
from oslo_log import versionutils
from oslo_utils import strutils
import six

from keystone.common import authorization
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import utils
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _, _LW
from keystone.models import token_model


LOG = log.getLogger(__name__)
CONF = keystone.conf.CONF


def v2_deprecated(f):
    @six.wraps(f)
    def wrapper(*args, **kwargs):
        deprecated = versionutils.deprecated(
            what=f.__name__ + ' of the v2 API',
            as_of=versionutils.deprecated.MITAKA,
            in_favor_of='a similar function in the v3 API',
            remove_in=+4)
        return deprecated(f)
    return wrapper()


def v2_ec2_deprecated(f):
    @six.wraps(f)
    def wrapper(*args, **kwargs):
        deprecated = versionutils.deprecated(
            what=f.__name__ + ' of the v2 EC2 APIs',
            as_of=versionutils.deprecated.MITAKA,
            in_favor_of=('a similar function in the v3 Credential APIs'),
            remove_in=0)
        return deprecated(f)
    return wrapper()


def v2_auth_deprecated(f):
    @six.wraps(f)
    def wrapper(*args, **kwargs):
        deprecated = versionutils.deprecated(
            what=f.__name__ + ' of the v2 Authentication APIs',
            as_of=versionutils.deprecated.MITAKA,
            in_favor_of=('a similar function in the v3 Authentication APIs'),
            remove_in=0)
        return deprecated(f)
    return wrapper()


def _build_policy_check_credentials(self, action, context, kwargs):
    kwargs_str = ', '.join(['%s=%s' % (k, kwargs[k]) for k in kwargs])
    kwargs_str = strutils.mask_password(kwargs_str)
    msg = 'RBAC: Authorizing %(action)s(%(kwargs)s)'
    LOG.debug(msg, {'action': action, 'kwargs': kwargs_str})

    return context['environment'].get(authorization.AUTH_CONTEXT_ENV, {})


def protected(callback=None):
    """Wrap API calls with role based access controls (RBAC).

    This handles both the protection of the API parameters as well as any
    target entities for single-entity API calls.

    More complex API calls (for example that deal with several different
    entities) should pass in a callback function, that will be subsequently
    called to check protection for these multiple entities. This callback
    function should gather the appropriate entities needed and then call
    check_protection() in the V3Controller class.

    """
    def wrapper(f):
        @functools.wraps(f)
        def inner(self, request, *args, **kwargs):
            request.assert_authenticated()

            if request.context.is_admin:
                LOG.warning(_LW('RBAC: Bypassing authorization'))
            elif callback is not None:
                prep_info = {'f_name': f.__name__,
                             'input_attr': kwargs}
                callback(self,
                         request,
                         prep_info,
                         *args,
                         **kwargs)
            else:
                action = 'identity:%s' % f.__name__
                creds = _build_policy_check_credentials(self,
                                                        action,
                                                        request.context_dict,
                                                        kwargs)

                policy_dict = {}

                # Check to see if we need to include the target entity in our
                # policy checks.  We deduce this by seeing if the class has
                # specified a get_member() method and that kwargs contains the
                # appropriate entity id.
                if (hasattr(self, 'get_member_from_driver') and
                        self.get_member_from_driver is not None):
                    key = '%s_id' % self.member_name
                    if key in kwargs:
                        ref = self.get_member_from_driver(kwargs[key])
                        policy_dict['target'] = {self.member_name: ref}

                # TODO(henry-nash): Move this entire code to a member
                # method inside v3 Auth
                if request.context_dict.get('subject_token_id') is not None:
                    window_seconds = self._token_validation_window(request)
                    token_ref = token_model.KeystoneToken(
                        token_id=request.context_dict['subject_token_id'],
                        token_data=self.token_provider_api.validate_token(
                            request.context_dict['subject_token_id'],
                            window_seconds=window_seconds))
                    policy_dict.setdefault('target', {})
                    policy_dict['target'].setdefault(self.member_name, {})
                    policy_dict['target'][self.member_name]['user_id'] = (
                        token_ref.user_id)
                    try:
                        user_domain_id = token_ref.user_domain_id
                    except exception.UnexpectedError:
                        user_domain_id = None
                    if user_domain_id:
                        policy_dict['target'][self.member_name].setdefault(
                            'user', {})
                        policy_dict['target'][self.member_name][
                            'user'].setdefault('domain', {})
                        policy_dict['target'][self.member_name]['user'][
                            'domain']['id'] = (
                                user_domain_id)

                # Add in the kwargs, which means that any entity provided as a
                # parameter for calls like create and update will be included.
                policy_dict.update(kwargs)
                self.policy_api.enforce(creds,
                                        action,
                                        utils.flatten_dict(policy_dict))
                LOG.debug('RBAC: Authorization granted')
            return f(self, request, *args, **kwargs)
        return inner
    return wrapper


def filterprotected(*filters, **callback):
    """Wrap API list calls with role based access controls (RBAC).

    This handles both the protection of the API parameters as well as any
    filters supplied.

    More complex API list calls (for example that need to examine the contents
    of an entity referenced by one of the filters) should pass in a callback
    function, that will be subsequently called to check protection for these
    multiple entities. This callback function should gather the appropriate
    entities needed and then call check_protection() in the V3Controller class.

    """
    def _filterprotected(f):
        @functools.wraps(f)
        def wrapper(self, request, **kwargs):
            request.assert_authenticated()

            if not request.context.is_admin:
                # The target dict for the policy check will include:
                #
                # - Any query filter parameters
                # - Data from the main url (which will be in the kwargs
                #   parameter), which although most of our APIs do not utilize,
                #   in theory you could have.
                #

                # First build the dict of filter parameters
                target = dict()
                if filters:
                    for item in filters:
                        if item in request.params:
                            target[item] = request.params[item]

                    LOG.debug('RBAC: Adding query filter params (%s)', (
                        ', '.join(['%s=%s' % (item, target[item])
                                  for item in target])))

                if 'callback' in callback and callback['callback'] is not None:
                    # A callback has been specified to load additional target
                    # data, so pass it the formal url params as well as the
                    # list of filters, so it can augment these and then call
                    # the check_protection() method.
                    prep_info = {'f_name': f.__name__,
                                 'input_attr': kwargs,
                                 'filter_attr': target}
                    callback['callback'](self,
                                         request,
                                         prep_info,
                                         **kwargs)
                else:
                    # No callback, so we are going to check the protection here
                    action = 'identity:%s' % f.__name__
                    creds = _build_policy_check_credentials(
                        self, action, request.context_dict, kwargs)
                    # Add in any formal url parameters
                    for key in kwargs:
                        target[key] = kwargs[key]

                    self.policy_api.enforce(creds,
                                            action,
                                            utils.flatten_dict(target))

                    LOG.debug('RBAC: Authorization granted')
            else:
                LOG.warning(_LW('RBAC: Bypassing authorization'))
            return f(self, request, filters, **kwargs)
        return wrapper
    return _filterprotected


class V2Controller(wsgi.Application):
    """Base controller class for Identity API v2."""

    def _normalize_domain_id(self, request, ref):
        """Fill in domain_id since v2 calls are not domain-aware.

        This will overwrite any domain_id that was inadvertently
        specified in the v2 call.

        """
        ref['domain_id'] = CONF.identity.default_domain_id
        return ref

    @staticmethod
    def filter_domain_id(ref):
        """Remove domain_id since v2 calls are not domain-aware."""
        ref.pop('domain_id', None)
        return ref

    @staticmethod
    def filter_domain(ref):
        """Remove domain since v2 calls are not domain-aware."""
        ref.pop('domain', None)
        return ref

    @staticmethod
    def filter_project_parent_id(ref):
        """Remove parent_id since v2 calls are not hierarchy-aware."""
        ref.pop('parent_id', None)
        return ref

    @staticmethod
    def filter_is_domain(ref):
        """Remove is_domain field since v2 calls are not domain-aware."""
        ref.pop('is_domain', None)
        return ref

    @staticmethod
    def normalize_username_in_response(ref):
        """Add username to outgoing user refs to match the v2 spec.

        Internally we use `name` to represent a user's name. The v2 spec
        requires the use of `username` instead.

        """
        if 'username' not in ref and 'name' in ref:
            ref['username'] = ref['name']
        return ref

    @staticmethod
    def normalize_username_in_request(ref):
        """Add name in incoming user refs to match the v2 spec.

        Internally we use `name` to represent a user's name. The v2 spec
        requires the use of `username` instead.

        """
        if 'name' not in ref and 'username' in ref:
            ref['name'] = ref.pop('username')
        return ref

    @staticmethod
    def v3_to_v2_user(ref):
        """Convert a user_ref from v3 to v2 compatible.

        * v2.0 users are not domain aware, and should have domain_id removed
        * v2.0 users expect the use of tenantId instead of default_project_id
        * v2.0 users have a username attribute
        * v2.0 remove password_expires_at

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
            ref.pop('password_expires_at', None)
            V2Controller.filter_domain(ref)
            V2Controller.filter_domain_id(ref)
            V2Controller.normalize_username_in_response(ref)
            return ref

        if isinstance(ref, dict):
            return _normalize_and_filter_user_properties(ref)
        elif isinstance(ref, list):
            return [_normalize_and_filter_user_properties(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    @staticmethod
    def v3_to_v2_project(ref):
        """Convert a project_ref from v3 to v2.

        * v2.0 projects are not domain aware, and should have domain_id removed
        * v2.0 projects are not hierarchy aware, and should have parent_id
          removed

        This method should only be applied to project_refs being returned from
        the v2.0 controller(s).

        If ref is a list type, we will iterate through each element and do the
        conversion.
        """
        def _filter_project_properties(ref):
            """Run through the various filter methods."""
            V2Controller.filter_domain_id(ref)
            V2Controller.filter_project_parent_id(ref)
            V2Controller.filter_is_domain(ref)
            return ref

        if isinstance(ref, dict):
            return _filter_project_properties(ref)
        elif isinstance(ref, list):
            return [_filter_project_properties(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def format_project_list(self, tenant_refs, **kwargs):
        """Format a v2 style project list, including marker/limits."""
        marker = kwargs.get('marker')
        first_index = 0
        if marker is not None:
            for (marker_index, tenant) in enumerate(tenant_refs):
                if tenant['id'] == marker:
                    # we start pagination after the marker
                    first_index = marker_index + 1
                    break
            else:
                msg = _('Marker could not be found')
                raise exception.ValidationError(message=msg)

        limit = kwargs.get('limit')
        last_index = None
        if limit is not None:
            try:
                limit = int(limit)
                if limit < 0:
                    raise AssertionError()
            except (ValueError, AssertionError):
                msg = _('Invalid limit value')
                raise exception.ValidationError(message=msg)
            last_index = first_index + limit

        tenant_refs = tenant_refs[first_index:last_index]

        for x in tenant_refs:
            if 'enabled' not in x:
                x['enabled'] = True
        o = {'tenants': tenant_refs,
             'tenants_links': []}
        return o


@dependency.requires('policy_api', 'token_provider_api')
class V3Controller(wsgi.Application):
    """Base controller class for Identity API v3.

    Child classes should set the ``collection_name`` and ``member_name`` class
    attributes, representing the collection of entities they are exposing to
    the API. This is required for supporting self-referential links,
    pagination, etc.

    Class parameters:

    * `_public_parameters` - set of parameters that are exposed to the user.
                             Usually used by cls.filter_params()

    """

    collection_name = 'entities'
    member_name = 'entity'
    get_member_from_driver = None

    @classmethod
    def base_url(cls, context, path=None):
        endpoint = super(V3Controller, cls).base_url(context, 'public')
        if not path:
            path = cls.collection_name

        return '%s/%s/%s' % (endpoint, 'v3', path.lstrip('/'))

    @classmethod
    def full_url(cls, context, path=None):
        url = cls.base_url(context, path)
        if context['environment'].get('QUERY_STRING'):
            url = '%s?%s' % (url, context['environment']['QUERY_STRING'])

        return url

    @classmethod
    def query_filter_is_true(cls, filter_value):
        """Determine if bool query param is 'True'.

        We treat this the same way as we do for policy
        enforcement:

        {bool_param}=0 is treated as False

        Any other value is considered to be equivalent to
        True, including the absence of a value

        """
        if (isinstance(filter_value, six.string_types) and
                filter_value == '0'):
            val = False
        else:
            val = True
        return val

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        ref.setdefault('links', {})
        ref['links']['self'] = cls.base_url(context) + '/' + ref['id']

    @classmethod
    def wrap_member(cls, context, ref):
        cls._add_self_referential_link(context, ref)
        return {cls.member_name: ref}

    @classmethod
    def wrap_collection(cls, context, refs, hints=None):
        """Wrap a collection, checking for filtering and pagination.

        Returns the wrapped collection, which includes:
        - Executing any filtering not already carried out
        - Truncate to a set limit if necessary
        - Adds 'self' links in every member
        - Adds 'next', 'self' and 'prev' links for the whole collection.

        :param context: the current context, containing the original url path
                        and query string
        :param refs: the list of members of the collection
        :param hints: list hints, containing any relevant filters and limit.
                      Any filters already satisfied by managers will have been
                      removed
        """
        # Check if there are any filters in hints that were not
        # handled by the drivers. The driver will not have paginated or
        # limited the output if it found there were filters it was unable to
        # handle.

        if hints is not None:
            refs = cls.filter_by_attributes(refs, hints)

        list_limited, refs = cls.limit(refs, hints)

        for ref in refs:
            cls.wrap_member(context, ref)

        container = {cls.collection_name: refs}
        container['links'] = {
            'next': None,
            'self': cls.full_url(context, path=context['path']),
            'previous': None}

        if list_limited:
            container['truncated'] = True

        return container

    @classmethod
    def limit(cls, refs, hints):
        """Limit a list of entities.

        The underlying driver layer may have already truncated the collection
        for us, but in case it was unable to handle truncation we check here.

        :param refs: the list of members of the collection
        :param hints: hints, containing, among other things, the limit
                      requested

        :returns: boolean indicating whether the list was truncated, as well
                  as the list of (truncated if necessary) entities.

        """
        NOT_LIMITED = False
        LIMITED = True

        if hints is None or hints.limit is None:
            # No truncation was requested
            return NOT_LIMITED, refs

        if hints.limit.get('truncated', False):
            # The driver did truncate the list
            return LIMITED, refs

        if len(refs) > hints.limit['limit']:
            # The driver layer wasn't able to truncate it for us, so we must
            # do it here
            return LIMITED, refs[:hints.limit['limit']]

        return NOT_LIMITED, refs

    @classmethod
    def filter_by_attributes(cls, refs, hints):
        """Filter a list of references by filter values."""
        def _attr_match(ref_attr, val_attr):
            """Matche attributes allowing for booleans as strings.

            We test explicitly for a value that defines it as 'False',
            which also means that the existence of the attribute with
            no value implies 'True'

            """
            if type(ref_attr) is bool:
                return ref_attr == utils.attr_as_boolean(val_attr)
            else:
                return ref_attr == val_attr

        def _inexact_attr_match(filter, ref):
            """Apply an inexact filter to a result dict.

            :param filter: the filter in question
            :param ref: the dict to check

            :returns: True if there is a match

            """
            comparator = filter['comparator']
            key = filter['name']

            if key in ref:
                filter_value = filter['value']
                target_value = ref[key]
                if not filter['case_sensitive']:
                    # We only support inexact filters on strings so
                    # it's OK to use lower()
                    filter_value = filter_value.lower()
                    target_value = target_value.lower()

                if comparator == 'contains':
                    return (filter_value in target_value)
                elif comparator == 'startswith':
                    return target_value.startswith(filter_value)
                elif comparator == 'endswith':
                    return target_value.endswith(filter_value)
                else:
                    # We silently ignore unsupported filters
                    return True

            return False

        for filter in hints.filters:
            if filter['comparator'] == 'equals':
                attr = filter['name']
                value = filter['value']
                refs = [r for r in refs if _attr_match(
                    utils.flatten_dict(r).get(attr), value)]
            else:
                # It might be an inexact filter
                refs = [r for r in refs if _inexact_attr_match(
                    filter, r)]

        return refs

    @classmethod
    def build_driver_hints(cls, request, supported_filters):
        """Build list hints based on the context query string.

        :param request: the current request
        :param supported_filters: list of filters supported, so ignore any
                                  keys in query_dict that are not in this list.

        """
        hints = driver_hints.Hints()

        if not request.params:
            return hints

        for key, value in request.params.items():
            # Check if this is an exact filter
            if supported_filters is None or key in supported_filters:
                hints.add_filter(key, value)
                continue

            # Check if it is an inexact filter
            for valid_key in supported_filters:
                # See if this entry in query_dict matches a known key with an
                # inexact suffix added.  If it doesn't match, then that just
                # means that there is no inexact filter for that key in this
                # query.
                if not key.startswith(valid_key + '__'):
                    continue

                base_key, comparator = key.split('__', 1)

                # We map the query-style inexact of, for example:
                #
                # {'email__contains', 'myISP'}
                #
                # into a list directive add filter call parameters of:
                #
                # name = 'email'
                # value = 'myISP'
                # comparator = 'contains'
                # case_sensitive = True

                case_sensitive = True
                if comparator.startswith('i'):
                    case_sensitive = False
                    comparator = comparator[1:]
                hints.add_filter(base_key, value,
                                 comparator=comparator,
                                 case_sensitive=case_sensitive)

        # NOTE(henry-nash): If we were to support pagination, we would pull any
        # pagination directives out of the query_dict here, and add them into
        # the hints list.
        return hints

    def _require_matching_id(self, value, ref):
        """Ensure the value matches the reference's ID, if any."""
        if 'id' in ref and ref['id'] != value:
            raise exception.ValidationError('Cannot change ID')

    def _assign_unique_id(self, ref):
        """Generate and assigns a unique identifier to a reference."""
        ref = ref.copy()
        ref['id'] = uuid.uuid4().hex
        return ref

    def _get_domain_id_for_list_request(self, request):
        """Get the domain_id for a v3 list call.

        If we running with multiple domain drivers, then the caller must
        specify a domain_id either as a filter or as part of the token scope.

        """
        if not CONF.identity.domain_specific_drivers_enabled:
            # We don't need to specify a domain ID in this case
            return

        domain_id = request.params.get('domain_id')
        if domain_id:
            return domain_id

        token_ref = utils.get_token_ref(request.context_dict)

        if token_ref.domain_scoped:
            return token_ref.domain_id
        elif token_ref.project_scoped:
            return token_ref.project_domain_id
        else:
            msg = _('No domain information specified as part of list request')
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

    def _get_domain_id_from_token(self, request):
        """Get the domain_id for a v3 create call.

        In the case of a v3 create entity call that does not specify a domain
        ID, the spec says that we should use the domain scoping from the token
        being used.

        """
        # return if domain scoped
        if request.context.domain_id:
            return request.context.domain_id

        if request.context.is_admin:
            raise exception.ValidationError(
                _('You have tried to create a resource using the admin '
                  'token. As this token is not within a domain you must '
                  'explicitly include a domain for this resource to '
                  'belong to.'))

        # TODO(henry-nash): We should issue an exception here since if
        # a v3 call does not explicitly specify the domain_id in the
        # entity, it should be using a domain scoped token.  However,
        # the current tempest heat tests issue a v3 call without this.
        # This is raised as bug #1283539.  Once this is fixed, we
        # should remove the line below and replace it with an error.
        #
        # Ahead of actually changing the code to raise an exception, we
        # issue a deprecation warning.
        versionutils.report_deprecated_feature(
            LOG,
            _LW('Not specifying a domain during a create user, group or '
                'project call, and relying on falling back to the '
                'default domain, is deprecated as of Liberty. There is no '
                'plan to remove this compatibility, however, future API '
                'versions may remove this, so please specify the domain '
                'explicitly or use a domain-scoped token.'))
        return CONF.identity.default_domain_id

    def _normalize_domain_id(self, request, ref):
        """Fill in domain_id if not specified in a v3 call."""
        if not ref.get('domain_id'):
            ref['domain_id'] = self._get_domain_id_from_token(request)
        return ref

    @staticmethod
    def filter_domain_id(ref):
        """Override v2 filter to let domain_id out for v3 calls."""
        return ref

    def check_protection(self, request, prep_info, target_attr=None):
        """Provide call protection for complex target attributes.

        As well as including the standard parameters from the original API
        call (which is passed in prep_info), this call will add in any
        additional entities or attributes (passed in target_attr), so that
        they can be referenced by policy rules.

        """
        if request.context.is_admin:
            LOG.warning(_LW('RBAC: Bypassing authorization'))
        else:
            action = 'identity:%s' % prep_info['f_name']
            # TODO(henry-nash) need to log the target attributes as well
            creds = _build_policy_check_credentials(self, action,
                                                    request.context_dict,
                                                    prep_info['input_attr'])
            # Build the dict the policy engine will check against from both the
            # parameters passed into the call we are protecting (which was
            # stored in the prep_info by protected()), plus the target
            # attributes provided.
            policy_dict = {}
            if target_attr:
                policy_dict = {'target': target_attr}
            policy_dict.update(prep_info['input_attr'])
            if 'filter_attr' in prep_info:
                policy_dict.update(prep_info['filter_attr'])
            self.policy_api.enforce(creds,
                                    action,
                                    utils.flatten_dict(policy_dict))
            LOG.debug('RBAC: Authorization granted')

    @classmethod
    def filter_params(cls, ref):
        """Remove unspecified parameters from the dictionary.

        This function removes unspecified parameters from the dictionary.
        This method checks only root-level keys from a ref dictionary.

        :param ref: a dictionary representing deserialized response to be
                    serialized
        """
        ref_keys = set(ref.keys())
        blocked_keys = ref_keys - cls._public_parameters
        for blocked_param in blocked_keys:
            del ref[blocked_param]
        return ref

    def _token_validation_window(self, request):
        # NOTE(jamielennox): it's dumb that i have to put this here. We should
        # only validate subject token in one place.
        allow_expired = request.params.get('allow_expired')
        allow_expired = strutils.bool_from_string(allow_expired, default=False)

        return CONF.token.allow_expired_window if allow_expired else 0

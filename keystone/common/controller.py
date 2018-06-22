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
import six

from keystone.common import authorization
from keystone.common import driver_hints
from keystone.common import provider_api
from keystone.common import utils
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _


LOG = log.getLogger(__name__)
CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


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
            check_function = authorization.check_protection
            if callback is not None:
                check_function = callback

            protected_wrapper(
                self, f, check_function, request, None, *args, **kwargs)
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
    def _handle_filters(filters, request):
        target = dict()
        if filters:
            for item in filters:
                if item in request.params:
                    target[item] = request.params[item]

        LOG.debug('RBAC: Adding query filter params (%s)', (
            ', '.join(['%s=%s' % (item, target[item])
                       for item in target])))
        return target

    def _filterprotected(f):
        @functools.wraps(f)
        def wrapper(self, request, **kwargs):
            filter_attr = _handle_filters(filters, request)
            check_function = authorization.check_protection
            if 'callback' in callback and callback['callback'] is not None:
                # A callback has been specified to load additional target
                # data, so pass it the formal url params as well as the
                # list of filters, so it can augment these and then call
                # the check_protection() method.
                check_function = callback['callback']

            protected_wrapper(
                self, f, check_function, request, filter_attr, **kwargs)
            return f(self, request, filters, **kwargs)
        return wrapper
    return _filterprotected


# Unified calls for the decorators above.
# TODO(ayoung):  Continue the refactoring.  Always call check_protection
# explicitly, by removing the calls to check protection from the callbacks.
# Instead,  have a call to the callbacks inserted prior to the call to
# `check_protection`.
def protected_wrapper(self, f, check_function, request, filter_attr,
                      *args, **kwargs):
    request.assert_authenticated()
    if request.context.is_admin:
        LOG.warning('RBAC: Bypassing authorization')
        return
    prep_info = {'f_name': f.__name__,
                 'input_attr': kwargs}
    if (filter_attr):
        prep_info['filter_attr'] = filter_attr
    check_function(self, request, prep_info, *args, **kwargs)


# FIXME(lbragstad): Find a better home for this... I put there here since it's
# needed across a couple different controller (keystone/auth/controllers.py and
# keystone/contrib/ec2/controllers.py both need it). This is technically an
# opinion of how a token should look according to the V3 API contract. My
# thought was to try and work this into a view of a token associated to the V3
# controller logic somewhere.
def render_token_response_from_model(token, include_catalog=True):
    token_reference = {
        'token': {
            'methods': token.methods,
            'user': {
                'domain': {
                    'id': token.user_domain['id'],
                    'name': token.user_domain['name']
                },
                'id': token.user_id,
                'name': token.user['name'],
                'password_expires_at': token.user[
                    'password_expires_at'
                ]
            },
            'audit_ids': token.audit_ids,
            'expires_at': token.expires_at,
            'issued_at': token.issued_at,
        }
    }
    if token.system_scoped:
        token_reference['token']['roles'] = token.roles
        token_reference['token']['system'] = {'all': True}
    elif token.domain_scoped:
        token_reference['token']['domain'] = {
            'id': token.domain['id'],
            'name': token.domain['name']
        }
        token_reference['token']['roles'] = token.roles
    elif token.trust_scoped:
        token_reference['token']['OS-TRUST:trust'] = {
            'id': token.trust_id,
            'trustor_user': {'id': token.trustor['id']},
            'trustee_user': {'id': token.trustee['id']},
            'impersonation': token.trust['impersonation']
        }
        token_reference['token']['project'] = {
            'domain': {
                'id': token.project_domain['id'],
                'name': token.project_domain['name']
            },
            'id': token.trust_project['id'],
            'name': token.trust_project['name']
        }
        if token.trust.get('impersonation'):
            trustor_domain = PROVIDERS.resource_api.get_domain(
                token.trustor['domain_id']
            )
            token_reference['token']['user'] = {
                'domain': {
                    'id': trustor_domain['id'],
                    'name': trustor_domain['name']
                },
                'id': token.trustor['id'],
                'name': token.trustor['name'],
                'password_expires_at': token.trustor[
                    'password_expires_at'
                ]
            }
        token_reference['token']['roles'] = token.roles
    elif token.project_scoped:
        token_reference['token']['project'] = {
            'domain': {
                'id': token.project_domain['id'],
                'name': token.project_domain['name']
            },
            'id': token.project['id'],
            'name': token.project['name']
        }
        token_reference['token']['is_domain'] = token.project.get(
            'is_domain', False
        )
        token_reference['token']['roles'] = token.roles
        ap_name = CONF.resource.admin_project_name
        ap_domain_name = CONF.resource.admin_project_domain_name
        if ap_name and ap_domain_name:
            is_ap = (
                token.project['name'] == ap_name and
                ap_domain_name == token.project_domain['name']
            )
            token_reference['token']['is_admin_project'] = is_ap
    if include_catalog and not token.unscoped:
        user_id = token.user_id
        if token.trust_id:
            user_id = token.trust['trustor_user_id']
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id, token.project_id
        )
        token_reference['token']['catalog'] = catalog
    sps = PROVIDERS.federation_api.get_enabled_service_providers()
    if sps:
        token_reference['token']['service_providers'] = sps
    if token.is_federated:
        PROVIDERS.federation_api.get_idp(token.identity_provider_id)
        federated_dict = {}
        federated_dict['groups'] = token.federated_groups
        federated_dict['identity_provider'] = {
            'id': token.identity_provider_id
        }
        federated_dict['protocol'] = {'id': token.protocol_id}
        token_reference['token']['user']['OS-FEDERATION'] = (
            federated_dict
        )
        token_reference['token']['user']['domain'] = {
            'id': 'Federated', 'name': 'Federated'
        }
        del token_reference['token']['user']['password_expires_at']
    if token.access_token_id:
        token_reference['token']['OS-OAUTH1'] = {
            'access_token_id': token.access_token_id,
            'consumer_id': token.access_token['consumer_id']
        }
    if token.application_credential_id:
        key = 'application_credential'
        token_reference['token'][key] = {}
        token_reference['token'][key]['id'] = (
            token.application_credential['id']
        )
        token_reference['token'][key]['name'] = (
            token.application_credential['name']
        )
        restricted = not token.application_credential['unrestricted']
        token_reference['token'][key]['restricted'] = restricted

    return token_reference


class V3Controller(provider_api.ProviderAPIMixin, wsgi.Application):
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

        token = authorization.get_token_ref(request.context_dict)

        if token.domain_scoped:
            return token.domain_id
        elif token.project_scoped:
            return token.project_domain['id']
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
            'Not specifying a domain during a create user, group or '
            'project call, and relying on falling back to the '
            'default domain, is deprecated as of Liberty. There is no '
            'plan to remove this compatibility, however, future API '
            'versions may remove this, so please specify the domain '
            'explicitly or use a domain-scoped token.')
        return CONF.identity.default_domain_id

    def _normalize_domain_id(self, request, ref):
        """Fill in domain_id if not specified in a v3 call."""
        if not ref.get('domain_id'):
            ref['domain_id'] = self._get_domain_id_from_token(request)
        return ref

    def check_protection(self, request, prep_info, target_attr=None):
        """Provide call protection for complex target attributes.

        As well as including the standard parameters from the original API
        call (which is passed in prep_info), this call will add in any
        additional entities or attributes (passed in target_attr), so that
        they can be referenced by policy rules.

        """
        authorization.check_protection(self, request, prep_info, target_attr)

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

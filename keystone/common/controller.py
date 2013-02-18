import functools
import uuid

from keystone.common import dependency
from keystone.common import logging
from keystone.common import wsgi
from keystone import config
from keystone import exception


LOG = logging.getLogger(__name__)
CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


def _build_policy_check_credentials(self, action, context, kwargs):

    LOG.debug(_('RBAC: Authorizing %s(%s)') % (
        action,
        ', '.join(['%s=%s' % (k, kwargs[k]) for k in kwargs])))

    try:
        token_ref = self.token_api.get_token(
            context=context, token_id=context['token_id'])
    except exception.TokenNotFound:
        LOG.warning(_('RBAC: Invalid token'))
        raise exception.Unauthorized()

    creds = {}
    token_data = token_ref['token_data']

    try:
        creds['user_id'] = token_data['user']['id']
    except AttributeError:
        LOG.warning(_('RBAC: Invalid user'))
        raise exception.Unauthorized()

    if 'project' in token_data:
        creds['project_id'] = token_data['project']['id']
    else:
        LOG.debug(_('RBAC: Proceeding without project'))

    if 'domain' in token_data:
        creds['domain_id'] = token_data['domain']['id']

    if 'roles' in token_data:
        creds['roles'] = []
        for role in token_data['roles']:
            creds['roles'].append(role['name'])

    return creds


def protected(f):
    """Wraps API calls with role based access controls (RBAC)."""

    @functools.wraps(f)
    def wrapper(self, context, **kwargs):
        if not context['is_admin']:
            action = 'identity:%s' % f.__name__
            creds = _build_policy_check_credentials(self, action,
                                                    context, kwargs)
            # Simply use the passed kwargs as the target dict, which
            # would typically include the prime key of a get/update/delete
            # call.
            self.policy_api.enforce(context, creds, action, kwargs)
            LOG.debug(_('RBAC: Authorization granted'))
        else:
            LOG.warning(_('RBAC: Bypassing authorization'))

        return f(self, context, **kwargs)
    return wrapper


def filterprotected(*filters):
    """Wraps filtered API calls with role based access controls (RBAC)."""

    def _filterprotected(f):
        @functools.wraps(f)
        def wrapper(self, context, **kwargs):
            if not context['is_admin']:
                action = 'identity:%s' % f.__name__
                creds = _build_policy_check_credentials(self, action,
                                                        context, kwargs)
                # Now, build the target dict for policy check.  We include:
                #
                # - Any query filter parameters
                # - Data from the main url (which will be in the kwargs
                #   parameter) and would typically include the prime key
                #   of a get/update/delete call
                #
                # TODO(henry-nash) do we need to put the whole object
                # in, which is part of kwargs?  I kept this in as it was part
                # of the previous implementation, but without a specific key
                # reference in the target I don't see how it can be used.

                # First  any query filter parameters
                target = dict()
                if len(filters) > 0:
                    for filter in filters:
                        if filter in context['query_string']:
                            target[filter] = context['query_string'][filter]

                    LOG.debug(_('RBAC: Adding query filter params (%s)') % (
                        ', '.join(['%s=%s' % (filter, target[filter])
                                  for filter in target])))

                # Now any formal url parameters
                for key in kwargs:
                    target[key] = kwargs[key]

                self.policy_api.enforce(context, creds, action, target)

                LOG.debug(_('RBAC: Authorization granted'))
            else:
                LOG.warning(_('RBAC: Bypassing authorization'))
            return f(self, context, filters, **kwargs)
        return wrapper
    return _filterprotected


@dependency.requires('identity_api', 'policy_api', 'token_api')
class V2Controller(wsgi.Application):
    """Base controller class for Identity API v2."""

    def _require_attribute(self, ref, attr):
        """Ensures the reference contains the specified attribute."""
        if ref.get(attr) is None or ref.get(attr) == '':
            msg = '%s field is required and cannot be empty' % attr
            raise exception.ValidationError(message=msg)

    def _normalize_domain_id(self, context, ref):
        """Fill in domain_id since v2 calls are not domain-aware.

        This will overwrite any domain_id that was inadvertently
        specified in the v2 call.

        """
        ref['domain_id'] = DEFAULT_DOMAIN_ID
        return ref

    def _filter_domain_id(self, ref):
        """Remove domain_id since v2 calls are not domain-aware."""
        ref.pop('domain_id', None)
        return ref


class V3Controller(V2Controller):
    """Base controller class for Identity API v3.

    Child classes should set the ``collection_name`` and ``member_name`` class
    attributes, representing the collection of entities they are exposing to
    the API. This is required for supporting self-referential links,
    pagination, etc.

    """

    collection_name = 'entities'
    member_name = 'entity'

    @classmethod
    def base_url(cls, path=None):
        endpoint = CONF.public_endpoint % CONF

        # allow a missing trailing slash in the config
        if endpoint[-1] != '/':
            endpoint += '/'

        url = endpoint + 'v3'

        if path:
            return url + path
        else:
            return url + '/' + cls.collection_name

    @classmethod
    def _add_self_referential_link(cls, ref):
        ref.setdefault('links', {})
        ref['links']['self'] = cls.base_url() + '/' + ref['id']

    @classmethod
    def wrap_member(cls, context, ref):
        cls._add_self_referential_link(ref)
        return {cls.member_name: ref}

    @classmethod
    def wrap_collection(cls, context, refs, filters=[]):
        for f in filters:
            refs = cls.filter_by_attribute(context, refs, f)

        refs = cls.paginate(context, refs)

        for ref in refs:
            cls.wrap_member(context, ref)

        container = {cls.collection_name: refs}
        container['links'] = {
            'next': None,
            'self': cls.base_url(path=context['path']),
            'previous': None}
        return container

    @classmethod
    def paginate(cls, context, refs):
        """Paginates a list of references by page & per_page query strings."""
        # FIXME(dolph): client needs to support pagination first
        return refs

        page = context['query_string'].get('page', 1)
        per_page = context['query_string'].get('per_page', 30)
        return refs[per_page * (page - 1):per_page * page]

    @classmethod
    def filter_by_attribute(cls, context, refs, attr):
        """Filters a list of references by query string value."""
        if attr in context['query_string']:
            value = context['query_string'][attr]
            return [r for r in refs if r[attr] == value]
        return refs

    def _require_matching_id(self, value, ref):
        """Ensures the value matches the reference's ID, if any."""
        if 'id' in ref and ref['id'] != value:
            raise exception.ValidationError('Cannot change ID')

    def _assign_unique_id(self, ref):
        """Generates and assigns a unique identifer to a reference."""
        ref = ref.copy()
        ref['id'] = uuid.uuid4().hex
        return ref

    def _normalize_domain_id(self, context, ref):
        """Fill in domain_id if not specified in a v3 call."""

        if 'domain_id' not in ref:
            if context['is_admin']:
                ref['domain_id'] = DEFAULT_DOMAIN_ID
            else:
                # Fish the domain_id out of the token
                #
                # We could make this more efficient by loading the domain_id
                # into the context in the wrapper function above (since
                # this version of normalize_domain will only be called inside
                # a v3 protected call).  However, given that we only use this
                # for creating entities, this optimization is probably not
                # worth the duplication of state
                try:
                    token_ref = self.token_api.get_token(
                        context=context, token_id=context['token_id'])
                except exception.TokenNotFound:
                    LOG.warning(_('Invalid token in normalize_domain_id'))
                    raise exception.Unauthorized()

                if 'domain' in token_ref:
                    ref['domain_id'] = token_ref['domain']['id']
                else:
                    # FIXME(henry-nash) Revisit this once v3 token scoping
                    # across domains has been hashed out
                    ref['domain_id'] = DEFAULT_DOMAIN_ID
        return ref

    def _filter_domain_id(self, ref):
        """Override v2 filter to let domain_id out for v3 calls."""
        return ref

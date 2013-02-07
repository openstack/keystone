import functools
import uuid

from keystone.common import dependency
from keystone.common import logging
from keystone.common import wsgi
from keystone import config
from keystone import exception


LOG = logging.getLogger(__name__)
CONF = config.CONF


def protected(f):
    """Wraps API calls with role based access controls (RBAC)."""

    @functools.wraps(f)
    def wrapper(self, context, **kwargs):
        if not context['is_admin']:
            action = 'identity:%s' % f.__name__

            LOG.debug(_('RBAC: Authorizing %s(%s)') % (
                action,
                ', '.join(['%s=%s' % (k, kwargs[k]) for k in kwargs])))

            try:
                token_ref = self.token_api.get_token(
                    context=context, token_id=context['token_id'])
            except exception.TokenNotFound:
                LOG.warning(_('RBAC: Invalid token'))
                raise exception.Unauthorized()

            creds = token_ref['metadata'].copy()

            try:
                creds['user_id'] = token_ref['user'].get('id')
            except AttributeError:
                LOG.warning(_('RBAC: Invalid user'))
                raise exception.Unauthorized()

            try:
                creds['tenant_id'] = token_ref['tenant'].get('id')
            except AttributeError:
                LOG.debug(_('RBAC: Proceeding without tenant'))

            # NOTE(vish): this is pretty inefficient
            creds['roles'] = [self.identity_api.get_role(context, role)['name']
                              for role in creds.get('roles', [])]

            self.policy_api.enforce(context, creds, action, kwargs)

            LOG.debug(_('RBAC: Authorization granted'))
        else:
            LOG.warning(_('RBAC: Bypassing authorization'))

        return f(self, context, **kwargs)
    return wrapper


@dependency.requires('identity_api', 'policy_api', 'token_api')
class V2Controller(wsgi.Application):
    """Base controller class for Identity API v2."""

    def _require_attribute(self, ref, attr):
        """Ensures the reference contains the specified attribute."""
        if ref.get(attr) is None or ref.get(attr) == '':
            msg = '%s field is required and cannot be empty' % attr
            raise exception.ValidationError(message=msg)


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
    def wrap_collection(cls, context, refs):
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

    def _require_matching_id(self, value, ref):
        """Ensures the value matches the reference's ID, if any."""
        if 'id' in ref and ref['id'] != value:
            raise exception.ValidationError('Cannot change ID')

    def _assign_unique_id(self, ref):
        """Generates and assigns a unique identifer to a reference."""
        ref = ref.copy()
        ref['id'] = uuid.uuid4().hex
        return ref

    def _filter_by_attribute(self, context, refs, attr):
        """Filters a list of references by query string value."""
        if attr in context['query_string']:
            value = context['query_string'][attr]
            return [r for r in refs if r[attr] == value]
        return refs

import uuid

from keystone.common import wsgi
from keystone import exception


class V3Controller(wsgi.Application):
    """Base controller class for Identity API v3."""

    def __init__(self, catalog_api, identity_api, token_api, policy_api):
        self.catalog_api = catalog_api
        self.identity_api = identity_api
        self.policy_api = policy_api
        self.token_api = token_api
        super(V3Controller, self).__init__()

    def _paginate(self, context, refs):
        """Paginates a list of references by page & per_page query strings."""
        page = context['query_string'].get('page', 1)
        per_page = context['query_string'].get('per_page', 30)
        return refs[per_page * (page - 1):per_page * page]

    def _require_attribute(self, ref, attr):
        """Ensures the reference contains the specified attribute."""
        if ref.get(attr) is None or ref.get(attr) == '':
            msg = '%s field is required and cannot be empty' % attr
            raise exception.ValidationError(message=msg)

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

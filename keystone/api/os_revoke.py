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

# This file handles all flask-restful resources for /v3/OS-REVOKE/events

import flask
import flask_restful
from oslo_utils import timeutils

from keystone.api._shared import json_home_relations
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask


PROVIDERS = provider_api.ProviderAPIs
ENFORCER = rbac_enforcer.RBACEnforcer


_build_resource_relation = json_home_relations.os_revoke_resource_rel_func


class OSRevokeResource(flask_restful.Resource):
    def get(self):
        ENFORCER.enforce_call(action='identity:list_revoke_events')
        since = flask.request.args.get('since')
        last_fetch = None
        if since:
            try:
                last_fetch = timeutils.normalize_time(
                    timeutils.parse_isotime(since))
            except ValueError:
                raise exception.ValidationError(
                    message=_('invalidate date format %s') % since)
        # FIXME(notmorgan): The revocation events cannot have resource options
        # added to them or lazy-loaded relationships as long as to_dict
        # is called outside of an active session context. This API is unused
        # and should be deprecated in the near future. Fix this before adding
        # resource_options or any lazy-loaded relationships to the revocation
        # events themselves.
        events = PROVIDERS.revoke_api.list_events(last_fetch=last_fetch)
        # Build the links by hand as the standard controller calls require ids
        response = {'events': [event.to_dict() for event in events],
                    'links': {
                        'next': None,
                        'self': ks_flask.base_url(path='/OS-REVOKE/events'),
                        'previous': None}
                    }
        return response


class OSRevokeAPI(ks_flask.APIBase):
    _name = 'events'
    _import_name = __name__
    _api_url_prefix = '/OS-REVOKE'
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=OSRevokeResource,
            url='/events',
            resource_kwargs={},
            rel='events',
            resource_relation_func=_build_resource_relation
        )
    ]


APIs = (OSRevokeAPI,)

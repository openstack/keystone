# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 - 2012 Justin Santa Barbara
# All Rights Reserved.
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

from oslo_log import log

from keystone import exception
from keystone.i18n import _, _LW
from keystone.models import token_model


AUTH_CONTEXT_ENV = 'KEYSTONE_AUTH_CONTEXT'
"""Environment variable used to convey the Keystone auth context.

Auth context is essentially the user credential used for policy enforcement.
It is a dictionary with the following attributes:

* ``user_id``: user ID of the principal
* ``project_id`` (optional): project ID of the scoped project if auth is
                             project-scoped
* ``domain_id`` (optional): domain ID of the scoped domain if auth is
                            domain-scoped
* ``roles`` (optional): list of role names for the given scope
* ``group_ids``: list of group IDs for which the API user has membership

"""

LOG = log.getLogger(__name__)


def token_to_auth_context(token):
    if not isinstance(token, token_model.KeystoneToken):
        raise exception.UnexpectedError(_('token reference must be a '
                                          'KeystoneToken type, got: %s') %
                                        type(token))
    auth_context = {'token': token,
                    'is_delegated_auth': False}
    try:
        auth_context['user_id'] = token.user_id
    except KeyError:
        LOG.warning(_LW('RBAC: Invalid user data in token'))
        raise exception.Unauthorized()

    if token.project_scoped:
        auth_context['project_id'] = token.project_id
    elif token.domain_scoped:
        auth_context['domain_id'] = token.domain_id
    else:
        LOG.debug('RBAC: Proceeding without project or domain scope')

    if token.trust_scoped:
        auth_context['is_delegated_auth'] = True
        auth_context['trust_id'] = token.trust_id
        auth_context['trustor_id'] = token.trustor_user_id
        auth_context['trustee_id'] = token.trustee_user_id
    else:
        auth_context['trust_id'] = None
        auth_context['trustor_id'] = None
        auth_context['trustee_id'] = None

    roles = token.role_names
    if roles:
        auth_context['roles'] = roles

    if token.oauth_scoped:
        auth_context['is_delegated_auth'] = True
    auth_context['consumer_id'] = token.oauth_consumer_id
    auth_context['access_token_id'] = token.oauth_access_token_id

    if token.is_federated_user:
        auth_context['group_ids'] = token.federation_group_ids

    return auth_context

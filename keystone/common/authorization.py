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

import collections

from keystone.contrib import federation
from keystone import exception
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log


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


def flatten(d, parent_key=''):
    """Flatten a nested dictionary

    Converts a dictionary with nested values to a single level flat
    dictionary, with dotted notation for each key.

    """
    items = []
    for k, v in d.items():
        new_key = parent_key + '.' + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key).items())
        else:
            items.append((new_key, v))
    return dict(items)


def is_v3_token(token):
    # V3 token data are encapsulated into "token" key while
    # V2 token data are encapsulated into "access" key.
    return 'token' in token


def v3_token_to_auth_context(token):
    creds = {'is_delegated_auth': False}
    token_data = token['token']
    try:
        creds['user_id'] = token_data['user']['id']
    except AttributeError:
        LOG.warning(_('RBAC: Invalid user data in v3 token'))
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
    creds['group_ids'] = [
        g['id'] for g in token_data['user'].get(federation.FEDERATION, {}).get(
            'groups', [])]

    trust = token_data.get('OS-TRUST:trust')
    if trust is None:
        creds['trust_id'] = None
        creds['trustor_id'] = None
        creds['trustee_id'] = None
    else:
        creds['trust_id'] = trust['id']
        creds['trustor_id'] = trust['trustor_user']['id']
        creds['trustee_id'] = trust['trustee_user']['id']
        creds['is_delegated_auth'] = True

    oauth1 = token_data.get('OS-OAUTH1')
    if oauth1 is None:
        creds['consumer_id'] = None
        creds['access_token_id'] = None
    else:
        creds['consumer_id'] = oauth1['consumer_id']
        creds['access_token_id'] = oauth1['access_token_id']
        creds['is_delegated_auth'] = True
    return creds


def v2_token_to_auth_context(token):
    creds = {'is_delegated_auth': False}
    token_data = token['access']
    try:
        creds['user_id'] = token_data['user']['id']
    except AttributeError:
        LOG.warning(_('RBAC: Invalid user data in v2 token'))
        raise exception.Unauthorized()
    if 'tenant' in token_data['token']:
        creds['project_id'] = token_data['token']['tenant']['id']
    else:
        LOG.debug(_('RBAC: Proceeding without tenant'))
    if 'roles' in token_data['user']:
        creds['roles'] = [role['name'] for
                          role in token_data['user']['roles']]

    trust = token_data.get('trust')
    if trust is None:
        creds['trust_id'] = None
        creds['trustor_id'] = None
        creds['trustee_id'] = None
    else:
        creds['trust_id'] = trust.get('id')
        creds['trustor_id'] = trust.get('trustor_id')
        creds['trustee_id'] = trust.get('trustee_id')
        creds['is_delegated_auth'] = True

    return creds


def token_to_auth_context(token):
    if is_v3_token(token):
        creds = v3_token_to_auth_context(token)
    else:
        creds = v2_token_to_auth_context(token)
    return creds

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

from keystone.api import auth
from keystone.api import credentials
from keystone.api import discovery
from keystone.api import domains
from keystone.api import ec2tokens
from keystone.api import endpoints
from keystone.api import groups
from keystone.api import limits
from keystone.api import os_ep_filter
from keystone.api import os_federation
from keystone.api import os_inherit
from keystone.api import os_oauth1
from keystone.api import os_oauth2
from keystone.api import os_revoke
from keystone.api import os_simple_cert
from keystone.api import policy
from keystone.api import projects
from keystone.api import regions
from keystone.api import registered_limits
from keystone.api import role_assignments
from keystone.api import role_inferences
from keystone.api import roles
from keystone.api import s3tokens
from keystone.api import services
from keystone.api import system
from keystone.api import trusts
from keystone.api import users

__all__ = (
    'auth',
    'discovery',
    'credentials',
    'domains',
    'ec2tokens',
    'endpoints',
    'groups',
    'limits',
    'os_ep_filter',
    'os_federation',
    'os_inherit',
    'os_oauth1',
    'os_oauth2',
    'os_revoke',
    'os_simple_cert',
    'policy',
    'projects',
    'regions',
    'registered_limits',
    'role_assignments',
    'role_inferences',
    'roles',
    's3tokens',
    'services',
    'system',
    'trusts',
    'users',
)

__apis__ = (
    discovery,
    auth,
    credentials,
    domains,
    ec2tokens,
    endpoints,
    groups,
    limits,
    os_ep_filter,
    os_federation,
    os_inherit,
    os_oauth1,
    os_oauth2,
    os_revoke,
    os_simple_cert,
    policy,
    projects,
    regions,
    registered_limits,
    role_assignments,
    role_inferences,
    roles,
    s3tokens,
    services,
    system,
    trusts,
    users,
)

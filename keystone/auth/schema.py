# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import validation
from keystone.common.validation import parameter_types
from keystone import exception
from keystone.i18n import _


token_issue = {
    'type': 'object',
    'properties': {
        'identity': {
            'type': 'object',
            'properties': {
                'methods': {
                    'type': 'array',
                    'items': {'type': 'string', },
                },
                'password': {
                    'type': 'object',
                    'properties': {
                        'user': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'string', },
                                'name': {'type': 'string', },
                                'password': {'type': 'string', },
                                'domain': {
                                    'type': 'object',
                                    'properties': {
                                        'id': {'type': 'string', },
                                        'name': {'type': 'string', },
                                    },
                                },
                            },
                        },
                    },
                },
                'token': {
                    'type': 'object',
                    'properties': {
                        'id': {
                            'type': 'string',
                        },
                    },
                    'required': ['id', ],
                },
            },
            'required': ['methods', ],
        },
        'scope': {
            # For explicit unscoped authentication the type should not be
            # strictly string. Although keystone server specifies the value
            # to be 'unscoped', old versions of keystoneauth might still be
            # using `"scope": {'unscoped': {}}` instead of
            # `"scope": "unscoped"`
            # https://bugs.launchpad.net/keystoneauth/+bug/1637682/
            'type': ['object', 'string'],
            'properties': {
                'project': {
                    'type': 'object',
                    'properties': {
                        'name': {'type': 'string', },
                        'id': {'type': 'string', },
                        'domain': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'string', },
                                'name': {'type': 'string', },
                            },
                        },
                    },
                },
                'domain': {
                    'type': 'object',
                    'properties': {
                        'id': {'type': 'string', },
                        'name': {'type': 'string', },
                    },
                },
                'OS-TRUST:trust': {
                    'type': 'object',
                    'properties': {
                        'id': {'type': 'string', },
                    }
                },
                'system': {
                    'type': 'object',
                    'properties': {
                        'all': parameter_types.boolean
                    }
                }
            },
        },
    },
    'required': ['identity', ],
}


def validate_issue_token_auth(auth=None):
    if auth is None:
        return
    validation.lazy_validate(token_issue, auth)

    user = auth['identity'].get('password', {}).get('user')
    if user is not None:
        if 'id' not in user and 'name' not in user:
            msg = _('Invalid input for field identity/password/user: '
                    'id or name must be present.')
            raise exception.SchemaValidationError(detail=msg)

        domain = user.get('domain')
        if domain is not None:
            if 'id' not in domain and 'name' not in domain:
                msg = _(
                    'Invalid input for field identity/password/user/domain: '
                    'id or name must be present.')
                raise exception.SchemaValidationError(detail=msg)

    scope = auth.get('scope')
    if scope is not None and isinstance(scope, dict):
        project = scope.get('project')
        if project is not None:
            if 'id' not in project and 'name' not in project:
                msg = _(
                    'Invalid input for field scope/project: '
                    'id or name must be present.')
                raise exception.SchemaValidationError(detail=msg)
            domain = project.get('domain')
            if domain is not None:
                if 'id' not in domain and 'name' not in domain:
                    msg = _(
                        'Invalid input for field scope/project/domain: '
                        'id or name must be present.')
                    raise exception.SchemaValidationError(detail=msg)
        domain = scope.get('domain')
        if domain is not None:
            if 'id' not in domain and 'name' not in domain:
                msg = _(
                    'Invalid input for field scope/domain: '
                    'id or name must be present.')
                raise exception.SchemaValidationError(detail=msg)

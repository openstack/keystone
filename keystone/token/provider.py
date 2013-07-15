# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Token provider interface."""


from keystone.common import dependency
from keystone.common import logging
from keystone.common import manager
from keystone import config
from keystone import exception


CONF = config.CONF
LOG = logging.getLogger(__name__)


# supported token versions
V2 = 'v2.0'
V3 = 'v3.0'


class UnsupportedTokenVersionException(Exception):
    """Token version is unrecognizable or unsupported."""
    pass


@dependency.provider('token_provider_api')
class Manager(manager.Manager):
    """Default pivot point for the token provider backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        # FIXME(gyee): we are deprecating CONF.signing.token_format. This code
        # is to ensure the token provider configuration agrees with
        # CONF.signing.token_format.
        if ((CONF.signing.token_format == 'PKI' and
                not CONF.token.provider.endswith('.pki.Provider')) or
                (CONF.signing.token_format == 'UUID' and
                    not CONF.token.provider.endswith('uuid.Provider'))):
            raise ValueError('token_format conflicts with token provider')

        super(Manager, self).__init__(CONF.token.provider)


class Provider(object):
    """Interface description for a Token provider."""

    def get_token_version(self, token_data):
        """Return the version of the given token data.

        If the given token data is unrecognizable,
        UnsupportedTokenVersionException is raised.

        """
        raise exception.NotImplemented()

    def issue_token(self, version='v3.0', **kwargs):
        """Issue a V3 token.

        For V3 tokens, 'user_id', 'method_names', must present in kwargs.
        Optionally, kwargs may contain 'expires_at' for rescope tokens;
        'project_id' for project-scoped token; 'domain_id' for
        domain-scoped token; and 'auth_context' from the authentication
        plugins.

        :param context: request context
        :type context: dictionary
        :param version: version of the token to be issued
        :type version: string
        :param kwargs: information needed for token creation. Parameters
                       may be different depending on token version.
        :type kwargs: dictionary
        :returns: (token_id, token_data)

        """
        raise exception.NotImplemented()

    def revoke_token(self, token_id):
        """Revoke a given token.

        :param token_id: identity of the token
        :type token_id: string
        :returns: None.
        """
        raise exception.NotImplemented()

    def validate_token(self, token_id, belongs_to=None, version='v3.0'):
        """Validate the given token and return the token data.

        Must raise Unauthorized exception if unable to validate token.

        :param token_id: identity of the token
        :type token_id: string
        :param belongs_to: identity of the scoped project to validate
        :type belongs_to: string
        :param version: version of the token to be validated
        :type version: string
        :returns: token data
        :raises: keystone.exception.Unauthorized

        """
        raise exception.NotImplemented()

    def check_token(self, token_id, belongs_to=None, version='v3.0'):
        """Check the validity of the given V3 token.

        Must raise Unauthorized exception if  unable to check token.

        :param token_id: identity of the token
        :type token_id: string
        :param belongs_to: identity of the scoped project to validate
        :type belongs_to: string
        :param version: version of the token to check
        :type version: string
        :returns: None
        :raises: keystone.exception.Unauthorized

        """

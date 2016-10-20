# Copyright 2012 OpenStack Foundation
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

import abc

import six

from keystone import exception


@six.add_metaclass(abc.ABCMeta)
class Provider(object):
    """Interface description for a Token provider."""

    @abc.abstractmethod
    def needs_persistence(self):
        """Determine if the token should be persisted.

        If the token provider requires that the token be persisted to a
        backend this should return True, otherwise return False.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_token_version(self, token_data):
        """Return the version of the given token data.

        If the given token data is unrecognizable,
        UnsupportedTokenVersionException is raised.

        :param token_data: token_data
        :type token_data: dict
        :returns: token version string
        :raises keystone.exception.UnsupportedTokenVersionException:
            If the token version is not expected.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def issue_token(self, user_id, method_names, expires_at=None,
                    project_id=None, domain_id=None, auth_context=None,
                    trust=None, include_catalog=True, parent_audit_id=None):
        """Issue a V3 Token.

        :param user_id: identity of the user
        :type user_id: string
        :param method_names: names of authentication methods
        :type method_names: list
        :param expires_at: optional time the token will expire
        :type expires_at: string
        :param project_id: optional project identity
        :type project_id: string
        :param domain_id: optional domain identity
        :type domain_id: string
        :param auth_context: optional context from the authorization plugins
        :type auth_context: dict
        :param trust: optional trust reference
        :type trust: dict
        :param include_catalog: optional, include the catalog in token data
        :type include_catalog: boolean
        :param parent_audit_id: optional, the audit id of the parent token
        :type parent_audit_id: string
        :returns: (token_id, token_data)
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def validate_token(self, token_ref):
        """Validate the given V3 token and return the token_data.

        :param token_ref: the token reference
        :type token_ref: dict
        :returns: token data
        :raises keystone.exception.TokenNotFound: If the token doesn't exist.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def _get_token_id(self, token_data):
        """Generate the token_id based upon the data in token_data.

        :param token_data: token information
        :type token_data: dict
        :returns: token identifier
        :rtype: six.text_type
        """
        raise exception.NotImplemented()  # pragma: no cover

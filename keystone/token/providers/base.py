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

from keystone import exception


class Provider(object, metaclass=abc.ABCMeta):
    """Interface description for a Token provider."""

    @abc.abstractmethod
    def validate_token(self, token_id):
        """Validate a given token by its ID and return the token_data.

        :param token_id: the unique ID of the token
        :type token_id: str
        :returns: token data as a tuple in the form of:

        (user_id, methods, audit_ids, system, domain_id, project_id,
         trust_id, federated_group_ids, identity_provider_id, protocol_id,
         access_token_id, app_cred_id, issued_at, expires_at)

        ``user_id`` is the unique ID of the user as a string
        ``methods`` a list of authentication methods used to obtain the token
        ``audit_ids`` a list of audit IDs for the token
        ``system`` a dictionary containing system scope if system-scoped
        ``domain_id`` the unique ID of the domain if domain-scoped
        ``project_id`` the unique ID of the project if project-scoped
        ``trust_id`` the unique identifier of the trust if trust-scoped
        ``federated_group_ids`` list of federated group IDs
        ``identity_provider_id`` unique ID of the user's identity provider
        ``protocol_id`` unique ID of the protocol used to obtain the token
        ``access_token_id`` the unique ID of the access_token for OAuth1 tokens
        ``app_cred_id`` the unique ID of the application credential
        ``issued_at`` a datetime object of when the token was minted
        ``expires_at`` a datetime object of when the token expires

        :raises keystone.exception.TokenNotFound: If the token doesn't exist.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def generate_id_and_issued_at(self, token):
        """Generate a token based on the information provided.

        :param token: A token object containing information about the
                      authorization context of the request.
        :type token: `keystone.models.token.TokenModel`
        :returns: tuple containing an ID for the token and the issued at time
                  of the token (token_id, issued_at).
        """
        raise exception.NotImplemented()  # pragma: no cover

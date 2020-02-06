# Copyright 2018 SUSE Linux GmbH
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


class ApplicationCredentialDriverBase(object, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def authenticate(self, application_credential_id, secret):
        """Validate an application credential.

        :param str application_credential_id: Application Credential ID
        :param str secret: Secret

        :raises AssertionError: If id or secret is invalid.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_application_credential(self, application_credential, roles):
        """Create a new application credential.

        :param dict application_credential: Application Credential data
        :param list roles: A list of roles that apply to the
                           application_credential.
        :returns: a new application credential
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_application_credential(self, application_credential_id):
        """Get an application credential by the credential id.

        :param str application_credential_id: Application Credential ID
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_application_credentials_for_user(self, user_id, hints):
        """List application credentials for a user.

        :param str user_id: User ID
        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_application_credential(self, application_credential_id):
        """Delete a single application credential.

        :param str application_credential_id: ID of the application credential
            to delete.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_application_credentials_for_user(self, user_id):
        """Delete all application credentials for a user.

        :param user_id: ID of a user to whose application credentials should
            be deleted.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_application_credentials_for_user_on_project(self, user_id,
                                                           project_id):
        """Delete all application credentials for a user on a given project.

        :param str user_id: ID of a user to whose application credentials
            should be deleted.
        :param str project_id: ID of a project on which to filter application
            credentials.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_access_rule(self, access_rule_id):
        """Get an access rule by its ID.

        :param str access_rule_id: Access Rule ID
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_access_rules_for_user(self, user_id):
        """List the access rules that a user has created.

        Access rules are only created as attributes of application credentials,
        they cannot be created independently.

        :param str user_id: User ID
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_access_rule(self, access_rule_id):
        """Delete one access rule.

        :param str access_rule_id: Access Rule ID
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_access_rules_for_user(self, user_id):
        """Delete all access rules for user.

        This is called when the user itself is deleted.

        :param str user_id: User ID
        """
        raise exception.NotImplemented()  # pragma: no cover

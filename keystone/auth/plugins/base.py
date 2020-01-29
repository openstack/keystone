# Copyright 2013 OpenStack Foundation
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
import collections

from keystone.common import provider_api
from keystone import exception


AuthHandlerResponse = collections.namedtuple(
    'AuthHandlerResponse', 'status, response_body, response_data')


class AuthMethodHandler(provider_api.ProviderAPIMixin, object,
                        metaclass=abc.ABCMeta):
    """Abstract base class for an authentication plugin."""

    def __init__(self):
        pass

    @abc.abstractmethod
    def authenticate(self, auth_payload):
        """Authenticate user and return an authentication context.

        :param auth_payload: the payload content of the authentication request
                             for a given method
        :type auth_payload: dict

        If successful, plugin must set ``user_id`` in ``response_data``.
        ``method_name`` is used to convey any additional authentication methods
        in case authentication is for re-scoping. For example, if the
        authentication is for re-scoping, plugin must append the previous
        method names into ``method_names``; NOTE: This behavior is exclusive
        to the re-scope type action. Here's an example of ``response_data`` on
        successful authentication::

            {
                "methods": [
                    "password",
                    "token"
                ],
                "user_id": "abc123"
            }

        Plugins are invoked in the order in which they are specified in the
        ``methods`` attribute of the ``identity`` object. For example,
        ``custom-plugin`` is invoked before ``password``, which is invoked
        before ``token`` in the following authentication request::

            {
                "auth": {
                    "identity": {
                        "custom-plugin": {
                            "custom-data": "sdfdfsfsfsdfsf"
                        },
                        "methods": [
                            "custom-plugin",
                            "password",
                            "token"
                        ],
                        "password": {
                            "user": {
                                "id": "s23sfad1",
                                "password": "secret"
                            }
                        },
                        "token": {
                            "id": "sdfafasdfsfasfasdfds"
                        }
                    }
                }
            }

        :returns: AuthHandlerResponse with status set to ``True`` if auth was
                  successful. If `status` is ``False`` and this is a multi-step
                  auth, the ``response_body`` can be in a form of a dict for
                  the next step in authentication.

        :raises keystone.exception.Unauthorized: for authentication failure
        """
        raise exception.Unauthorized()

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

import six

from keystone import exception


@six.add_metaclass(abc.ABCMeta)
class AuthMethodHandler(object):
    """Abstract base class for an authentication plugin."""

    def __init__(self):
        pass

    @abc.abstractmethod
    def authenticate(self, context, auth_payload, auth_context):
        """Authenticate user and return an authentication context.

        :param context: keystone's request context
        :param auth_payload: the content of the authentication for a given
                             method
        :param auth_context: user authentication context, a dictionary shared
                             by all plugins. It contains "method_names" and
                             "extras" by default. "method_names" is a list and
                             "extras" is a dictionary.

        If successful, plugin must set ``user_id`` in ``auth_context``.
        ``method_name`` is used to convey any additional authentication methods
        in case authentication is for re-scoping. For example, if the
        authentication is for re-scoping, plugin must append the previous
        method names into ``method_names``. Also, plugin may add any additional
        information into ``extras``. Anything in ``extras`` will be conveyed in
        the token's ``extras`` attribute. Here's an example of ``auth_context``
        on successful authentication::

            {
                "extras": {},
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
                                "password": "secrete"
                            }
                        },
                        "token": {
                            "id": "sdfafasdfsfasfasdfds"
                        }
                    }
                }
            }

        :returns: None if authentication is successful.
                  Authentication payload in the form of a dictionary for the
                  next authentication step if this is a multi step
                  authentication.
        :raises: exception.Unauthorized for authentication failure
        """
        raise exception.Unauthorized()

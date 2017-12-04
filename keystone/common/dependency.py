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

"""This module provides support for dependency injection.

Providers are registered via the ``@provider()`` decorator, and dependencies on
them are registered with ``@requires()``. Providers are available to their
consumers via an attribute. See the documentation for the individual functions
for more detail.

See also:

    https://en.wikipedia.org/wiki/Dependency_injection

"""

from keystone.common import provider_api
from keystone.i18n import _


REGISTRY = provider_api.ProviderAPIs


GET_REQUIRED = object()
GET_OPTIONAL = object()


def get_provider(name, optional=GET_REQUIRED):
    return None


class UnresolvableDependencyException(Exception):
    """Raised when a required dependency is not resolvable.

    See ``resolve_future_dependencies()`` for more details.

    """

    def __init__(self, name, targets):
        msg = _('Unregistered dependency: %(name)s for %(targets)s') % {
            'name': name, 'targets': targets}
        super(UnresolvableDependencyException, self).__init__(msg)


def provider(name):
    """Deprecated, does nothing."""
    def wrapper(cls):
        return cls
    return wrapper


def requires(*dependencies):
    """Deprecated, does nothing."""
    def wrapped(cls):
        return cls
    return wrapped


def resolve_future_dependencies(__provider_name=None):
    """Deprecated, does nothing."""
    return {}


def reset():
    """Deprecated, does nothing."""

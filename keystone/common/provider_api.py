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

ProviderAPIs = None


def _create_provider_api_instance():
    class _ProviderAPIs(object):

        def __init__(self):
            self.__registry = {}
            self.__locked = False

            self.__iter__ = self.__registry.__iter__
            self.__getitem__ = self.__registry.__getitem__

        def __getattr__(self, item):
            """Do attr lookup."""
            try:
                return self.__registry[item]
            except KeyError:
                raise AttributeError(
                    "'ProviderAPIs' has no attribute %s" % item)

        def _register_provider_api(self, name, obj):
            """Register an instance of a class as a provider api."""
            if name == 'driver':
                raise ValueError('A provider may not be named "driver".')

            if self.__locked:
                raise RuntimeError(
                    'Programming Error: The provider api registry has been '
                    'locked (post configuration). Ensure all provider api '
                    'managers are instantiated before locking.')

            if name in self.__registry:
                raise DuplicateProviderError(
                    '`%(name)s` has already been registered as an api '
                    'provider by `%(prov)r`' % {'name': name,
                                                'prov': self.__registry[name]})
            self.__registry[name] = obj

        def _clear_registry_instances(self):
            """ONLY USED FOR TESTING."""
            self.__registry.clear()
            self.__locked = False

        def lock_provider_registry(self):
            self.__locked = True

    global ProviderAPIs
    if ProviderAPIs is None:
        ProviderAPIs = _ProviderAPIs()
    else:
        raise RuntimeError('Programming Error: ProviderAPIs object cannot be '
                           'instatiated more than one time. It is meant to '
                           'act as a singleton.')


class DuplicateProviderError(Exception):
    """Attempting to register a duplicate API provider."""


class ProviderAPIMixin(object):
    """Allow referencing provider apis on self via __getattr__.

    Be sure this class is first in the class definition for inheritance.
    """

    def __getattr__(self, item):
        """Magic getattr method."""
        try:
            return getattr(ProviderAPIs, item)
        except AttributeError:
            return self.__getattribute__(item)


_create_provider_api_instance()

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

import traceback

from keystone.i18n import _


_REGISTRY = {}

_future_dependencies = {}
_factories = {}


def _set_provider(name, provider):
    _original_provider, where_registered = _REGISTRY.get(name, (None, None))
    if where_registered:
        raise Exception('%s already has a registered provider, at\n%s' %
                        (name, ''.join(where_registered)))
    _REGISTRY[name] = (provider, traceback.format_stack())


GET_REQUIRED = object()
GET_OPTIONAL = object()


def get_provider(name, optional=GET_REQUIRED):
    if optional is GET_REQUIRED:
        return _REGISTRY[name][0]
    return _REGISTRY.get(name, (None, None))[0]


class UnresolvableDependencyException(Exception):
    """Raised when a required dependency is not resolvable.

    See ``resolve_future_dependencies()`` for more details.

    """
    def __init__(self, name, targets):
        msg = _('Unregistered dependency: %(name)s for %(targets)s') % {
            'name': name, 'targets': targets}
        super(UnresolvableDependencyException, self).__init__(msg)


def provider(name):
    """A class decorator used to register providers.

    When ``@provider()`` is used to decorate a class, members of that class
    will register themselves as providers for the named dependency. As an
    example, In the code fragment::

        @dependency.provider('foo_api')
        class Foo:
            def __init__(self):
                ...

            ...

        foo = Foo()

    The object ``foo`` will be registered as a provider for ``foo_api``. No
    more than one such instance should be created; additional instances will
    replace the previous ones, possibly resulting in different instances being
    used by different consumers.

    """
    def wrapper(cls):
        def wrapped(init):
            def __wrapped_init__(self, *args, **kwargs):
                """Initialize the wrapped object and add it to the registry."""
                init(self, *args, **kwargs)
                _set_provider(name, self)
                resolve_future_dependencies(__provider_name=name)

            return __wrapped_init__

        cls.__init__ = wrapped(cls.__init__)
        _factories[name] = cls
        return cls
    return wrapper


def _process_dependencies(obj):
    # Any dependencies that can be resolved immediately are resolved.
    # Dependencies that cannot be resolved immediately are stored for
    # resolution in resolve_future_dependencies.

    def process(obj, attr_name, unresolved_in_out):
        for dependency in getattr(obj, attr_name, []):
            if dependency not in _REGISTRY:
                # We don't know about this dependency, so save it for later.
                unresolved_in_out.setdefault(dependency, []).append(obj)
                continue

            setattr(obj, dependency, get_provider(dependency))

    process(obj, '_dependencies', _future_dependencies)


def requires(*dependencies):
    """A class decorator used to inject providers into consumers.

    The required providers will be made available to instances of the decorated
    class via an attribute with the same name as the provider. For example, in
    the code fragment::

        @dependency.requires('foo_api', 'bar_api')
        class FooBarClient:
            def __init__(self):
                ...

            ...

        client = FooBarClient()

    The object ``client`` will have attributes named ``foo_api`` and
    ``bar_api``, which are instances of the named providers.

    Objects must not rely on the existence of these attributes until after
    ``resolve_future_dependencies()`` has been called; they may not exist
    beforehand.

    Dependencies registered via ``@required()`` must have providers; if not,
    an ``UnresolvableDependencyException`` will be raised when
    ``resolve_future_dependencies()`` is called.

    """
    def wrapper(self, *args, **kwargs):
        """Inject each dependency from the registry."""
        self.__wrapped_init__(*args, **kwargs)
        _process_dependencies(self)

    def wrapped(cls):
        """Note the required dependencies on the object for later injection.

        The dependencies of the parent class are combined with that of the
        child class to create a new set of dependencies.

        """
        existing_dependencies = getattr(cls, '_dependencies', set())
        cls._dependencies = existing_dependencies.union(dependencies)
        if not hasattr(cls, '__wrapped_init__'):
            cls.__wrapped_init__ = cls.__init__
            cls.__init__ = wrapper
        return cls

    return wrapped


def resolve_future_dependencies(__provider_name=None):
    """Forces injection of all dependencies.

    Before this function is called, circular dependencies may not have been
    injected. This function should be called only once, after all global
    providers are registered. If an object needs to be created after this
    call, it must not have circular dependencies.

    If any required dependencies are unresolvable, this function will raise an
    ``UnresolvableDependencyException``.

    Outside of this module, this function should be called with no arguments;
    the optional argument, ``__provider_name`` is used internally, and should
    be treated as an implementation detail.

    """
    new_providers = dict()
    if __provider_name:
        # A provider was registered, so take care of any objects depending on
        # it.
        targets = _future_dependencies.pop(__provider_name, [])

        for target in targets:
            setattr(target, __provider_name, get_provider(__provider_name))

        return

    # Resolve future dependencies, raises UnresolvableDependencyException if
    # there's no provider registered.
    try:
        for dependency, targets in _future_dependencies.copy().items():
            if dependency not in _REGISTRY:
                # a Class was registered that could fulfill the dependency, but
                # it has not yet been initialized.
                factory = _factories.get(dependency)
                if factory:
                    provider = factory()
                    new_providers[dependency] = provider
                else:
                    raise UnresolvableDependencyException(dependency, targets)

            for target in targets:
                setattr(target, dependency, get_provider(dependency))
    finally:
        _future_dependencies.clear()
    return new_providers


def reset():
    """Reset the registry of providers.

    This is useful for unit testing to ensure that tests don't use providers
    from previous tests.
    """

    _REGISTRY.clear()
    _future_dependencies.clear()

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

"""Options specific to resources managed by Keystone (Domain, User, etc)."""

from keystone.common import validation
from keystone.i18n import _


def _validator(value):
    return


def boolean_validator(value):
    if value not in (True, False):
        raise TypeError(_('Expected boolean value, got %r') % type(value))


def ref_mapper_to_dict_options(ref):
    """Convert the values in _resource_option_mapper to options dict.

    NOTE: this is to be called from the relevant `to_dict` methods or
          similar and must be called from within the active session context.

    :param ref: the DB model ref to extract options from
    :returns: Dict of options as expected to be returned out of to_dict in
              the `options` key.
    """
    options = {}
    for opt in ref._resource_option_mapper.values():
        if opt.option_id in ref.resource_options_registry.option_ids:
            r_opt = ref.resource_options_registry.get_option_by_id(
                opt.option_id)
            if r_opt is not None:
                options[r_opt.option_name] = opt.option_value
    return options


def get_resource_option(model, option_id):
    """Get the resource option information from the model's mapper."""
    if option_id in model._resource_option_mapper.keys():
        return model._resource_option_mapper[option_id]
    return None


def resource_options_ref_to_mapper(ref, option_class):
    """Convert the _resource_options property-dict to options attr map.

    The model must have the resource option mapper located in the
    ``_resource_option_mapper`` attribute.

    The model must have the resource option registry located in the
    ``resource_options_registry`` attribute.

    The option dict with key(opt_id), value(opt_value) will be pulled from
    ``ref._resource_options``.

    NOTE: This function MUST be called within the active writer session
          context!

    :param ref: The DB model reference that is actually stored to the
                backend.
    :param option_class: Class that is used to store the resource option
                         in the DB.
    """
    options = getattr(ref, '_resource_options', None)
    if options is not None:
        # To ensure everything is clean, no lingering refs.
        delattr(ref, '_resource_options')
    else:
        # _resource_options didn't exist. Work from an empty set.
        options = {}

    # NOTE(notmorgan): explicitly use .keys() here as the attribute mapper
    # has some oddities at times. This guarantees we are working with keys.
    set_options = set(ref._resource_option_mapper.keys())
    # Get any options that are not registered and slate them for removal from
    # the DB. This will delete unregistered options.
    clear_options = set_options.difference(
        ref.resource_options_registry.option_ids)
    options.update({x: None for x in clear_options})

    # Set the resource options for user in the Attribute Mapping.
    for r_opt_id, r_opt_value in options.items():
        if r_opt_value is None:
            # Delete any option set explicitly to None, ignore unset
            # options.
            ref._resource_option_mapper.pop(r_opt_id, None)
        else:
            # Set any options on the user_ref itself.
            opt_obj = option_class(
                option_id=r_opt_id,
                option_value=r_opt_value)
            ref._resource_option_mapper[r_opt_id] = opt_obj


class ResourceOptionRegistry(object):
    def __init__(self, registry_name):
        self._registered_options = {}
        self._registry_type = registry_name

    @property
    def option_names(self):
        return set([opt.option_name for opt in self.options])

    @property
    def options_by_name(self):
        return {opt.option_name: opt
                for opt in self._registered_options.values()}

    @property
    def options(self):
        return self._registered_options.values()

    @property
    def option_ids(self):
        return set(self._registered_options.keys())

    def get_option_by_id(self, opt_id):
        return self._registered_options.get(opt_id, None)

    def get_option_by_name(self, name):
        for option in self._registered_options.values():
            if name == option.option_name:
                return option
        return None

    @property
    def json_schema(self):
        schema = {'type': 'object',
                  'properties': {},
                  'additionalProperties': False}
        for opt in self.options:
            if opt.json_schema is not None:
                # NOTE(notmorgan): All options are nullable. Null indicates
                # the option should be reset and removed from the DB store.
                schema['properties'][opt.option_name] = validation.nullable(
                    opt.json_schema)
            else:
                # NOTE(notmorgan): without 'type' being specified, this
                # can be of any-type. We are simply specifying no interesting
                # values beyond that the property may exist here.
                schema['properties'][opt.option_name] = {}
        return schema

    def register_option(self, option):
        if option in self.options:
            # Re-registering the exact same option does nothing.
            return

        if option.option_id in self._registered_options:
            raise ValueError(_('Option %(option_id)s already defined in '
                               '%(registry)s.') %
                             {'option_id': option.option_id,
                              'registry': self._registry_type})
        if option.option_name in self.option_names:
            raise ValueError(_('Option %(option_name)s already defined in '
                               '%(registry)s') %
                             {'option_name': option.option_name,
                              'registry': self._registry_type})
        self._registered_options[option.option_id] = option


class ResourceOption(object):

    def __init__(self, option_id, option_name, validator=_validator,
                 json_schema_validation=None):
        """The base object to define the option(s) to be stored in the DB.

        :param option_id: The ID of the option. This will be used to lookup
                          the option value from the DB and should not be
                          changed once defined as the values will no longer
                          be correctly mapped to the keys in the user_ref when
                          retrieving the data from the DB.
        :type option_id: str
        :param option_name: The name of the option. This value will be used
                            to map the value from the user request on a
                            resource update to the correct option id to be
                            stored in the database. This value should not be
                            changed once defined as it will change the
                            resulting keys in the user_ref.
        :type option_name: str
        :param validator: A callable that raises TypeError if the value to be
                          persisted is incorrect. A single argument of the
                          value to be persisted will be passed to it. No return
                          value is expected.
        :type validator: callable
        :param json_schema_validation: Dictionary defining the JSON schema
                                       validation for the option itself. This
                                       is used to generate the JSON Schema
                                       validator(s) used at the API layer
        :type json_schema_validation: dict
        """
        if not isinstance(option_id, str) and len(option_id) == 4:
            raise TypeError(_('`option_id` must be a string, got %r')
                            % option_id)
        elif len(option_id) != 4:
            raise ValueError(_('`option_id` must be 4 characters in '

                               'length. Got %r') % option_id)
        if not isinstance(option_name, str):
            raise TypeError(_('`option_name` must be a string. '
                              'Got %r') % option_name)

        self._option_id = option_id
        self._option_name = option_name
        self.validator = validator
        self._json_schema_validation = json_schema_validation

    @property
    def json_schema(self):
        return self._json_schema_validation or None

    @property
    def option_name(self):
        # NOTE(notmorgan) Option IDs should never be set outside of definition
        # time.
        return self._option_name

    @property
    def option_id(self):
        # NOTE(notmorgan) Option IDs should never be set outside of definition
        # time.
        return self._option_id

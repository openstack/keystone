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

"""Utilities for Federation Extension."""

import re

import jsonschema
from oslo_utils import timeutils
import six

from keystone.common import config
from keystone import exception
from keystone.i18n import _, _LW
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)


MAPPING_SCHEMA = {
    "type": "object",
    "required": ['rules'],
    "properties": {
        "rules": {
            "minItems": 1,
            "type": "array",
            "items": {
                "type": "object",
                "required": ['local', 'remote'],
                "additionalProperties": False,
                "properties": {
                    "local": {
                        "type": "array"
                    },
                    "remote": {
                        "minItems": 1,
                        "type": "array",
                        "items": {
                            "type": "object",
                            "oneOf": [
                                {"$ref": "#/definitions/empty"},
                                {"$ref": "#/definitions/any_one_of"},
                                {"$ref": "#/definitions/not_any_of"}
                            ],
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "empty": {
            "type": "object",
            "required": ['type'],
            "properties": {
                "type": {
                    "type": "string"
                },
            },
            "additionalProperties": False,
        },
        "any_one_of": {
            "type": "object",
            "additionalProperties": False,
            "required": ['type', 'any_one_of'],
            "properties": {
                "type": {
                    "type": "string"
                },
                "any_one_of": {
                    "type": "array"
                },
                "regex": {
                    "type": "boolean"
                }
            }
        },
        "not_any_of": {
            "type": "object",
            "additionalProperties": False,
            "required": ['type', 'not_any_of'],
            "properties": {
                "type": {
                    "type": "string"
                },
                "not_any_of": {
                    "type": "array"
                },
                "regex": {
                    "type": "boolean"
                }
            }
        }
    }
}


def validate_mapping_structure(ref):
    v = jsonschema.Draft4Validator(MAPPING_SCHEMA)

    messages = ''
    for error in sorted(v.iter_errors(ref), key=str):
        messages = messages + error.message + "\n"

    if messages:
        raise exception.ValidationError(messages)


def validate_expiration(token_ref):
    if timeutils.utcnow() > token_ref.expires:
        raise exception.Unauthorized(_('Federation token is expired'))


def validate_groups_cardinality(group_ids, mapping_id):
    """Check if groups list is non-empty.

    :param group_ids: list of group ids
    :type group_ids: list of str

    :raises exception.MissingGroups: if ``group_ids`` cardinality is 0

    """
    if not group_ids:
        raise exception.MissingGroups(mapping_id=mapping_id)


def validate_idp(idp, assertion):
    """Check if the IdP providing the assertion is the one registered for
       the mapping
    """
    remote_id_parameter = CONF.federation.remote_id_attribute
    if not remote_id_parameter or not idp['remote_id']:
        LOG.warning(_LW('Impossible to identify the IdP %s '),
                    idp['id'])
        # If nothing is defined, the administrator may want to
        # allow the mapping of every IdP
        return
    try:
        idp_remote_identifier = assertion[remote_id_parameter]
    except KeyError:
        msg = _('Could not find Identity Provider identifier in '
                'environment, check [federation] remote_id_attribute '
                'for details.')
        raise exception.ValidationError(msg)
    if idp_remote_identifier != idp['remote_id']:
        msg = _('Incoming identity provider identifier not included '
                'among the accepeted identifiers.')
        raise exception.Forbidden(msg)


def validate_groups_in_backend(group_ids, mapping_id, identity_api):
    """Iterate over group ids and make sure they are present in the backend/

    This call is not transactional.
    :param group_ids: IDs of the groups to be checked
    :type group_ids: list of str

    :param mapping_id: id of the mapping used for this operation
    :type mapping_id: str

    :param identity_api: Identity Manager object used for communication with
                         backend
    :type identity_api: identity.Manager

    :raises: exception.MappedGroupNotFound

    """
    for group_id in group_ids:
        try:
            identity_api.get_group(group_id)
        except exception.GroupNotFound:
            raise exception.MappedGroupNotFound(
                group_id=group_id, mapping_id=mapping_id)


def validate_groups(group_ids, mapping_id, identity_api):
    """Check group ids cardinality and check their existence in the backend.

    This call is not transactional.
    :param group_ids: IDs of the groups to be checked
    :type group_ids: list of str

    :param mapping_id: id of the mapping used for this operation
    :type mapping_id: str

    :param identity_api: Identity Manager object used for communication with
                         backend
    :type identity_api: identity.Manager

    :raises: exception.MappedGroupNotFound
    :raises: exception.MissingGroups

    """
    validate_groups_cardinality(group_ids, mapping_id)
    validate_groups_in_backend(group_ids, mapping_id, identity_api)


# TODO(marek-denis): Optimize this function, so the number of calls to the
# backend are minimized.
def transform_to_group_ids(group_names, mapping_id,
                           identity_api, assignment_api):
    """Transform groups identitified by name/domain to their ids

    Function accepts list of groups identified by a name and domain giving
    a list of group ids in return.

    Example of group_names parameter::

        [
            {
                "name": "group_name",
                "domain": {
                    "id": "domain_id"
                },
            },
            {
                "name": "group_name_2",
                "domain": {
                    "name": "domain_name"
                }
            }
        ]

    :param group_names: list of group identified by name and its domain.
    :type group_names: list

    :param mapping_id: id of the mapping used for mapping assertion into
        local credentials
    :type mapping_id: str

    :param identity_api: identity_api object
    :param assignment_api: assignment_api object

    :returns: generator object with group ids

    :raises: excepton.MappedGroupNotFound: in case asked group doesn't
        exist in the backend.

    """

    def resolve_domain(domain):
        """Return domain id.

        Input is a dictionary with a domain identified either by a ``id`` or a
        ``name``. In the latter case system will attempt to fetch domain object
        from the backend.

        :returns: domain's id
        :rtype: str

        """
        domain_id = (domain.get('id') or
                     assignment_api.get_domain_by_name(
                     domain.get('name')).get('id'))
        return domain_id

    for group in group_names:
        try:
            group_dict = identity_api.get_group_by_name(
                group['name'], resolve_domain(group['domain']))
            yield group_dict['id']
        except exception.GroupNotFound:
            raise exception.MappedGroupNotFound(
                group_id=group['name'], mapping_id=mapping_id)


def get_assertion_params_from_env(context):
    LOG.debug('Environment variables: %s', context['environment'])
    prefix = CONF.federation.assertion_prefix
    for k, v in context['environment'].items():
        if k.startswith(prefix):
            yield (k, v)


class RuleProcessor(object):
    """A class to process assertions and mapping rules."""

    class _EvalType(object):
        """Mapping rule evaluation types."""
        ANY_ONE_OF = 'any_one_of'
        NOT_ANY_OF = 'not_any_of'

    def __init__(self, rules):
        """Initialize RuleProcessor.

        Example rules can be found at:
        :class:`keystone.tests.mapping_fixtures`

        :param rules: rules from a mapping
        :type rules: dict

        """

        self.rules = rules

    def process(self, assertion_data):
        """Transform assertion to a dictionary of user name and group ids
        based on mapping rules.

        This function will iterate through the mapping rules to find
        assertions that are valid.

        :param assertion_data: an assertion containing values from an IdP
        :type assertion_data: dict

        Example assertion_data::

            {
                'Email': 'testacct@example.com',
                'UserName': 'testacct',
                'FirstName': 'Test',
                'LastName': 'Account',
                'orgPersonType': 'Tester'
            }

        :returns: dictionary with user and group_ids

        The expected return structure is::

            {
                'name': 'foobar',
                'group_ids': ['abc123', 'def456'],
                'group_names': [
                    {
                        'name': 'group_name_1',
                        'domain': {
                            'name': 'domain1'
                        }
                    },
                    {
                        'name': 'group_name_1_1',
                        'domain': {
                            'name': 'domain1'
                        }
                    },
                    {
                        'name': 'group_name_2',
                        'domain': {
                            'id': 'xyz132'
                        }
                    }
                ]
            }

        """

        # Assertions will come in as string key-value pairs, and will use a
        # semi-colon to indicate multiple values, i.e. groups.
        # This will create a new dictionary where the values are arrays, and
        # any multiple values are stored in the arrays.
        LOG.debug('assertion data: %s', assertion_data)
        assertion = dict((n, v.split(';')) for n, v in assertion_data.items()
                         if isinstance(v, six.string_types))
        LOG.debug('assertion: %s', assertion)
        identity_values = []

        LOG.debug('rules: %s', self.rules)
        for rule in self.rules:
            direct_maps = self._verify_all_requirements(rule['remote'],
                                                        assertion)

            # If the compare comes back as None, then the rule did not apply
            # to the assertion data, go on to the next rule
            if direct_maps is None:
                continue

            # If there are no direct mappings, then add the local mapping
            # directly to the array of saved values. However, if there is
            # a direct mapping, then perform variable replacement.
            if not direct_maps:
                identity_values += rule['local']
            else:
                for local in rule['local']:
                    new_local = self._update_local_mapping(local, direct_maps)
                    identity_values.append(new_local)

        LOG.debug('identity_values: %s', identity_values)
        mapped_properties = self._transform(identity_values)
        LOG.debug('mapped_properties: %s', mapped_properties)
        return mapped_properties

    def _transform(self, identity_values):
        """Transform local mappings, to an easier to understand format.

        Transform the incoming array to generate the return value for
        the process function. Generating content for Keystone tokens will
        be easier if some pre-processing is done at this level.

        :param identity_values: local mapping from valid evaluations
        :type identity_values: array of dict

        Example identity_values::

            [{'group': {'id': '0cd5e9'}, 'user': {'email': 'bob@example.com'}}]

        :returns: dictionary with user name, group_ids and group_names.

        """

        def extract_groups(groups_by_domain):
            for groups in groups_by_domain.values():
                for group in {g['name']: g for g in groups}.values():
                    yield group

        # initialize the group_ids as a set to eliminate duplicates
        user_name = None
        group_ids = set()
        group_names = list()
        groups_by_domain = dict()

        for identity_value in identity_values:
            if 'user' in identity_value:
                # if a mapping outputs more than one user name, log it
                if user_name is not None:
                    LOG.warning(_LW('Ignoring user name %s'),
                                identity_value['user']['name'])
                else:
                    user_name = identity_value['user']['name']
            if 'group' in identity_value:
                group = identity_value['group']
                if 'id' in group:
                    group_ids.add(group['id'])
                elif 'name' in group:
                    domain = (group['domain'].get('name') or
                              group['domain'].get('id'))
                    groups_by_domain.setdefault(domain, list()).append(group)
                group_names.extend(extract_groups(groups_by_domain))

        return {'name': user_name,
                'group_ids': list(group_ids),
                'group_names': group_names}

    def _update_local_mapping(self, local, direct_maps):
        """Replace any {0}, {1} ... values with data from the assertion.

        :param local: local mapping reference that needs to be updated
        :type local: dict
        :param direct_maps: list of identity values, used to update local
        :type direct_maps: list

        Example local::

            {'user': {'name': '{0} {1}', 'email': '{2}'}}

        Example direct_maps::

            ['Bob', 'Thompson', 'bob@example.com']

        :returns: new local mapping reference with replaced values.

        The expected return structure is::

            {'user': {'name': 'Bob Thompson', 'email': 'bob@example.org'}}

        """

        LOG.debug('direct_maps: %s', direct_maps)
        LOG.debug('local: %s', local)
        new = {}
        for k, v in six.iteritems(local):
            if isinstance(v, dict):
                new_value = self._update_local_mapping(v, direct_maps)
            else:
                new_value = v.format(*direct_maps)
            new[k] = new_value
        return new

    def _verify_all_requirements(self, requirements, assertion):
        """Go through the remote requirements of a rule, and compare against
        the assertion.

        If a value of ``None`` is returned, the rule with this assertion
        doesn't apply.
        If an array of zero length is returned, then there are no direct
        mappings to be performed, but the rule is valid.
        Otherwise, then it will return the values, in order, to be directly
        mapped, again, the rule is valid.

        :param requirements: list of remote requirements from rules
        :type requirements: list

        Example requirements::

            [
                {
                    "type": "UserName"
                },
                {
                    "type": "orgPersonType",
                    "any_one_of": [
                        "Customer"
                    ]
                }
            ]

        :param assertion: dict of attributes from an IdP
        :type assertion: dict

        Example assertion::

            {
                'UserName': ['testacct'],
                'LastName': ['Account'],
                'orgPersonType': ['Tester'],
                'Email': ['testacct@example.com'],
                'FirstName': ['Test']
            }

        :returns: list of direct mappings or None.

        """

        direct_maps = []

        for requirement in requirements:
            requirement_type = requirement['type']
            regex = requirement.get('regex', False)

            any_one_values = requirement.get(self._EvalType.ANY_ONE_OF)
            if any_one_values is not None:
                if self._evaluate_requirement(any_one_values,
                                              requirement_type,
                                              self._EvalType.ANY_ONE_OF,
                                              regex,
                                              assertion):
                    continue
                else:
                    return None

            not_any_values = requirement.get(self._EvalType.NOT_ANY_OF)
            if not_any_values is not None:
                if self._evaluate_requirement(not_any_values,
                                              requirement_type,
                                              self._EvalType.NOT_ANY_OF,
                                              regex,
                                              assertion):
                    continue
                else:
                    return None

            # If 'any_one_of' or 'not_any_of' are not found, then values are
            # within 'type'. Attempt to find that 'type' within the assertion.
            direct_map_values = assertion.get(requirement_type)
            if direct_map_values:
                LOG.debug('updating a direct mapping: %s', direct_map_values)
                direct_maps += direct_map_values

        return direct_maps

    def _evaluate_requirement(self, values, requirement_type,
                              eval_type, regex, assertion):
        """Evaluate the incoming requirement and assertion.

        If the requirement type does not exist in the assertion data, then
        return False. If regex is specified, then compare the values and
        assertion values. Otherwise, grab the intersection of the values
        and use that to compare against the evaluation type.

        :param values: list of allowed values, defined in the requirement
        :type values: list
        :param requirement_type: key to look for in the assertion
        :type requirement_type: string
        :param eval_type: determine how to evaluate requirements
        :type eval_type: string
        :param regex: perform evaluation with regex
        :type regex: boolean
        :param assertion: dict of attributes from the IdP
        :type assertion: dict

        :returns: boolean, whether requirement is valid or not.

        """

        assertion_values = assertion.get(requirement_type)
        if not assertion_values:
            return False

        if regex:
            for value in values:
                for assertion_value in assertion_values:
                    if re.search(value, assertion_value):
                        return True
            return False

        any_match = bool(set(values).intersection(set(assertion_values)))
        if any_match and eval_type == self._EvalType.ANY_ONE_OF:
            return True
        if not any_match and eval_type == self._EvalType.NOT_ANY_OF:
            return True

        return False


def assert_enabled_identity_provider(federation_api, idp_id):
    identity_provider = federation_api.get_idp(idp_id)
    if identity_provider.get('enabled') is not True:
        msg = _('Identity Provider %(idp)s is disabled') % {'idp': idp_id}
        LOG.debug(msg)
        raise exception.Forbidden(msg)

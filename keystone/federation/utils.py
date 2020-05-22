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

import ast
import re

import flask
import jsonschema
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import timeutils

from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class UserType(object):
    """User mapping type."""

    EPHEMERAL = 'ephemeral'
    LOCAL = 'local'


ROLE_PROPERTIES = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {
                "type": "string"
            },
            "additionalProperties": False
        }
    }
}


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
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "user": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "string"},
                                        "name": {"type": "string"},
                                        "email": {"type": "string"},
                                        "domain": {
                                            "$ref": "#/definitions/domain"
                                        },
                                        "type": {
                                            "type": "string",
                                            "enum": [UserType.EPHEMERAL,
                                                     UserType.LOCAL]
                                        }
                                    },
                                    "additionalProperties": False
                                },
                                "projects": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["name", "roles"],
                                        "additionalProperties": False,
                                        "properties": {
                                            "name": {"type": "string"},
                                            "roles": ROLE_PROPERTIES
                                        }
                                    }
                                },
                                "group": {
                                    "type": "object",
                                    "oneOf": [
                                        {"$ref": "#/definitions/group_by_id"},
                                        {"$ref": "#/definitions/group_by_name"}
                                    ]
                                },
                                "groups": {
                                    "type": "string"
                                },
                                "group_ids": {
                                    "type": "string"
                                },
                                "domain": {"$ref": "#/definitions/domain"},
                            }
                        }
                    },
                    "remote": {
                        "minItems": 1,
                        "type": "array",
                        "items": {
                            "type": "object",
                            "oneOf": [
                                {"$ref": "#/definitions/empty"},
                                {"$ref": "#/definitions/any_one_of"},
                                {"$ref": "#/definitions/not_any_of"},
                                {"$ref": "#/definitions/blacklist"},
                                {"$ref": "#/definitions/whitelist"}
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
        },
        "blacklist": {
            "type": "object",
            "additionalProperties": False,
            "required": ['type', 'blacklist'],
            "properties": {
                "type": {
                    "type": "string"
                },
                "blacklist": {
                    "type": "array"
                },
                "regex": {
                    "type": "boolean"
                }
            }
        },
        "whitelist": {
            "type": "object",
            "additionalProperties": False,
            "required": ['type', 'whitelist'],
            "properties": {
                "type": {
                    "type": "string"
                },
                "whitelist": {
                    "type": "array"
                },
                "regex": {
                    "type": "boolean"
                }
            }
        },
        "domain": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"}
            },
            "additionalProperties": False
        },
        "group_by_id": {
            "type": "object",
            "properties": {
                "id": {"type": "string"}
            },
            "additionalProperties": False,
            "required": ["id"]
        },
        "group_by_name": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "domain": {"$ref": "#/definitions/domain"}
            },
            "additionalProperties": False,
            "required": ["name", "domain"]
        }
    }
}


class DirectMaps(object):
    """An abstraction around the remote matches.

    Each match is treated internally as a list.
    """

    def __init__(self):
        self._matches = []

    def __str__(self):
        """return the direct map array as a string."""
        return '%s' % self._matches

    def add(self, values):
        """Add a matched value to the list of matches.

        :param list value: the match to save

        """
        self._matches.append(values)

    def __getitem__(self, idx):
        """Used by Python when executing ``''.format(*DirectMaps())``."""
        value = self._matches[idx]
        if isinstance(value, list) and len(value) == 1:
            return value[0]
        else:
            return value


def validate_mapping_structure(ref):
    v = jsonschema.Draft4Validator(MAPPING_SCHEMA)

    messages = ''
    for error in sorted(v.iter_errors(ref), key=str):
        messages = messages + error.message + "\n"

    if messages:
        raise exception.ValidationError(messages)


def validate_expiration(token):
    token_expiration_datetime = timeutils.normalize_time(
        timeutils.parse_isotime(token.expires_at)
    )
    if timeutils.utcnow() > token_expiration_datetime:
        raise exception.Unauthorized(_('Federation token is expired'))


def get_remote_id_parameter(idp, protocol):
    # NOTE(marco-fargetta): Since we support any protocol ID, we attempt to
    # retrieve the remote_id_attribute of the protocol ID. It will look up
    # first if the remote_id_attribute exists.
    protocol_ref = PROVIDERS.federation_api.get_protocol(idp['id'], protocol)
    remote_id_parameter = protocol_ref.get('remote_id_attribute')
    if remote_id_parameter:
        return remote_id_parameter
    else:
        # If it's not registered in the config, then register the option and
        # try again. This allows the user to register protocols other than
        # oidc and saml2.
        try:
            remote_id_parameter = CONF[protocol]['remote_id_attribute']
        except AttributeError:
            # TODO(dolph): Move configuration registration to keystone.conf
            CONF.register_opt(cfg.StrOpt('remote_id_attribute'),
                              group=protocol)
            try:
                remote_id_parameter = CONF[protocol]['remote_id_attribute']
            except AttributeError:  # nosec
                # No remote ID attr, will be logged and use the default
                # instead.
                pass
    if not remote_id_parameter:
        LOG.debug('Cannot find "remote_id_attribute" in configuration '
                  'group %s. Trying default location in '
                  'group federation.', protocol)
        remote_id_parameter = CONF.federation.remote_id_attribute

    return remote_id_parameter


def validate_idp(idp, protocol, assertion):
    """The IdP providing the assertion should be registered for the mapping."""
    remote_id_parameter = get_remote_id_parameter(idp, protocol)
    if not remote_id_parameter or not idp['remote_ids']:
        LOG.debug('Impossible to identify the IdP %s ', idp['id'])
        # If nothing is defined, the administrator may want to
        # allow the mapping of every IdP
        return
    try:
        idp_remote_identifier = assertion[remote_id_parameter]
    except KeyError:
        msg = _('Could not find Identity Provider identifier in '
                'environment')
        raise exception.ValidationError(msg)
    if idp_remote_identifier not in idp['remote_ids']:
        msg = _('Incoming identity provider identifier not included '
                'among the accepted identifiers.')
        raise exception.Forbidden(msg)


def validate_mapped_group_ids(group_ids, mapping_id, identity_api):
    """Iterate over group ids and make sure they are present in the backend.

    This call is not transactional.
    :param group_ids: IDs of the groups to be checked
    :type group_ids: list of str

    :param mapping_id: id of the mapping used for this operation
    :type mapping_id: str

    :param identity_api: Identity Manager object used for communication with
                         backend
    :type identity_api: identity.Manager

    :raises keystone.exception.MappedGroupNotFound: If the group returned by
        mapping was not found in the backend.

    """
    for group_id in group_ids:
        try:
            identity_api.get_group(group_id)
        except exception.GroupNotFound:
            raise exception.MappedGroupNotFound(
                group_id=group_id, mapping_id=mapping_id)


# TODO(marek-denis): Optimize this function, so the number of calls to the
# backend are minimized.
def transform_to_group_ids(group_names, mapping_id,
                           identity_api, resource_api):
    """Transform groups identified by name/domain to their ids.

    Function accepts list of groups identified by a name and domain giving
    a list of group ids in return. A message is logged if the group doesn't
    exist in the backend.

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
    :param resource_api: resource manager object

    :returns: generator object with group ids

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
                     resource_api.get_domain_by_name(
                     domain.get('name')).get('id'))
        return domain_id

    for group in group_names:
        try:
            group_dict = identity_api.get_group_by_name(
                group['name'], resolve_domain(group['domain']))
            yield group_dict['id']
        except exception.GroupNotFound:
            LOG.debug('Group %s has no entry in the backend',
                      group['name'])


def get_assertion_params_from_env():
    LOG.debug('Environment variables: %s', flask.request.environ)
    prefix = CONF.federation.assertion_prefix
    for k, v in list(flask.request.environ.items()):
        if not k.startswith(prefix):
            continue
        # These bytes may be decodable as ISO-8859-1 according to Section
        # 3.2.4 of RFC 7230. Let's assume that our web server plugins are
        # correctly encoding the data.
        if not isinstance(v, str) and getattr(v, 'decode', False):
            v = v.decode('ISO-8859-1')
        yield (k, v)


class RuleProcessor(object):
    """A class to process assertions and mapping rules."""

    class _EvalType(object):
        """Mapping rule evaluation types."""

        ANY_ONE_OF = 'any_one_of'
        NOT_ANY_OF = 'not_any_of'
        BLACKLIST = 'blacklist'
        WHITELIST = 'whitelist'

    def __init__(self, mapping_id, rules):
        """Initialize RuleProcessor.

        Example rules can be found at:
        :class:`keystone.tests.mapping_fixtures`

        :param mapping_id: id for the mapping
        :type mapping_id: string
        :param rules: rules from a mapping
        :type rules: dict

        """
        self.mapping_id = mapping_id
        self.rules = rules

    def process(self, assertion_data):
        """Transform assertion to a dictionary.

        The dictionary contains mapping of user name and group ids
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
        assertion = {n: v.split(';') for n, v in assertion_data.items()
                     if isinstance(v, str)}
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

    def _normalize_groups(self, identity_value):
        # In this case, identity_value['groups'] is a string
        # representation of a list, and we want a real list.  This is
        # due to the way we do direct mapping substitutions today (see
        # function _update_local_mapping() )
        if 'name' in identity_value['groups']:
            try:
                group_names_list = ast.literal_eval(
                    identity_value['groups'])
            except (ValueError, SyntaxError):
                group_names_list = [identity_value['groups']]

            def convert_json(group):
                if group.startswith('JSON:'):
                    return jsonutils.loads(group.lstrip('JSON:'))
                return group

            group_dicts = [convert_json(g) for g in group_names_list]
            for g in group_dicts:
                if 'domain' not in g:
                    msg = _("Invalid rule: %(identity_value)s. Both "
                            "'groups' and 'domain' keywords must be "
                            "specified.")
                    msg = msg % {'identity_value': identity_value}
                    raise exception.ValidationError(msg)
        else:
            if 'domain' not in identity_value:
                msg = _("Invalid rule: %(identity_value)s. Both "
                        "'groups' and 'domain' keywords must be "
                        "specified.")
                msg = msg % {'identity_value': identity_value}
                raise exception.ValidationError(msg)
            try:
                group_names_list = ast.literal_eval(
                    identity_value['groups'])
            except (ValueError, SyntaxError):
                group_names_list = [identity_value['groups']]
            domain = identity_value['domain']
            group_dicts = [{'name': name, 'domain': domain} for name in
                           group_names_list]
        return group_dicts

    def _transform(self, identity_values):
        """Transform local mappings, to an easier to understand format.

        Transform the incoming array to generate the return value for
        the process function. Generating content for Keystone tokens will
        be easier if some pre-processing is done at this level.

        :param identity_values: local mapping from valid evaluations
        :type identity_values: array of dict

        Example identity_values::

            [
                {
                    'group': {'id': '0cd5e9'},
                    'user': {
                        'email': 'bob@example.com'
                    },
                },
                {
                    'groups': ['member', 'admin', tester'],
                    'domain': {
                        'name': 'default_domain'
                    }
                },
                {
                    'group_ids': ['abc123', 'def456', '0cd5e9']
                }
            ]

        :returns: dictionary with user name, group_ids and group_names.
        :rtype: dict

        """
        def extract_groups(groups_by_domain):
            for groups in list(groups_by_domain.values()):
                for group in list({g['name']: g for g in groups}.values()):
                    yield group

        def normalize_user(user):
            """Parse and validate user mapping."""
            user_type = user.get('type')

            if user_type and user_type not in (UserType.EPHEMERAL,
                                               UserType.LOCAL):
                msg = _("User type %s not supported") % user_type
                raise exception.ValidationError(msg)

            if user_type is None:
                user['type'] = UserType.EPHEMERAL

        # initialize the group_ids as a set to eliminate duplicates
        user = {}
        group_ids = set()
        group_names = list()
        groups_by_domain = dict()
        projects = []

        # if mapping yield no valid identity values, we should bail right away
        # instead of continuing on with a normalized bogus user
        if not identity_values:
            msg = ("Could not map any federated user properties to identity "
                   "values. Check debug logs or the mapping used for "
                   "additional details.")
            tr_msg = _("Could not map any federated user properties to "
                       "identity values. Check debug logs or the mapping "
                       "used for additional details.")
            LOG.warning(msg)
            raise exception.ValidationError(tr_msg)

        for identity_value in identity_values:
            if 'user' in identity_value:
                # if a mapping outputs more than one user name, log it
                if user:
                    LOG.warning('Ignoring user name')
                else:
                    user = identity_value.get('user')
            if 'group' in identity_value:
                group = identity_value['group']
                if 'id' in group:
                    group_ids.add(group['id'])
                elif 'name' in group:
                    domain = (group['domain'].get('name') or
                              group['domain'].get('id'))
                    groups_by_domain.setdefault(domain, list()).append(group)
                group_names.extend(extract_groups(groups_by_domain))
            if 'groups' in identity_value:
                group_dicts = self._normalize_groups(identity_value)
                group_names.extend(group_dicts)
            if 'group_ids' in identity_value:
                # If identity_values['group_ids'] is a string representation
                # of a list, parse it to a real list. Also, if the provided
                # group_ids parameter contains only one element, it will be
                # parsed as a simple string, and not a list or the
                # representation of a list.
                try:
                    group_ids.update(
                        ast.literal_eval(identity_value['group_ids']))
                except (ValueError, SyntaxError):
                    group_ids.update([identity_value['group_ids']])
            if 'projects' in identity_value:
                projects = identity_value['projects']

        normalize_user(user)

        return {'user': user,
                'group_ids': list(group_ids),
                'group_names': group_names,
                'projects': projects}

    def _update_local_mapping(self, local, direct_maps):
        """Replace any {0}, {1} ... values with data from the assertion.

        :param local: local mapping reference that needs to be updated
        :type local: dict
        :param direct_maps: identity values used to update local
        :type direct_maps: keystone.federation.utils.DirectMaps

        Example local::

            {'user': {'name': '{0} {1}', 'email': '{2}'}}

        Example direct_maps::

            [['Bob'], ['Thompson'], ['bob@example.com']]

        :returns: new local mapping reference with replaced values.

        The expected return structure is::

            {'user': {'name': 'Bob Thompson', 'email': 'bob@example.org'}}

        :raises keystone.exception.DirectMappingError: when referring to a
            remote match from a local section of a rule

        """
        LOG.debug('direct_maps: %s', direct_maps)
        LOG.debug('local: %s', local)
        new = {}
        for k, v in local.items():
            if isinstance(v, dict):
                new_value = self._update_local_mapping(v, direct_maps)
            elif isinstance(v, list):
                new_value = [self._update_local_mapping(item, direct_maps)
                             for item in v]
            else:
                try:
                    new_value = v.format(*direct_maps)
                except IndexError:
                    raise exception.DirectMappingError(
                        mapping_id=self.mapping_id)

            new[k] = new_value
        return new

    def _verify_all_requirements(self, requirements, assertion):
        """Compare remote requirements of a rule against the assertion.

        If a value of ``None`` is returned, the rule with this assertion
        doesn't apply.
        If an array of zero length is returned, then there are no direct
        mappings to be performed, but the rule is valid.
        Otherwise, then it will first attempt to filter the values according
        to blacklist or whitelist rules and finally return the values in
        order, to be directly mapped.

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
                },
                {
                    "type": "ADFS_GROUPS",
                    "whitelist": [
                        "g1", "g2", "g3", "g4"
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
                'FirstName': ['Test'],
                'ADFS_GROUPS': ['g1', 'g2']
            }

        :returns: identity values used to update local
        :rtype: keystone.federation.utils.DirectMaps or None

        """
        direct_maps = DirectMaps()

        for requirement in requirements:
            requirement_type = requirement['type']
            direct_map_values = assertion.get(requirement_type)
            regex = requirement.get('regex', False)

            if not direct_map_values:
                return None

            any_one_values = requirement.get(self._EvalType.ANY_ONE_OF)
            if any_one_values is not None:
                if self._evaluate_requirement(any_one_values,
                                              direct_map_values,
                                              self._EvalType.ANY_ONE_OF,
                                              regex):
                    continue
                else:
                    return None

            not_any_values = requirement.get(self._EvalType.NOT_ANY_OF)
            if not_any_values is not None:
                if self._evaluate_requirement(not_any_values,
                                              direct_map_values,
                                              self._EvalType.NOT_ANY_OF,
                                              regex):
                    continue
                else:
                    return None

            # If 'any_one_of' or 'not_any_of' are not found, then values are
            # within 'type'. Attempt to find that 'type' within the assertion,
            # and filter these values if 'whitelist' or 'blacklist' is set.
            blacklisted_values = requirement.get(self._EvalType.BLACKLIST)
            whitelisted_values = requirement.get(self._EvalType.WHITELIST)

            # If a blacklist or whitelist is used, we want to map to the
            # whole list instead of just its values separately.
            if blacklisted_values is not None:
                direct_map_values = (
                    self._evaluate_requirement(blacklisted_values,
                                               direct_map_values,
                                               self._EvalType.BLACKLIST,
                                               regex))
            elif whitelisted_values is not None:
                direct_map_values = (
                    self._evaluate_requirement(whitelisted_values,
                                               direct_map_values,
                                               self._EvalType.WHITELIST,
                                               regex))

            direct_maps.add(direct_map_values)

            LOG.debug('updating a direct mapping: %s', direct_map_values)

        return direct_maps

    def _evaluate_values_by_regex(self, values, assertion_values):
        return [
            assertion for assertion in assertion_values
            if any([re.search(regex, assertion) for regex in values])
        ]

    def _evaluate_requirement(self, values, assertion_values,
                              eval_type, regex):
        """Evaluate the incoming requirement and assertion.

        Filter the incoming assertions against the requirement values. If regex
        is specified, the assertion list is filtered by checking if any of the
        requirement regexes matches. Otherwise, the list is filtered by string
        equality with any of the allowed values.

        Once the assertion values are filtered, the output is determined by the
        evaluation type:
            any_one_of: return True if there are any matches, False otherwise
            not_any_of: return True if there are no matches, False otherwise
            blacklist: return the incoming values minus any matches
            whitelist: return only the matched values

        :param values: list of allowed values, defined in the requirement
        :type values: list
        :param assertion_values: The values from the assertion to evaluate
        :type assertion_values: list/string
        :param eval_type: determine how to evaluate requirements
        :type eval_type: string
        :param regex: perform evaluation with regex
        :type regex: boolean

        :returns: list of filtered assertion values (if evaluation type is
                  'blacklist' or 'whitelist'), or boolean indicating if the
                  assertion values fulfill the requirement (if evaluation type
                  is 'any_one_of' or 'not_any_of')

        """
        if regex:
            matches = self._evaluate_values_by_regex(values, assertion_values)
        else:
            matches = set(values).intersection(set(assertion_values))

        if eval_type == self._EvalType.ANY_ONE_OF:
            return bool(matches)
        elif eval_type == self._EvalType.NOT_ANY_OF:
            return not bool(matches)
        elif eval_type == self._EvalType.BLACKLIST:
            return list(set(assertion_values).difference(set(matches)))
        elif eval_type == self._EvalType.WHITELIST:
            return list(matches)
        else:
            raise exception.UnexpectedError(
                _('Unexpected evaluation type "%(eval_type)s"') % {
                    'eval_type': eval_type})


def assert_enabled_identity_provider(federation_api, idp_id):
    identity_provider = federation_api.get_idp(idp_id)
    if identity_provider.get('enabled') is not True:
        msg = 'Identity Provider %(idp)s is disabled' % {
            'idp': idp_id}
        tr_msg = _('Identity Provider %(idp)s is disabled') % {
            'idp': idp_id}
        LOG.debug(msg)
        raise exception.Forbidden(tr_msg)


def assert_enabled_service_provider_object(service_provider):
    if service_provider.get('enabled') is not True:
        sp_id = service_provider['id']
        msg = 'Service Provider %(sp)s is disabled' % {'sp': sp_id}
        tr_msg = _('Service Provider %(sp)s is disabled') % {'sp': sp_id}
        LOG.debug(msg)
        raise exception.Forbidden(tr_msg)

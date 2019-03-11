# Copyright 2019 SUSE Linux GmbH
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

import re

from oslo_log import log
from oslo_serialization import jsonutils

from keystone.access_rules_config.backends import base
import keystone.conf
from keystone import exception

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


class AccessRulesConfig(base.AccessRulesConfigDriverBase):
    """This backend reads the access rules from a JSON file on disk.

    The format of the file is a mapping from service type to rules for that
    service type. For example::

        {
            "identity": [
                {
                    "path": "/v3/users",
                    "method": "GET"
                },
                {
                    "path": "/v3/users",
                    "method": "POST"
                },
                {
                    "path": "/v3/users/*",
                    "method": "GET"
                },
                {
                    "path": "/v3/users/*",
                    "method": "PATCH"
                },
                {
                    "path": "/v3/users/*",
                    "method": "DELETE"
                }
                ...
            ],
            "image": [
                {
                    "path": "/v2/images",
                    "method": "GET"
                },
                ...
            ],
            ...
        }

    This will be transmuted in memory to a hash map that looks like this::

        {
            "identity": {
                "GET": [
                    {
                        "path": "/v3/users"
                    },
                    {
                        "path": "/v3/users/*"
                    }
                    ...
                ],
                "POST": [ ... ]
            },
            ...
        }

    The path may include a wildcard like '*' or '**' or a named wildcard like
    {server_id}. An application credential access rule validation request for
    a path like "/v3/users/uuid" will match with a configured access rule like
    "/v3/users/*" or "/v3/users/{user_id}", and a request for a path like
    "/v3/users/uuid/application_credentials/uuid" will match with a configured
    access rule like "/v3/users/**".

    """

    def __init__(self):
        super(AccessRulesConfig, self).__init__()
        if CONF.access_rules_config.permissive:
            return
        access_rules_file = CONF.access_rules_config.rules_file
        self.access_rules = dict()
        self.access_rules_json = dict()
        try:
            with open(access_rules_file, "rb") as f:
                self.access_rules_json = jsonutils.load(f)
        except IOError:
            LOG.warning('No config file found for access rules, application'
                        ' credential access rules will be unavailable.')
            return
        except ValueError as e:
            raise exception.AccessRulesConfigFileError(error=e)

        for service, rules in self.access_rules_json.items():
            self.access_rules[service] = dict()
            for rule in rules:
                try:
                    self.access_rules[service].setdefault(
                        rule['method'], []).append({
                            'path': rule['path']
                        })
                except KeyError as e:
                    raise exception.AccessRulesConfigFileError(error=e)

    def _path_matches(self, request_path, path_pattern):
        # The fnmatch module doesn't provide the ability to match * versus **,
        # so convert to regex.
        # replace {tags} with *
        pattern = r'{[^}]*}'
        replace = r'*'
        path_regex = re.sub(pattern, replace, path_pattern)
        # temporarily sub out **
        pattern = r'([^\*]*)\*\*([^\*]*)'
        replace = r'\1%TMP%\2'
        path_regex = re.sub(pattern, replace, path_regex)
        # replace * with [^\/]* (all except /)
        pattern = r'([^\*]?)\*($|[^\*])'
        replace = r'\1[^\/]*\2'
        path_regex = re.sub(pattern, replace, path_regex)
        # replace ** with .* (includes /)
        pattern = r'%TMP%'
        replace = '.*'
        path_regex = re.sub(pattern, replace, path_regex)
        path_regex = r'^%s$' % path_regex
        regex = re.compile(path_regex)
        return regex.match(request_path)

    def list_access_rules_config(self, service=None):
        """List access rules config in human readable form."""
        if service:
            if service not in self.access_rules_json:
                raise exception.AccessRulesConfigNotFound(service=service)
            return {service: self.access_rules_json[service]}
        return self.access_rules_json

    def check_access_rule(self, service, request_path, request_method):
        """Check if an access rule exists in config."""
        if (service in self.access_rules
                and request_method in self.access_rules[service]):
            rules = self.access_rules[service][request_method]
            for rule in rules:
                if self._path_matches(request_path, rule['path']):
                    return True
        return False

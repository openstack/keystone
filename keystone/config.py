# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
"""Wrapper for keystone.common.config that configures itself on import."""

from keystone.common import config


config.configure()
CONF = config.CONF

setup_logging = config.setup_logging
register_str = config.register_str
register_cli_str = config.register_cli_str
register_list = config.register_list
register_cli_list = config.register_cli_list
register_bool = config.register_bool
register_cli_bool = config.register_cli_bool
register_int = config.register_int
register_cli_int = config.register_cli_int
setup_authentication = config.setup_authentication

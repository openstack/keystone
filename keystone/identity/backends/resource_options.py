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

from keystone.common import resource_options


USER_OPTIONS_REGISTRY = resource_options.ResourceOptionRegistry('USER')
USER_OPTIONS_LIST = [
    # NOTE(notmorgan): This placeholder options can be removed once more
    # options are populated. This forces iteration on possible options for
    # complete test purposes in unit/functional/gate tests outside of the
    # explicit test cases that test resource options. This option is never
    # expected to be set.
    resource_options.ResourceOption('_TST', '__PLACEHOLDER__'),
]


# NOTE(notmorgan): wrap this in a function for testing purposes.
# This is called on import by design.
def register_user_options():
    for opt in USER_OPTIONS_LIST:
        USER_OPTIONS_REGISTRY.register_option(opt)


register_user_options()

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

from oslo_config import cfg

from keystone.conf import utils

GROUP_NAME = __name__.split('.')[-1]

ALL_OPTS = [
    cfg.StrOpt(
        "response_validation",
        choices=(
            (
                'error',
                'Raise a HTTP 500 (Server Error) for responses that fail '
                'schema validation',
            ),
            (
                'warn',
                'Log a warning for responses that fail schema validation',
            ),
            ('ignore', 'Ignore schema validation failures'),
        ),
        default='warn',
        help=utils.fmt(
            """
Configure validation of API responses.

``warn`` is the current recommendation for production environments. If you find
it necessary to enable the ``ignore`` option, please report the issues you are
seeing to the Keystone team so we can improve our schemas.

``error`` should not be used in a production environment. This is because
schema validation happens *after* the response body has been generated, meaning
any side effects will still happen and the call may be non-idempotent despite
the user receiving a HTTP 500 error.
"""
        ),
    )
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}

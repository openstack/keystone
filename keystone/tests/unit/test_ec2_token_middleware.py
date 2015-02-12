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

from keystonemiddleware import ec2_token as ksm_ec2_token

from keystone.middleware import ec2_token
from keystone.tests import unit as tests


class EC2TokenMiddlewareTestBase(tests.BaseTestCase):
    def test_symbols(self):
        """Verify ec2 middleware symbols.

        Verify that the keystone version of ec2_token middleware forwards the
        public symbols from the keystonemiddleware version of the ec2_token
        middleware for backwards compatibility.

        """

        self.assertIs(ksm_ec2_token.app_factory, ec2_token.app_factory)
        self.assertIs(ksm_ec2_token.filter_factory, ec2_token.filter_factory)
        self.assertTrue(
            issubclass(ec2_token.EC2Token, ksm_ec2_token.EC2Token),
            'ec2_token.EC2Token is not subclass of '
            'keystonemiddleware.ec2_token.EC2Token')

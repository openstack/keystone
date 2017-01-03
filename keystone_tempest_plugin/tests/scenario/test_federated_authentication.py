# Copyright 2016 Red Hat, Inc.
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

from lxml import etree
from six.moves import http_client
from tempest import config
from tempest.lib.common.utils import data_utils
import testtools

from keystone_tempest_plugin.tests import base


CONF = config.CONF


class TestSaml2EcpFederatedAuthentication(base.BaseIdentityTest):

    ECP_SAML2_NAMESPACES = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
    }

    ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:Request/'
                                         '@responseConsumerURL')

    ECP_IDP_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                            '@AssertionConsumerServiceURL')

    ECP_RELAY_STATE = '//ecp:RelayState'

    def _setup_settings(self):
        self.idp_id = CONF.fed_scenario.idp_id
        self.idp_url = CONF.fed_scenario.idp_ecp_url
        self.keystone_v3_endpoint = CONF.identity.uri_v3
        self.password = CONF.fed_scenario.idp_password
        self.protocol_id = CONF.fed_scenario.protocol_id
        self.username = CONF.fed_scenario.idp_username

    def _setup_idp(self):
        remote_ids = CONF.fed_scenario.idp_remote_ids
        self.idps_client.create_identity_provider(
            self.idp_id, remote_ids=remote_ids, enabled=True)
        self.addCleanup(
            self.idps_client.delete_identity_provider, self.idp_id)

    def _setup_mapping(self):
        self.mapping_id = data_utils.rand_uuid_hex()
        mapping_remote_type = CONF.fed_scenario.mapping_remote_type
        mapping_user_name = CONF.fed_scenario.mapping_user_name
        mapping_group_name = CONF.fed_scenario.mapping_group_name
        mapping_group_domain_name = CONF.fed_scenario.mapping_group_domain_name

        rules = [{
            'local': [
                {
                    'user': {'name': mapping_user_name}
                },
                {
                    'group': {
                        'domain': {'name': mapping_group_domain_name},
                        'name': mapping_group_name
                    }
                }
            ],
            'remote': [
                {
                    'type': mapping_remote_type
                }
            ]
        }]
        mapping_ref = {'rules': rules}
        self.mappings_client.create_mapping_rule(self.mapping_id, mapping_ref)
        self.addCleanup(
            self.mappings_client.delete_mapping_rule, self.mapping_id)

    def _setup_protocol(self):
        self.idps_client.add_protocol_and_mapping(
            self.idp_id, self.protocol_id, self.mapping_id)
        self.addCleanup(
            self.idps_client.delete_protocol_and_mapping,
            self.idp_id,
            self.protocol_id)

    def setUp(self):
        super(TestSaml2EcpFederatedAuthentication, self).setUp()
        self._setup_settings()

        # Reset client's session to avoid getting garbage from another runs
        self.saml2_client.reset_session()

        # Setup identity provider, mapping and protocol
        self._setup_idp()
        self._setup_mapping()
        self._setup_protocol()

    def _str_from_xml(self, xml, path):
        l = xml.xpath(path, namespaces=self.ECP_SAML2_NAMESPACES)
        self.assertEqual(1, len(l))
        return l[0]

    def _request_unscoped_token(self):
        resp = self.saml2_client.send_service_provider_request(
            self.keystone_v3_endpoint, self.idp_id, self.protocol_id)
        self.assertEqual(http_client.OK, resp.status_code)
        saml2_authn_request = etree.XML(resp.content)

        relay_state = self._str_from_xml(
            saml2_authn_request, self.ECP_RELAY_STATE)
        sp_consumer_url = self._str_from_xml(
            saml2_authn_request, self.ECP_SERVICE_PROVIDER_CONSUMER_URL)

        # Perform the authn request to the identity provider
        resp = self.saml2_client.send_identity_provider_authn_request(
            saml2_authn_request, self.idp_url, self.username, self.password)
        self.assertEqual(http_client.OK, resp.status_code)
        saml2_idp_authn_response = etree.XML(resp.content)

        idp_consumer_url = self._str_from_xml(
            saml2_idp_authn_response, self.ECP_IDP_CONSUMER_URL)

        # Assert that both saml2_authn_request and saml2_idp_authn_response
        # have the same consumer URL.
        self.assertEqual(sp_consumer_url, idp_consumer_url)

        # Present the identity provider authn response to the service provider.
        resp = self.saml2_client.send_service_provider_saml2_authn_response(
            saml2_idp_authn_response, relay_state, idp_consumer_url)
        # Must receive a redirect from service provider to the URL where the
        # unscoped token can be retrieved.
        self.assertIn(resp.status_code,
                      [http_client.FOUND, http_client.SEE_OTHER])

        # We can receive multiple types of errors here, the response depends on
        # the mapping and the username used to authenticate in the Identity
        # Provider and also in the Identity Provider remote ID validation.
        # If everything works well, we receive an unscoped token.
        sp_url = resp.headers['location']
        resp = (
            self.saml2_client.send_service_provider_unscoped_token_request(
                sp_url))
        self.assertEqual(http_client.CREATED, resp.status_code)
        self.assertIn('X-Subject-Token', resp.headers)
        self.assertNotEmpty(resp.json())

        return resp

    @testtools.skipUnless(CONF.identity_feature_enabled.federation,
                          "Federated Identity feature not enabled")
    def test_request_unscoped_token(self):
        self._request_unscoped_token()

    @testtools.skipUnless(CONF.identity_feature_enabled.federation,
                          "Federated Identity feature not enabled")
    def test_request_scoped_token(self):
        resp = self._request_unscoped_token()
        token_id = resp.headers['X-Subject-Token']

        projects = self.auth_client.get_available_projects_scopes(
            self.keystone_v3_endpoint, token_id)['projects']
        self.assertNotEmpty(projects)

        # Get a scoped token to one of the listed projects
        self.tokens_client.auth(
            project_id=projects[0]['id'], token=token_id)

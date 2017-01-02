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
import requests


class Saml2Client(object):

    ECP_SP_EMPTY_REQUEST_HEADERS = {
        'Accept': 'text/html, application/vnd.paos+xml',
        'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
                 'SAML:2.0:profiles:SSO:ecp"')
    }

    ECP_SP_SAML2_REQUEST_HEADERS = {'Content-Type': 'application/vnd.paos+xml'}

    def __init__(self):
        self.reset_session()

    def reset_session(self):
        self.session = requests.Session()

    def _idp_auth_url(self, keystone_v3_endpoint, idp_id, protocol_id):
        subpath = 'OS-FEDERATION/identity_providers/%s/protocols/%s/auth' % (
            idp_id, protocol_id)
        return '%s/%s' % (keystone_v3_endpoint, subpath)

    def send_service_provider_request(self, keystone_v3_endpoint,
                                      idp_id, protocol_id):
        return self.session.get(
            self._idp_auth_url(keystone_v3_endpoint, idp_id, protocol_id),
            headers=self.ECP_SP_EMPTY_REQUEST_HEADERS
        )

    def _prepare_sp_saml2_authn_response(self, saml2_idp_authn_response,
                                         relay_state):
        # Replace the header contents of the Identity Provider response with
        # the relay state initially sent by the Service Provider. The response
        # is a SOAP envelope with the following structure:
        #
        #   <S:Envelope
        #       <S:Header>
        #           ...
        #       </S:Header>
        #       <S:Body>
        #           ...
        #       </S:Body>
        #   </S:Envelope>
        saml2_idp_authn_response[0][0] = relay_state

    def send_identity_provider_authn_request(self, saml2_authn_request,
                                             idp_url, username, password):

        saml2_authn_request.remove(saml2_authn_request[0])
        return self.session.post(
            idp_url,
            headers={'Content-Type': 'text/xml'},
            data=etree.tostring(saml2_authn_request),
            auth=(username, password)
        )

    def send_service_provider_saml2_authn_response(
            self, saml2_idp_authn_response, relay_state, idp_consumer_url):

        self._prepare_sp_saml2_authn_response(
            saml2_idp_authn_response, relay_state)

        return self.session.post(
            idp_consumer_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
            data=etree.tostring(saml2_idp_authn_response),
            # Do not follow HTTP redirect
            allow_redirects=False
        )

    def send_service_provider_unscoped_token_request(self, sp_url):
        return self.session.get(
            sp_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS
        )

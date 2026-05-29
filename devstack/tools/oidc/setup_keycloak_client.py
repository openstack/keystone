import http
import os
import requests

KEYCLOAK_USERNAME = os.environ.get('KEYCLOAK_USERNAME')
KEYCLOAK_PASSWORD = os.environ.get('KEYCLOAK_PASSWORD')
KEYCLOAK_URL = os.environ.get('KEYCLOAK_URL')
HOST_IP = os.environ.get('HOST_IP', 'localhost')


class KeycloakClient:
    def __init__(self):
        self.session = requests.session()

    @staticmethod
    def construct_url(realm, path):
        return f'{KEYCLOAK_URL}/admin/realms/{realm}/{path}'

    @staticmethod
    def token_endpoint(realm):
        return f'{KEYCLOAK_URL}/realms/{realm}/protocol/openid-connect/token'

    def _admin_auth(self, realm):
        params = {
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': KEYCLOAK_USERNAME,
            'password': KEYCLOAK_PASSWORD,
            'scope': 'openid',
        }
        r = requests.post(self.token_endpoint(realm), data=params).json()
        headers = {
            'Authorization': f"Bearer {r['access_token']}",
            'Content-Type': 'application/json',
        }
        self.session.headers.update(headers)
        return r

    def _get_client_uuid(self, realm, client_id):
        resp = self.session.get(
            self.construct_url(realm, 'clients'),
            params={'clientId': client_id},
        )
        resp.raise_for_status()
        for client in resp.json():
            if client.get('clientId') == client_id:
                return client['id']
        return None

    def create_client(self, realm, client_id, client_secret, redirect_uris):
        self._admin_auth(realm)
        data = {
            'clientId': client_id,
            'secret': client_secret,
            'redirectUris': redirect_uris,
            'implicitFlowEnabled': True,
            'directAccessGrantsEnabled': True,
        }
        resp = self.session.post(
            self.construct_url(realm, 'clients'), json=data
        )
        if resp.status_code == http.HTTPStatus.CONFLICT:
            # Client already exists from a previous run; reuse it.
            client_uuid = self._get_client_uuid(realm, client_id)
            if client_uuid is None:
                resp.raise_for_status()
        else:
            resp.raise_for_status()
            # Keycloak returns 201 with the new client's UUID in the
            # Location header: .../admin/realms/<realm>/clients/<uuid>
            client_uuid = resp.headers['Location'].rsplit('/', 1)[-1]
        # Since Keycloak 26.6.2 (CVE-2026-37979) the OAuth2 token
        # introspection endpoint requires the introspecting client to
        # be present in the access token's "aud" claim. Apache's
        # mod_auth_openidc uses this same client to introspect bearer
        # tokens it receives from federated users, so we add an
        # audience protocol mapper that lists the client itself in
        # "aud". Without this, introspection returns active=false and
        # mod_auth_openidc rejects the token with HTTP 401.
        self._add_audience_mapper(realm, client_uuid, client_id)
        return resp

    def _add_audience_mapper(self, realm, client_uuid, audience_client_id):
        mapper = {
            'name': f'{audience_client_id}-audience',
            'protocol': 'openid-connect',
            'protocolMapper': 'oidc-audience-mapper',
            'config': {
                'included.client.audience': audience_client_id,
                'access.token.claim': 'true',
                'id.token.claim': 'false',
                'introspection.token.claim': 'true',
            },
        }
        path = f'clients/{client_uuid}/protocol-mappers/models'
        resp = self.session.post(self.construct_url(realm, path), json=mapper)
        if resp.status_code == http.HTTPStatus.CONFLICT:
            # Mapper already present from a previous run; nothing to do.
            return resp
        resp.raise_for_status()
        return resp


def main():
    c = KeycloakClient()

    redirect_uris = [
        f'http://{HOST_IP}/identity/v3/auth/OS-FEDERATION/identity_providers/sso/protocols/openid/websso',
        f'http://{HOST_IP}/identity/v3/auth/OS-FEDERATION/websso/openid',
    ]

    c.create_client('master', 'devstack', 'nomoresecret', redirect_uris)


if __name__ == "__main__":
    main()

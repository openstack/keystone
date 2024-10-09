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

    def create_client(self, realm, client_id, client_secret, redirect_uris):
        self._admin_auth(realm)
        data = {
            'clientId': client_id,
            'secret': client_secret,
            'redirectUris': redirect_uris,
            'implicitFlowEnabled': True,
            'directAccessGrantsEnabled': True,
        }
        return self.session.post(
            self.construct_url(realm, 'clients'), json=data
        )


def main():
    c = KeycloakClient()

    redirect_uris = [
        f'http://{HOST_IP}/identity/v3/auth/OS-FEDERATION/identity_providers/sso/protocols/openid/websso',
        f'http://{HOST_IP}/identity/v3/auth/OS-FEDERATION/websso/openid',
    ]

    c.create_client('master', 'devstack', 'nomoresecret', redirect_uris)


if __name__ == "__main__":
    main()

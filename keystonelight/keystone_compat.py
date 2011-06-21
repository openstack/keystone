# vim: tabstop=4 shiftwidth=4 softtabstop=4

# this is the web service frontend that emulates keystone
import logging

from keystonelight import service

def _token_to_keystone(token):
    return {'id': token,
            'expires': ''}


SERVICE_CATALOG = {"cdn": [{"adminURL": "http://cdn.admin-nets.local/v1.1/1234", "region": "RegionOne", "internalURL": "http://33.33.33.10:7777/v1.1/1234", "publicURL": "http://cdn.publicinternets.com/v1.1/1234"}], "nova_compat": [{"adminURL": "http://33.33.33.10:8774/v1.0", "region": "RegionOne", "internalURL": "http://33.33.33.10:8774/v1.0", "publicURL": "http://nova.publicinternets.com/v1.0/"}], "nova": [{"adminURL": "http://33.33.33.10:8774/v1.1", "region": "RegionOne", "internalURL": "http://33.33.33.10:8774/v1.1", "publicURL": "http://nova.publicinternets.com/v1.1/"}], "keystone": [{"adminURL": "http://33.33.33.10:8081/v2.0", "region": "RegionOne", "internalURL": "http://33.33.33.10:8080/v2.0", "publicURL": "http://keystone.publicinternets.com/v2.0"}], "glance": [{"adminURL": "http://nova.admin-nets.local/v1.1/1234", "region": "RegionOne", "internalURL": "http://33.33.33.10:9292/v1.1/1234", "publicURL": "http://glance.publicinternets.com/v1.1/1234"}], "swift": [{"adminURL": "http://swift.admin-nets.local:8080/", "region": "RegionOne", "internalURL": "http://33.33.33.10:8080/v1/AUTH_1234", "publicURL": "http://swift.publicinternets.com/v1/AUTH_1234"}]}



class KeystoneIdentityController(service.IdentityController):
    def authenticate(self, context, **kwargs):
        kwargs = kwargs['passwordCredentials']
        token = super(KeystoneIdentityController, self).authenticate(
                context, **kwargs)
        return {'auth': {'token': _token_to_keystone(token),
                         'serviceCatalog': SERVICE_CATALOG}}


class KeystoneTokenController(service.TokenController):
    def validate_token(self, context, token_id):
        token = super(KeystoneTokenController, self).validate_token(
                context, token_id)
        # TODO(termie): munge into keystone format

        tenants = [{'tenantId': token['tenant']['id'],
                    'name': token['tenant']['name']}]
        roles = []
        if token['extras'].get('is_admin'):
            roles.append({
                    'roleId': 'Admin',
                    'href': 'https://www.openstack.org/identity/v2.0/roles/admin',
                    'tenantId': token['tenant']['id']})

        return {'auth': {'token': _token_to_keystone(token),
                         'user': {'groups': {'group': tenants},
                                  'roleRefs': roles,
                                  'username': token['user']['name'],
                                  'tenantId': token['tenant']['id']}}}

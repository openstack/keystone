# vim: tabstop=4 shiftwidth=4 softtabstop=4

# this is the web service frontend that emulates keystone
from keystonelight import service

def _token_to_keystone(token):
    return {'id': token['id'],
            'expires': token.get('expires', '')


class KeystoneIdentityController(service.IdentityController):
    def authenticate(self, context, **kwargs):
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
                    'id': 1,
                    'href': 'https://.openstack.org/identity/v2.0/roles/admin',
                    'tenantId': token['tenant']['id']})

        return {'auth': {'token': _token_to_keystone(token),
                         'user': {'groups': {'group': tenants},
                                  'roleRefs': {'roleRef': roles}
                                  'username': token['user']['name'],
                                  'tenantId': token['tenant']['id']}}}

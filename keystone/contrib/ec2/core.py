# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""Main entry point into the EC2 Credentials service."""

from keystone import catalog
from keystone import config
from keystone import identity
from keystone import policy
from keystone import token
from keystone.common import manager
from keystone.common import wsgi


CONF = config.CONF


class Manager(manager.Manager):
    """Default pivot point for the EC2 Credentials backend.

    See :mod:`keystone.manager.Manager` for more details on how this
    dynamically calls the backend.

    See :mod:`keystone.backends.base.Ec2` for more details on the
    interface provided by backends.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.ec2.driver)


class Ec2Extension(wsgi.ExtensionRouter):
    def add_routes(self, mapper):
        ec2_controller = Ec2Controller()
        # validation
        mapper.connect('/ec2tokens',
                       controller=ec2_controller,
                       action='authenticate_ec2',
                       conditions=dict(method=['POST']))

        # crud
        mapper.connect('/users/{user_id}/credentials/OS-EC2',
                       controller=ec2_controller,
                       action='create_credential',
                       conditions=dict(method=['POST']))
        mapper.connect('/users/{user_id}/credentials/OS-EC2',
                       controller=ec2_controller,
                       action='get_credentials',
                       conditions=dict(method=['GET']))
        mapper.connect('/users/{user_id}/credentials/OS-EC2/{credential_id}',
                       controller=ec2_controller,
                       action='get_credential',
                       conditions=dict(method=['GET']))
        mapper.connect('/users/{user_id}/credentials/OS-EC2/{credential_id}',
                       controller=ec2_controller,
                       action='delete_credential',
                       conditions=dict(method=['DELETE']))


class Ec2Controller(wsgi.Application):
    def __init__(self):
        self.catalog_api = catalog.Manager()
        self.identity_api = identity.Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        self.ec2_api = Manager()
        super(Ec2Controller, self).__init__()

    def authenticate_ec2(self, context, credentials=None,
                         ec2Credentials=None):
        """Validate a signed EC2 request and provide a token."""
        # NOTE(termie): backwards compat hack
        if not credentials and ec2Credentials:
            credentials = ec2Credentials
        creds_ref = self.ec2_api.get_credential(context,
                                                credentials['access'])

        signer = utils.Signer(creds_ref['secret'])
        signature = signer.generate(credentials)
        if signature == credentials['signature']:
            pass
        # NOTE(vish): Some libraries don't use the port when signing
        #             requests, so try again without port.
        elif ':' in credentials['signature']:
            hostname, _port = credentials['host'].split(":")
            credentials['host'] = hostname
            signature = signer.generate(credentials)
            if signature != credentials.signature:
                # TODO(termie): proper exception
                raise Exception("Not Authorized")
        else:
            raise Exception("Not Authorized")

        # TODO(termie): don't create new tokens every time
        # TODO(termie): this is copied from TokenController.authenticate
        token_id = uuid.uuid4().hex
        tenant_ref = self.identity_api.get_tenant(creds_ref['tenant_id'])
        user_ref = self.identity_api.get_user(creds_ref['user_id'])
        metadata_ref = self.identity_api.get_metadata(
                context=context,
                user_id=user_ref['id'],
                tenant_id=tenant_ref['id'])
        catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=user_ref['id'],
                tenant_id=tenant_ref['id'],
                    metadata=metadata_ref)

        token_ref = self.token_api.create_token(
                context, token_id, dict(expires='',
                                        id=token_id,
                                        user=user_ref,
                                        tenant=tenant_ref,
                                        metadata=metadata_ref))

        # TODO(termie): optimize this call at some point and put it into the
        #               the return for metadata
        # fill out the roles in the metadata
        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            roles_ref.append(self.identity_api.get_role(context, role_id))

        # TODO(termie): make this a util function or something
        # TODO(termie): i don't think the ec2 middleware currently expects a
        #               full return, but it contains a note saying that it
        #               would be better to expect a full return
        return TokenController._format_authenticate(
                self, token_ref, roles_ref, catalog_ref)

    def create_credential(self, context, user_id, tenant_id):
        # TODO(termie): validate that this request is valid for given user
        #               tenant
        cred_ref = {'user_id': user_id,
                    'tenant_id': tenant_id,
                    'access': uuid.uuid4().hex,
                    'secret': uuid.uuid4().hex}
        self.ec2_api.create_credential(context, cred_ref['access'], cred_ref)
        return {'credential': cred_ref}

    def get_credentials(self, context, user_id):
        """List credentials for the given user_id."""
        # TODO(termie): validate that this request is valid for given user
        #               tenant
        return {'credentials': self.ec2_api.list_credentials(context, user_id)}

    def get_credential(self, context, user_id, credential_id):
        # TODO(termie): validate that this request is valid for given user
        #               tenant
        return {'credential': self.ec2_api.get_credential(context,
                                                          credential_id)}

    def delete_credential(self, context, user_id, credential_id):
        # TODO(termie): validate that this request is valid for given user
        #               tenant
        return self.ec2_api.delete_credential(context, credential_id)



from keystone import models
from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--tenant-id',
    required=True,
    help='identify the tenant to be mapped by ID')
@common.arg('--endpoint-template-id',
    required=True,
    help='identify the endpoint to be mapped by ID')
class Command(base.BaseBackendCommand):
    """Maps a non-global endpoint to a tenant.

    If a mapping exists between a tenant and an endpoint template, then
    the endpoint will appear in the tenant's service catalog, customized
    for the tenant.

    Global endpoints are already available to all tenants and therefore don't
    need to be mapped.
    """

    # pylint: disable=E1101,R0913
    def create_endpoint(self, endpoint_template_id, tenant_id):
        self.get_endpoint_template(endpoint_template_id)
        self.get_tenant(tenant_id)

        obj = models.Endpoint()
        obj.endpoint_template_id = endpoint_template_id
        obj.tenant_id = tenant_id

        self.endpoint_manager.create(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.create_endpoint(endpoint_template_id=args.endpoint_template_id,
                tenant_id=args.tenant_id)

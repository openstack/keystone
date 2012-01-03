from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--tenant-id',
    required=True,
    help='identify the tenant to be unmapped by ID')
@common.arg('--endpoint-template-id',
    required=True,
    help='identify the endpoint template to be unmapped by ID')
class Command(base.BaseBackendCommand):
    """Unmap an endpoint template from a tenant."""

    # pylint: disable=E1101,R0913
    def delete_endpoint(self, endpoint_template_id, tenant_id):
        obj = self.endpoint_manager.get_by_ids(endpoint_template_id, tenant_id)

        if obj is None:
            raise KeyError("Endpoint mapping not found for "
                    "endpoint_template_id=%s, tenant_id=%s" % (
                        endpoint_template_id, tenant_id))

        self.endpoint_manager.delete(obj.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.delete_endpoint(endpoint_template_id=args.endpoint_template_id,
                tenant_id=args.tenant_id)

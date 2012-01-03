from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identify the endpoint template to be deleted by ID')
class Command(base.BaseBackendCommand):
    """Deletes the specified endpoint_template."""

    # pylint: disable=E1101
    def delete_endpoint_template(self, id):
        endpoint_template = self.get_endpoint_template(id)
        self.endpoint_template_manager.delete(endpoint_template.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.delete_endpoint_template(id=args.where_id)

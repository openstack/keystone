from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identify the service to be deleted by ID')
class Command(base.BaseBackendCommand):
    """Deletes the specified service."""

    # pylint: disable=E1101
    def delete_service(self, id):
        service = self.get_service(id)
        self.service_manager.delete(service.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.delete_service(id=args.where_id)

from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identify the role to be deleted by ID')
class Command(base.BaseBackendCommand):
    """Deletes the specified role."""

    # pylint: disable=E1101
    def delete_role(self, id):
        role = self.get_role(id)
        self.role_manager.delete(role.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.delete_role(id=args.where_id)

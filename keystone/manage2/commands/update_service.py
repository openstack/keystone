from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identifies the service to update by ID')
@common.arg('--name',
    required=False,
    help='unique service name')
@common.arg('--type',
    required=False,
    help='service type (e.g. identity, compute, object-storage, etc)')
@common.arg('--description',
    required=False,
    help='describe the service')
@common.arg('--owner-id',
    required=False,
    help='user who owns the service')
class Command(base.BaseBackendCommand):
    """Updates the specified service."""

    # pylint: disable=E1101,R0913
    def update_service(self, id, name=None, service_type=None,
            description=None, owner_id=None):
        obj = self.get_service(id)

        if name is not None:
            obj.name = name

        if service_type is not None:
            obj.type = service_type

        if description is not None:
            obj.description = description

        if owner_id is not None:
            owner = self.get_user(owner_id)
            obj.owner_id = owner.id

        self.service_manager.update(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.update_service(id=args.where_id, name=args.name,
                service_type=args.type,
                description=args.description, owner_id=args.owner_id)

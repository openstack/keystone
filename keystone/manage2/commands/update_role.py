from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identifies the role to update by ID')
@common.arg('--name',
    required=False,
    help='a unique role name')
@common.arg('--description',
    required=False,
    help='describe the role')
@common.arg('--service-id',
    required=False,
    help='service which owns the role')
class Command(base.BaseBackendCommand):
    """Updates the specified role."""

    # pylint: disable=E1101,R0913
    def update_role(self, id, name=None, description=None, service_id=None):
        obj = self.get_role(id)

        if name is not None:
            obj.name = name

        if description is not None:
            obj.description = description

        if service_id is not None:
            service = self.get_service(service_id)
            obj.service_id = service.id

        self.role_manager.update(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.update_role(id=args.where_id, name=args.name,
                description=args.description,
                service_id=args.service_id)

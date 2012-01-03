from keystone import models
from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--name',
    required=True,
    help='a unique role name')
@common.arg('--description',
    required=False,
    help='describe the role')
@common.arg('--service-id',
    required=False,
    help='service which owns the role')
class Command(base.BaseBackendCommand):
    """Creates a new role.

    Optionally, specify a service to own the role.
    """

    # pylint: disable=E1101
    def create_role(self, name, description=None, service_id=None):
        self.get_service(service_id)

        obj = models.Role()
        obj.name = name
        obj.description = description
        obj.service_id = service_id

        return self.role_manager.create(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        role = self.create_role(name=args.name,
                description=args.description, service_id=args.service_id)
        print role.id

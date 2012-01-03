from keystone.manage2 import common
from keystone.manage2 import base
from keystone.backends import models


@common.arg('--name',
    required=True,
    help='unique service name')
@common.arg('--type',
    required=True,
    help='service type (e.g. identity, compute, object-storage, etc)')
@common.arg('--description',
    required=False,
    help='describe the service')
@common.arg('--owner-id',
    required=False,
    help='user who owns the service')
class Command(base.BaseBackendCommand):
    """Creates a new service.

    Optionally, specify a user to own the service.
    """

    # pylint: disable=E1101,R0913
    def create_service(self, name, service_type, description=None,
            owner_id=None):
        self.get_user(owner_id)

        obj = models.Service()
        obj.name = name
        obj.type = service_type
        obj.owner_id = owner_id
        obj.desc = description

        return self.service_manager.create(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        service = self.create_service(name=args.name,
                service_type=args.type, description=args.description,
                owner_id=args.owner_id)
        print service.id

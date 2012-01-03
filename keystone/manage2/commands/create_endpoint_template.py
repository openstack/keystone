from keystone import models
from keystone.manage2 import base
from keystone.manage2 import common
from keystone.manage2 import mixins


@common.arg('--region',
    required=True,
    help='identifies the region where the endpoint exists')
@common.arg('--service-id',
    required=True,
    help='references the service that owns the endpoint, by ID')
@common.arg('--public-url',
    required=True,
    help='url to access the endpoint over a public network (e.g. the '
        'internet)')
@common.arg('--admin-url',
    required=True,
    help='url to access service administrator api')
@common.arg('--internal-url',
    required=True,
    help='url to access the endpoint over a high bandwidth, low latency, '
        'unmetered network (e.g. LAN)')
@common.arg('--global',
    action='store_true',
    required=False,
    default=False,
    help='indicates whether the endpoint should be mapped to tenants '
        '(tenant-specific) or not (global)')
@common.arg('--disabled',
    action='store_true',
    required=False,
    default=False,
    help="create the endpoint in a disabled state (endpoints are enabled by "
            "default)")
class Command(base.BaseBackendCommand, mixins.DateTimeMixin):
    """Creates a new endpoint template."""

    # pylint: disable=E1101,R0913
    def create_endpoint_template(self, region, service_id, public_url,
            admin_url, internal_url, is_global=False, is_enabled=True):
        self.get_service(service_id)

        obj = models.EndpointTemplate()
        obj.region = region
        obj.service_id = service_id
        obj.public_url = public_url
        obj.admin_url = admin_url
        obj.internal_url = internal_url
        obj.is_global = is_global
        obj.enabled = is_enabled

        return self.endpoint_template_manager.create(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        endpoint_template = self.create_endpoint_template(region=args.region,
                service_id=args.service_id, public_url=args.public_url,
                admin_url=args.admin_url, internal_url=args.internal_url,
                is_global=getattr(args, 'global'),
                is_enabled=(not args.disabled))
        print endpoint_template.id

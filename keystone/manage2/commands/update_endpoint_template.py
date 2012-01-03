from keystone.manage2 import base
from keystone.manage2 import common
from keystone.manage2 import mixins


@common.arg('--where-id',
    required=True,
    help='identifies the endpoint template to update by ID')
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
    help='indicates whether the endpoint should apply to all tenants')
@common.arg('--non-global',
    action='store_true',
    required=False,
    default=False,
    help='indicates whether the endpoint should be mapped to specific tenants')
@common.arg('--enable',
    action='store_true',
    required=False,
    default=False,
    help="enable the endpoint template")
@common.arg('--disable',
    action='store_true',
    required=False,
    default=False,
    help="disable the endpoint template")
class Command(base.BaseBackendCommand, mixins.DateTimeMixin):
    """Updates an existing endpoint template."""

    # pylint: disable=E1101,R0913
    def update_endpoint_template(self, id, region, service_id, public_url,
            admin_url, internal_url, is_global=False, is_enabled=True):
        obj = self.get_endpoint_template(id)

        self.get_service(service_id)

        if region is not None:
            obj.region = region

        if service_id is not None:
            obj.service_id = service_id

        if public_url is not None:
            obj.public_url = public_url

        if admin_url is not None:
            obj.admin_url = admin_url

        if internal_url is not None:
            obj.internal_url = internal_url

        if is_global is not None:
            obj.is_global = is_global

        if is_enabled is not None:
            obj.enabled = is_enabled

        self.endpoint_template_manager.update(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        is_global = self.true_or_false(args, 'global', 'non_global')
        enabled = self.true_or_false(args, 'enable', 'disable')

        self.update_endpoint_template(id=args.where_id,
                region=args.region, service_id=args.service_id,
                public_url=args.public_url, admin_url=args.admin_url,
                internal_url=args.internal_url, is_global=is_global,
                is_enabled=enabled)

"""Prints keystone's version information"""


from keystone import version
from keystone.manage2 import common


@common.arg('--api', action='store_true',
    default=False,
    help='only print the API version')
@common.arg('--implementation', action='store_true',
    default=False,
    help='only print the implementation version')
class Command(common.BaseCommand):
    """Returns keystone version data.

    Includes the latest API version, implementation version, or both,
    if neither is specified.
    """

    def get_api_version(self):
        """Returns a complete API version string"""
        return ' '.join([version.API_VERSION, version.API_VERSION_STATUS])

    def get_implementation_version(self):
        """Returns a complete implementation version string"""
        return version.version()

    @staticmethod
    def run(args):
        """Process argparse args, and print results to stdout"""
        cmd = Command()

        show_all = not (args.api or args.implementation)

        if args.api or show_all:
            print 'API v%s' % cmd.get_api_version()
        if args.implementation or show_all:
            print 'Implementation v%s' % cmd.get_implementation_version()

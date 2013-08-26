import os

from paste import deploy

from keystone.openstack.common import gettextutils

# NOTE(blk-u):
# gettextutils.install() must run to set _ before importing any modules that
# contain static translated strings.
#
# Configure gettextutils for deferred translation of messages
# so that error messages in responses can be translated according to the
# Accept-Language in the request rather than the Keystone server locale.
gettextutils.install('keystone', lazy=True)

from keystone.common import environment
from keystone import config
from keystone.openstack.common import log as logging


LOG = logging.getLogger(__name__)
CONF = config.CONF
CONF(project='keystone')
config.setup_logging(CONF)

environment.use_stdlib()
name = os.path.basename(__file__)

if CONF.debug:
    CONF.log_opt_values(logging.getLogger(CONF.prog), logging.DEBUG)

# NOTE(ldbragst): 'application' is required in this context by WSGI spec.
# The following is a reference to Python Paste Deploy documentation
# http://pythonpaste.org/deploy/
application = deploy.loadapp('config:%s' % config.find_paste_config(),
                             name=name)

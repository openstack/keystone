import os

from paste import deploy

from keystone.common import environment
from keystone.common import logging
from keystone import config
from keystone.openstack.common import gettextutils

gettextutils.install('keystone')

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

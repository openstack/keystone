import os

from paste import deploy

from keystone.common import logging
from keystone import config

LOG = logging.getLogger(__name__)
CONF = config.CONF
CONF(project='keystone')

name = os.path.basename(__file__)

if CONF.debug:
    CONF.log_opt_values(logging.getLogger(CONF.prog), logging.DEBUG)

deploy.loadapp('config:%s' % config.find_paste_config(), name=name)

import os

from paste import deploy

from keystone import config
from keystone.common import logging

LOG = logging.getLogger(__name__)
CONF = config.CONF
config_files = ['/etc/keystone/keystone.conf']
CONF(project='keystone', default_config_files=config_files)

conf = CONF.config_file[0]
name = os.path.basename(__file__)

if CONF.debug:
    CONF.log_opt_values(logging.getLogger(CONF.prog), logging.DEBUG)

options = deploy.appconfig('config:%s' % CONF.config_file[0])

application = deploy.loadapp('config:%s' % conf, name=name)

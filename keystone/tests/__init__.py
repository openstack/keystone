
from keystone.openstack.common import gettextutils


# NOTE(blk-u):
# gettextutils.install() must run to set _ before importing any modules that
# contain static translated strings.
#
# Configure gettextutils for deferred translation of messages
# so that error messages in responses can be translated according to the
# Accept-Language in the request rather than the Keystone server locale.
gettextutils.install('keystone', lazy=True)

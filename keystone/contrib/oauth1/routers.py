# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log
from oslo_log import versionutils

from keystone.common import wsgi
from keystone.i18n import _


LOG = log.getLogger(__name__)


class OAuth1Extension(wsgi.Middleware):

    def __init__(self, *args, **kwargs):
        super(OAuth1Extension, self).__init__(*args, **kwargs)
        msg = _("Remove oauth1_extension from the paste pipeline, the "
                "oauth1 extension is now always available. Update the "
                "[pipeline:api_v3] section in keystone-paste.ini accordingly, "
                "as it will be removed in the O release.")
        versionutils.report_deprecated_feature(LOG, msg)

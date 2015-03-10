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

from oslo_utils import timeutils

from keystone.common import controller
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _


@dependency.requires('revoke_api')
class RevokeController(controller.V3Controller):
    @controller.protected()
    def list_revoke_events(self, context):
        since = context['query_string'].get('since')
        last_fetch = None
        if since:
            try:
                last_fetch = timeutils.normalize_time(
                    timeutils.parse_isotime(since))
            except ValueError:
                raise exception.ValidationError(
                    message=_('invalid date format %s') % since)
        events = self.revoke_api.list_events(last_fetch=last_fetch)
        # Build the links by hand as the standard controller calls require ids
        response = {'events': [event.to_dict() for event in events],
                    'links': {
                        'next': None,
                        'self': RevokeController.base_url(
                            context,
                            path=context['path']),
                        'previous': None}
                    }
        return response

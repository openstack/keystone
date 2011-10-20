# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystone.backends.sqlalchemy import get_session, models
from keystone.backends.api import BaseCredentialsAPI


class CredentialsAPI(BaseCredentialsAPI):
    def create(self, values):
        credentials_ref = models.Credentials()
        credentials_ref.update(values)
        credentials_ref.save()
        return credentials_ref

    def get(self, id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Credentials).filter_by(id=id).first()
        return result

    def get_by_access(self, access, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Credentials).\
                         filter_by(type="EC2", key=access).first()
        return result

    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            group_ref = self.get(id, session)
            session.delete(group_ref)


def get():
    return CredentialsAPI()

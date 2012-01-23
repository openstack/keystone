# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
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
from keystone.backends import api
from keystone.models import Service


# pylint: disable=E1103,W0221
class ServiceAPI(api.BaseServiceAPI):
    def __init__(self, *args, **kw):
        super(ServiceAPI, self).__init__(*args, **kw)

    # pylint: disable=W0221
    @staticmethod
    def transpose(values):
        """ Handles transposing field names from Keystone model to
        sqlalchemy model

        Differences:
            desc <-> description
            id <-> uid (coming soon)
        """
        if 'description' in values:
            values['desc'] = values.pop('description')

        if hasattr(api.USER, 'uid_to_id'):
            if 'owner_id' in values:
                values['owner_id'] = api.USER.uid_to_id(values['owner_id'])
            elif hasattr(values, 'owner_id'):
                values.owner_id = api.USER.uid_to_id(values.owner_id)

    @staticmethod
    def from_model(ref):
        """ Returns SQLAlchemy model object based on Keystone model"""
        if ref:
            if hasattr(api.USER, 'uid_to_id'):
                if 'owner_id' in ref:
                    ref['owner_id'] = api.USER.uid_to_id(ref['owner_id'])
                elif hasattr(ref, 'owner_id'):
                    ref.owner_id = api.USER.uid_to_id(ref.owner_id)

            result = models.Service()
            try:
                result.id = int(ref.id)
            except (AttributeError, TypeError):
                # Unspecified or invalid ID -- ignore it.
                pass
            result.update(ref)
            if hasattr(ref, 'description'):
                result.desc = ref.description
            return result

    @staticmethod
    def to_model(ref):
        """ Returns Keystone model object based on SQLAlchemy model"""
        if ref:
            if hasattr(api.USER, 'id_to_uid'):
                if 'owner_id' in ref:
                    ref['owner_id'] = api.USER.id_to_uid(ref['owner_id'])
                elif hasattr(ref, 'owner_id'):
                    ref.owner_id = api.USER.id_to_uid(ref.owner_id)

            return Service(id=str(ref.id), name=ref.name, description=ref.desc,
                type=ref.type, owner_id=ref.owner_id)

    @staticmethod
    def to_model_list(refs):
        return [ServiceAPI.to_model(ref) for ref in refs]

    # pylint: disable=W0221
    def create(self, values):
        service_ref = ServiceAPI.from_model(values)
        service_ref.save()
        return ServiceAPI.to_model(service_ref)

    @staticmethod
    def update(id, values, session=None):
        if not session:
            session = get_session()

        ServiceAPI.transpose(values)

        with session.begin():
            service_ref = session.query(models.Service).filter_by(id=id).\
                    first()
            service_ref.update(values)
            service_ref.save(session=session)

    def get(self, id, session=None):
        if not session:
            session = get_session()
        return ServiceAPI.to_model(session.query(models.Service).
                                   filter_by(id=id).first())

    def get_by_name(self, name, session=None):
        if not session:
            session = get_session()
        return ServiceAPI.to_model(session.query(models.Service).
                                   filter_by(name=name).first())

    def get_by_name_and_type(self, name, type, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Service).\
                filter_by(name=name).\
                filter_by(type=type).\
                first()
        return ServiceAPI.to_model(result)

    def get_all(self, session=None):
        if not session:
            session = get_session()
        return ServiceAPI.to_model_list(session.query(models.Service).all())

    def get_page(self, marker, limit, session=None):
        if not session:
            session = get_session()
        if marker:
            return session.query(models.Service).filter("id>:marker").params(
                    marker='%s' % marker).order_by(
                    models.Service.id.desc()).limit(int(limit)).all()
        else:
            return session.query(models.Service).order_by(
                                models.Service.id.desc()).limit(
                                int(limit)).all()

    @staticmethod
    def get_page_markers(marker, limit, session=None):
        if not session:
            session = get_session()
        first = session.query(models.Service).order_by(
                            models.Service.id).first()
        last = session.query(models.Service).order_by(
                            models.Service.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next_page = session.query(models.Service).\
                        filter("id > :marker").params(
                        marker='%s' % marker).order_by(
                        models.Service.id).limit(int(limit)).all()
        prev_page = session.query(models.Service).\
                        filter("id < :marker").params(
                        marker='%s' % marker).order_by(
                        models.Service.id.desc()).limit(int(limit)).all()
        if len(next_page) == 0:
            next_page = last
        else:
            for t in next_page:
                next_page = t
        if len(prev_page) == 0:
            prev_page = first
        else:
            for t in prev_page:
                prev_page = t
        if prev_page.id == marker:
            prev_page = None
        else:
            prev_page = prev_page.id
        if next_page.id == last.id:
            next_page = None
        else:
            next_page = next_page.id
        return (prev_page, next_page)

    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            service_ref = session.query(models.Service).\
                                   filter_by(id=id).first()
            session.delete(service_ref)


def get():
    return ServiceAPI()

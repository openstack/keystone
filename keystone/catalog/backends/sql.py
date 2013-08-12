# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 OpenStack LLC
# Copyright 2012 Canonical Ltd.
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

from keystone import catalog
from keystone.catalog import core
from keystone.common import sql
from keystone.common.sql import migration
from keystone import config
from keystone import exception


CONF = config.CONF


class Service(sql.ModelBase, sql.DictBase):
    __tablename__ = 'service'
    attributes = ['id', 'type']
    id = sql.Column(sql.String(64), primary_key=True)
    type = sql.Column(sql.String(255))
    extra = sql.Column(sql.JsonBlob())
    endpoints = sql.relationship("Endpoint", backref="service")


class Endpoint(sql.ModelBase, sql.DictBase):
    __tablename__ = 'endpoint'
    attributes = ['id', 'interface', 'region', 'service_id', 'url',
                  'legacy_endpoint_id']
    id = sql.Column(sql.String(64), primary_key=True)
    legacy_endpoint_id = sql.Column(sql.String(64))
    interface = sql.Column(sql.String(8), nullable=False)
    region = sql.Column(sql.String(255))
    service_id = sql.Column(sql.String(64),
                            sql.ForeignKey('service.id'),
                            nullable=False)
    url = sql.Column(sql.Text(), nullable=False)
    extra = sql.Column(sql.JsonBlob())


class Catalog(sql.Base, catalog.Driver):
    def db_sync(self, version=None):
        migration.db_sync(version=version)

    # Services
    def list_services(self):
        session = self.get_session()
        services = session.query(Service).all()
        return [s.to_dict() for s in list(services)]

    def _get_service(self, session, service_id):
        ref = session.query(Service).get(service_id)
        if not ref:
            raise exception.ServiceNotFound(service_id=service_id)
        return ref

    def get_service(self, service_id):
        session = self.get_session()
        return self._get_service(session, service_id).to_dict()

    def delete_service(self, service_id):
        session = self.get_session()
        with session.begin():
            ref = self._get_service(session, service_id)
            session.query(Endpoint).filter_by(service_id=service_id).delete()
            session.delete(ref)
            session.flush()

    def create_service(self, service_id, service_ref):
        session = self.get_session()
        with session.begin():
            service = Service.from_dict(service_ref)
            session.add(service)
            session.flush()
        return service.to_dict()

    def update_service(self, service_id, service_ref):
        session = self.get_session()
        with session.begin():
            ref = self._get_service(session, service_id)
            old_dict = ref.to_dict()
            old_dict.update(service_ref)
            new_service = Service.from_dict(old_dict)
            for attr in Service.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_service, attr))
            ref.extra = new_service.extra
            session.flush()
        return ref.to_dict()

    # Endpoints
    def create_endpoint(self, endpoint_id, endpoint_ref):
        session = self.get_session()
        self.get_service(endpoint_ref['service_id'])
        new_endpoint = Endpoint.from_dict(endpoint_ref)
        with session.begin():
            session.add(new_endpoint)
            session.flush()
        return new_endpoint.to_dict()

    def delete_endpoint(self, endpoint_id):
        session = self.get_session()
        with session.begin():
            ref = self._get_endpoint(session, endpoint_id)
            session.delete(ref)
            session.flush()

    def _get_endpoint(self, session, endpoint_id):
        try:
            return session.query(Endpoint).filter_by(id=endpoint_id).one()
        except sql.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    def get_endpoint(self, endpoint_id):
        session = self.get_session()
        return self._get_endpoint(session, endpoint_id).to_dict()

    def list_endpoints(self):
        session = self.get_session()
        endpoints = session.query(Endpoint)
        return [e.to_dict() for e in list(endpoints)]

    def update_endpoint(self, endpoint_id, endpoint_ref):
        session = self.get_session()
        with session.begin():
            ref = self._get_endpoint(session, endpoint_id)
            old_dict = ref.to_dict()
            old_dict.update(endpoint_ref)
            new_endpoint = Endpoint.from_dict(old_dict)
            for attr in Endpoint.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_endpoint, attr))
            ref.extra = new_endpoint.extra
            session.flush()
        return ref.to_dict()

    def get_catalog(self, user_id, tenant_id, metadata=None):
        d = dict(CONF.iteritems())
        d.update({'tenant_id': tenant_id,
                  'user_id': user_id})

        session = self.get_session()
        endpoints = (session.query(Endpoint).
                     options(sql.joinedload(Endpoint.service)).
                     all())

        catalog = {}

        for endpoint in endpoints:
            region = endpoint['region']
            service_type = endpoint.service['type']
            default_service = {
                'id': endpoint['id'],
                'name': endpoint.service['name'],
                'publicURL': ''
            }
            catalog.setdefault(region, {})
            catalog[region].setdefault(service_type, default_service)
            url = core.format_url(endpoint['url'], d)
            interface_url = '%sURL' % endpoint['interface']
            catalog[region][service_type][interface_url] = url

        return catalog

    def get_v3_catalog(self, user_id, tenant_id, metadata=None):
        d = dict(CONF.iteritems())
        d.update({'tenant_id': tenant_id,
                  'user_id': user_id})

        session = self.get_session()
        services = (session.query(Service).
                    options(sql.joinedload(Service.endpoints)).
                    all())

        def make_v3_endpoint(endpoint):
            del endpoint['service_id']
            endpoint['url'] = core.format_url(endpoint['url'], d)
            return endpoint

        catalog = [{'endpoints': [make_v3_endpoint(ep.to_dict())
                                  for ep in svc.endpoints],
                    'id': svc.id,
                    'type': svc.type} for svc in services]

        return catalog

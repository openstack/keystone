# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

"""Export data from Nova database and import through Identity Service."""

import uuid

from keystone import assignment
from keystone.common import logging
from keystone import config
from keystone.contrib.ec2.backends import sql as ec2_sql
from keystone import identity


LOG = logging.getLogger(__name__)
CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


def import_auth(data):
    identity_api = identity.Manager()
    assignment_api = assignment.Manager()

    tenant_map = _create_projects(assignment_api, data['tenants'])
    user_map = _create_users(identity_api, data['users'])
    _create_memberships(assignment_api, data['user_tenant_list'],
                        user_map, tenant_map)
    role_map = _create_roles(assignment_api, data['roles'])
    _assign_roles(assignment_api, data['role_user_tenant_list'],
                  role_map, user_map, tenant_map)

    ec2_api = ec2_sql.Ec2()
    ec2_creds = data['ec2_credentials']
    _create_ec2_creds(ec2_api, assignment_api, ec2_creds, user_map)


def _generate_uuid():
    return uuid.uuid4().hex


def _create_projects(api, tenants):
    tenant_map = {}
    for tenant in tenants:
        tenant_dict = {
            'id': _generate_uuid(),
            'name': tenant['id'],
            'domain_id': tenant.get('domain_id', DEFAULT_DOMAIN_ID),
            'description': tenant['description'],
            'enabled': True,
        }
        tenant_map[tenant['id']] = tenant_dict['id']
        LOG.debug(_('Create tenant %s') % tenant_dict)
        api.create_project(tenant_dict['id'], tenant_dict)
    return tenant_map


def _create_users(api, users):
    user_map = {}
    for user in users:
        user_dict = {
            'id': _generate_uuid(),
            'name': user['id'],
            'domain_id': user.get('domain_id', DEFAULT_DOMAIN_ID),
            'email': '',
            'password': user['password'],
            'enabled': True,
        }
        user_map[user['id']] = user_dict['id']
        LOG.debug(_('Create user %s') % user_dict)
        api.create_user(user_dict['id'], user_dict)
    return user_map


def _create_memberships(api, memberships, user_map, tenant_map):
    for membership in memberships:
        user_id = user_map[membership['user_id']]
        tenant_id = tenant_map[membership['tenant_id']]
        LOG.debug(_('Add user %(user_id)s to tenant %(tenant_id)s') % {
            'user_id': user_id, 'tenant_id': tenant_id})
        api.add_user_to_project(tenant_id, user_id)


def _create_roles(api, roles):
    role_map = dict((r['name'], r['id']) for r in api.list_roles())
    for role in roles:
        if role in role_map:
            LOG.debug(_('Ignoring existing role %s') % role)
            continue
        role_dict = {
            'id': _generate_uuid(),
            'name': role,
        }
        role_map[role] = role_dict['id']
        LOG.debug(_('Create role %s') % role_dict)
        api.create_role(role_dict['id'], role_dict)
    return role_map


def _assign_roles(api, assignments, role_map, user_map, tenant_map):
    for assignment in assignments:
        role_id = role_map[assignment['role']]
        user_id = user_map[assignment['user_id']]
        tenant_id = tenant_map[assignment['tenant_id']]
        LOG.debug(_(
            'Assign role %(role_id)s to user %(user_id)s on tenant '
            '%(tenant_id)s') % {
                'role_id': role_id,
                'user_id': user_id,
                'tenant_id': tenant_id})
        api.add_role_to_user_and_project(user_id, tenant_id, role_id)


def _create_ec2_creds(ec2_api, assignment_api, ec2_creds, user_map):
    for ec2_cred in ec2_creds:
        user_id = user_map[ec2_cred['user_id']]
        for tenant_id in assignment_api.get_projects_for_user(user_id):
            cred_dict = {
                'access': '%s:%s' % (tenant_id, ec2_cred['access_key']),
                'secret': ec2_cred['secret_key'],
                'user_id': user_id,
                'tenant_id': tenant_id,
            }
            LOG.debug(_(
                'Creating ec2 cred for user %(user_id)s and tenant '
                '%(tenant_id)s') % {
                    'user_id': user_id, 'tenant_id': tenant_id})
            ec2_api.create_credential(None, cred_dict)

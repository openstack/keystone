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

# This file handles all flask-restful resources for /v3/domains

import flask
import flask_restful
import functools
import http.client

from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.resource import schema
from keystone.server import flask as ks_flask

CONF = keystone.conf.CONF
ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs


def _build_domain_enforcement_target():
    target = {}
    try:
        target['domain'] = PROVIDERS.resource_api.get_domain(
            flask.request.view_args.get('domain_id')
        )
    except exception.NotFound:  # nosec
        # Defer existence in the event the domain doesn't exist, we'll
        # check this later anyway.
        pass

    return target


def _build_enforcement_target(allow_non_existing=False):
    target = {}
    if flask.request.view_args:
        domain_id = flask.request.view_args.get('domain_id', None)
        if domain_id:
            target['domain'] = PROVIDERS.resource_api.get_domain(domain_id)

        role_id = flask.request.view_args.get('role_id', None)
        if role_id:
            target['role'] = PROVIDERS.role_api.get_role(role_id)

        if flask.request.view_args.get('user_id'):
            try:
                target['user'] = PROVIDERS.identity_api.get_user(
                    flask.request.view_args['user_id'])
            except exception.UserNotFound:
                if not allow_non_existing:
                    raise
        else:
            try:
                target['group'] = PROVIDERS.identity_api.get_group(
                    flask.request.view_args.get('group_id'))
            except exception.GroupNotFound:
                if not allow_non_existing:
                    raise
    return target


class DomainResource(ks_flask.ResourceBase):
    collection_key = 'domains'
    member_key = 'domain'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='resource_api', method='get_domain')

    def get(self, domain_id=None):
        """Get domain or list domains.

        GET/HEAD /v3/domains
        GET/HEAD /v3/domains/{domain_id}
        """
        if domain_id is not None:
            return self._get_domain(domain_id)
        return self._list_domains()

    def _get_domain(self, domain_id):
        ENFORCER.enforce_call(
            action='identity:get_domain',
            build_target=_build_domain_enforcement_target
        )
        domain = PROVIDERS.resource_api.get_domain(domain_id)
        return self.wrap_member(domain)

    def _list_domains(self):
        filters = ['name', 'enabled']
        ENFORCER.enforce_call(action='identity:list_domains',
                              filters=filters)
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.resource_api.list_domains(hints=hints)
        return self.wrap_collection(refs, hints=hints)

    def post(self):
        """Create domain.

        POST /v3/domains
        """
        ENFORCER.enforce_call(action='identity:create_domain')
        domain = self.request_body_json.get('domain', {})
        validation.lazy_validate(schema.domain_create, domain)

        domain_id = domain.get('explicit_domain_id')
        if domain_id is None:
            domain = self._assign_unique_id(domain)
        else:
            # Domain ID validation provided by PyCADF
            try:
                self._validate_id_format(domain_id)
            except ValueError:
                raise exception.DomainIdInvalid
            domain['id'] = domain_id
        domain = self._normalize_dict(domain)
        ref = PROVIDERS.resource_api.create_domain(
            domain['id'], domain, initiator=self.audit_initiator)
        return self.wrap_member(ref), http.client.CREATED

    def patch(self, domain_id):
        """Update domain.

        PATCH /v3/domains/{domain_id}
        """
        ENFORCER.enforce_call(action='identity:update_domain')
        domain = self.request_body_json.get('domain', {})
        validation.lazy_validate(schema.domain_update, domain)
        PROVIDERS.resource_api.get_domain(domain_id)
        ref = PROVIDERS.resource_api.update_domain(
            domain_id, domain, initiator=self.audit_initiator)
        return self.wrap_member(ref)

    def delete(self, domain_id):
        """Delete domain.

        DELETE /v3/domains/{domain_id}
        """
        ENFORCER.enforce_call(action='identity:delete_domain')
        PROVIDERS.resource_api.delete_domain(
            domain_id, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class DomainConfigBase(ks_flask.ResourceBase):
    member_key = 'config'

    def get(self, domain_id=None, group=None, option=None):
        """Check if config option exists.

        GET/HEAD /v3/domains/{domain_id}/config
        GET/HEAD /v3/domains/{domain_id}/config/{group}
        GET/HEAD /v3/domains/{domain_id}/config/{group}/{option}
        """
        err = None
        config = {}
        try:
            PROVIDERS.resource_api.get_domain(domain_id)
        except Exception as e:   # nosec
            # We don't raise out here, we raise out after enforcement, this
            # ensures we do not leak domain existance.
            err = e
        finally:
            if group and group == 'security_compliance':
                config = self._get_security_compliance_config(
                    domain_id, group, option)
            else:
                config = self._get_config(domain_id, group, option)
        if err is not None:
            raise err
        return {self.member_key: config}

    def _get_config(self, domain_id, group, option):
        ENFORCER.enforce_call(action='identity:get_domain_config')
        return PROVIDERS.domain_config_api.get_config(
            domain_id, group=group, option=option)

    def _get_security_compliance_config(self, domain_id, group, option):
        ENFORCER.enforce_call(
            action='identity:get_security_compliance_domain_config')
        return PROVIDERS.domain_config_api.get_security_compliance_config(
            domain_id, group, option=option)

    def patch(self, domain_id=None, group=None, option=None):
        """Update domain config option.

        PATCH /v3/domains/{domain_id}/config
        PATCH /v3/domains/{domain_id}/config/{group}
        PATCH /v3/domains/{domain_id}/config/{group}/{option}
        """
        ENFORCER.enforce_call(action='identity:update_domain_config')
        PROVIDERS.resource_api.get_domain(domain_id)
        config = self.request_body_json.get('config', {})
        ref = PROVIDERS.domain_config_api.update_config(
            domain_id, config, group, option=option)
        return {self.member_key: ref}

    def delete(self, domain_id=None, group=None, option=None):
        """Delete domain config.

        DELETE /v3/domains/{domain_id}/config
        DELETE /v3/domains/{domain_id}/config/{group}
        DELETE /v3/domains/{domain_id}/config/{group}/{option}
        """
        ENFORCER.enforce_call(action='identity:delete_domain_config')
        PROVIDERS.resource_api.get_domain(domain_id)
        PROVIDERS.domain_config_api.delete_config(
            domain_id, group, option=option)
        return None, http.client.NO_CONTENT


class DomainConfigResource(DomainConfigBase):
    """Provides config routing functionality.

    This class leans on DomainConfigBase to provide the following APIs:

    GET/HEAD /v3/domains/{domain_id}/config
    PATCH /v3/domains/{domain_id}/config
    DELETE /v3/domains/{domain_id}/config
    """

    def put(self, domain_id):
        """Create domain config.

        PUT /v3/domains/{domain_id}/config
        """
        ENFORCER.enforce_call(action='identity:create_domain_config')
        PROVIDERS.resource_api.get_domain(domain_id)
        config = self.request_body_json.get('config', {})
        original_config = (
            PROVIDERS.domain_config_api.get_config_with_sensitive_info(
                domain_id
            )
        )
        ref = PROVIDERS.domain_config_api.create_config(domain_id, config)
        if original_config:
            return {self.member_key: ref}
        else:
            return {self.member_key: ref}, http.client.CREATED


class DomainConfigGroupResource(DomainConfigBase):
    """Provides config group routing functionality.

    This class leans on DomainConfigBase to provide the following APIs:

    GET/HEAD /v3/domains/{domain_id}/config/{group}
    PATCH /v3/domains/{domain_id}/config/{group}
    DELETE /v3/domains/{domain_id}/config/{group}
    """


class DomainConfigOptionResource(DomainConfigBase):
    """Provides config option routing functionality.

    This class leans on DomainConfigBase to provide the following APIs:

    GET/HEAD /v3/domains/{domain_id}/config/{group}/{option}
    PATCH /v3/domains/{domain_id}/config/{group}/{option}
    DELETE /v3/domains/{domain_id}/config/{group}/{option}
    """


class DefaultConfigResource(flask_restful.Resource):
    def get(self):
        """Get default domain config.

        GET/HEAD /v3/domains/config/default
        """
        ENFORCER.enforce_call(action='identity:get_domain_config_default')
        ref = PROVIDERS.domain_config_api.get_config_default()
        return {'config': ref}


class DefaultConfigGroupResource(flask_restful.Resource):
    def get(self, group=None):
        """Get default domain group config.

        GET/HEAD /v3/domains/config/{group}/default
        """
        ENFORCER.enforce_call(action='identity:get_domain_config_default')
        ref = PROVIDERS.domain_config_api.get_config_default(group=group)
        return {'config': ref}


class DefaultConfigOptionResource(flask_restful.Resource):
    def get(self, group=None, option=None):
        """Get default domain group option config.

        GET/HEAD /v3/domains/config/{group}/{option}/default
        """
        ENFORCER.enforce_call(action='identity:get_domain_config_default')
        ref = PROVIDERS.domain_config_api.get_config_default(
            group=group, option=option)
        return {'config': ref}


class DomainUserListResource(flask_restful.Resource):
    def get(self, domain_id=None, user_id=None):
        """Get user grant.

        GET/HEAD /v3/domains/{domain_id}/users/{user_id}/roles
        """
        ENFORCER.enforce_call(
            action='identity:list_grants',
            build_target=_build_enforcement_target)
        refs = PROVIDERS.assignment_api.list_grants(
            domain_id=domain_id, user_id=user_id,
            inherited_to_projects=False)
        return ks_flask.ResourceBase.wrap_collection(
            refs, collection_name='roles')


class DomainUserResource(ks_flask.ResourceBase):
    member_key = 'grant'
    collection_key = 'grants'

    def get(self, domain_id=None, user_id=None, role_id=None):
        """Check if a user has a specific role on the domain.

        GET/HEAD /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:check_grant',
            build_target=_build_enforcement_target)
        PROVIDERS.assignment_api.get_grant(
            role_id, domain_id=domain_id, user_id=user_id,
            inherited_to_projects=False)
        return None, http.client.NO_CONTENT

    def put(self, domain_id=None, user_id=None, role_id=None):
        """Create a role to a user on a domain.

        PUT /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:create_grant',
            build_target=_build_enforcement_target)
        PROVIDERS.assignment_api.create_grant(
            role_id, domain_id=domain_id, user_id=user_id,
            inherited_to_projects=False, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT

    def delete(self, domain_id=None, user_id=None, role_id=None):
        """Revoke a role from user on a domain.

        DELETE /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:revoke_grant',
            build_target=functools.partial(_build_enforcement_target,
                                           allow_non_existing=True))
        PROVIDERS.assignment_api.delete_grant(
            role_id, domain_id=domain_id, user_id=user_id,
            inherited_to_projects=False, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class DomainGroupListResource(flask_restful.Resource):
    def get(self, domain_id=None, group_id=None):
        """List all domain grats for a specific group.

        GET/HEAD /v3/domains/{domain_id}/groups/{group_id}/roles
        """
        ENFORCER.enforce_call(
            action='identity:list_grants',
            build_target=_build_enforcement_target)
        refs = PROVIDERS.assignment_api.list_grants(
            domain_id=domain_id, group_id=group_id,
            inherited_to_projects=False)
        return ks_flask.ResourceBase.wrap_collection(
            refs, collection_name='roles')


class DomainGroupResource(ks_flask.ResourceBase):
    member_key = 'grant'
    collection_key = 'grants'

    def get(self, domain_id=None, group_id=None, role_id=None):
        """Check if a group has a specific role on a domain.

        GET/HEAD /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:check_grant',
            build_target=_build_enforcement_target)
        PROVIDERS.assignment_api.get_grant(
            role_id, domain_id=domain_id, group_id=group_id,
            inherited_to_projects=False)
        return None, http.client.NO_CONTENT

    def put(self, domain_id=None, group_id=None, role_id=None):
        """Grant a role to a group on a domain.

        PUT /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:create_grant',
            build_target=_build_enforcement_target)
        PROVIDERS.assignment_api.create_grant(
            role_id, domain_id=domain_id, group_id=group_id,
            inherited_to_projects=False, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT

    def delete(self, domain_id=None, group_id=None, role_id=None):
        """Revoke a role from a group on a domain.

        DELETE /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(
            action='identity:revoke_grant',
            build_target=functools.partial(_build_enforcement_target,
                                           allow_non_existing=True))
        PROVIDERS.assignment_api.delete_grant(
            role_id, domain_id=domain_id, group_id=group_id,
            inherited_to_projects=False, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class DomainAPI(ks_flask.APIBase):
    CONFIG_GROUP = json_home.build_v3_parameter_relation('config_group')
    CONFIG_OPTION = json_home.build_v3_parameter_relation('config_option')
    _name = 'domains'
    _import_name = __name__
    resources = [DomainResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=DomainConfigResource,
            url=('/domains/<string:domain_id>/config'),
            resource_kwargs={},
            rel='domain_config',
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID}),
        ks_flask.construct_resource_map(
            resource=DomainConfigGroupResource,
            url='/domains/<string:domain_id>/config/<string:group>',
            resource_kwargs={},
            rel='domain_config_group',
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group': CONFIG_GROUP}),
        ks_flask.construct_resource_map(
            resource=DomainConfigOptionResource,
            url=('/domains/<string:domain_id>/config/<string:group>'
                 '/<string:option>'),
            resource_kwargs={},
            rel='domain_config_option',
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group': CONFIG_GROUP,
                'option': CONFIG_OPTION}),
        ks_flask.construct_resource_map(
            resource=DefaultConfigResource,
            url=('/domains/config/default'),
            resource_kwargs={},
            rel='domain_config_default',
            path_vars={}),
        ks_flask.construct_resource_map(
            resource=DefaultConfigGroupResource,
            url='/domains/config/<string:group>/default',
            resource_kwargs={},
            rel='domain_config_default_group',
            path_vars={
                'group': CONFIG_GROUP}),
        ks_flask.construct_resource_map(
            resource=DefaultConfigOptionResource,
            url=('/domains/config/<string:group>'
                 '/<string:option>/default'),
            resource_kwargs={},
            rel='domain_config_default_option',
            path_vars={
                'group': CONFIG_GROUP,
                'option': CONFIG_OPTION}),
        ks_flask.construct_resource_map(
            resource=DomainUserListResource,
            url=('/domains/<string:domain_id>/users'
                 '/<string:user_id>/roles'),
            resource_kwargs={},
            rel='domain_user_roles',
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'user_id': json_home.Parameters.USER_ID,
            }),
        ks_flask.construct_resource_map(
            resource=DomainUserResource,
            url=('/domains/<string:domain_id>/users'
                 '/<string:user_id>/roles/<string:role_id>'),
            resource_kwargs={},
            rel='domain_user_role',
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'user_id': json_home.Parameters.USER_ID,
                'role_id': json_home.Parameters.ROLE_ID
            }),
        ks_flask.construct_resource_map(
            resource=DomainGroupListResource,
            url=('/domains/<string:domain_id>/groups'
                 '/<string:group_id>/roles'),
            resource_kwargs={},
            rel='domain_group_roles',
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group_id': json_home.Parameters.GROUP_ID,
            }),
        ks_flask.construct_resource_map(
            resource=DomainGroupResource,
            url=('/domains/<string:domain_id>/groups'
                 '/<string:group_id>/roles/<string:role_id>'),
            resource_kwargs={},
            rel='domain_group_role',
            path_vars={
                'domain_id': json_home.Parameters.DOMAIN_ID,
                'group_id': json_home.Parameters.GROUP_ID,
                'role_id': json_home.Parameters.ROLE_ID
            })
    ]


APIs = (DomainAPI,)

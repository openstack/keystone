===============================
Mapping of policy target to API
===============================

The following table shows the target in the policy.json file for each API.

=========================================================  ===
Target                                                     API
=========================================================  ===
identity:get_region                                        GET /v3/regions/{region_id}
identity:list_regions                                      GET /v3/regions
identity:create_region                                     POST /v3/regions
identity:update_region                                     PATCH /v3/regions/{region_id}
identity:delete_region                                     DELETE /v3/regions/{region_id}

identity:get_service                                       GET /v3/services/{service_id}
identity:list_services                                     GET /v3/services
identity:create_service                                    POST /v3/services
identity:update_service                                    PATCH /v3/services/{service__id}
identity:delete_service                                    DELETE /v3/services/{service__id}

identity:get_endpoint                                      GET /v3/endpoints/{endpoint_id}
identity:list_endpoints                                    GET /v3/endpoints
identity:create_endpoint                                   POST /v3/endpoints
identity:update_endpoint                                   PATCH /v3/endpoints/{endpoint_id}
identity:delete_endpoint                                   DELETE /v3/endpoints/{endpoint_id}

identity:get_domain                                        GET /v3/domains/{domain_id}
identity:list_domains                                      GET /v3/domains
identity:create_domain                                     POST /v3/domains
identity:update_domain                                     PATCH /v3/domains/{domain_id}
identity:delete_domain                                     DELETE /v3/domains/{domain_id}

identity:get_project                                       GET /v3/projects/{project_id}
identity:list_projects                                     GET /v3/projects
identity:list_user_projects                                GET /v3/users/{user_id}/projects
identity:create_project                                    POST /v3/projects
identity:update_project                                    PATCH /v3/projects/{project_id}
identity:delete_project                                    DELETE /v3/projects/{project_id}

identity:get_user                                          GET /v3/users/{user_id}
identity:list_users                                        GET /v3/users
identity:create_user                                       POST /v3/users
identity:update_user                                       PATCH /v3/users/{user_id}
identity:delete_user                                       DELETE /v3/users/{user_id}
identity:change_password                                   POST /v3/users/{user_id}/password

identity:get_group                                         GET /v3/groups/{group_id}
identity:list_groups                                       GET /v3/groups
identity:list_groups_for_user                              GET /v3/users/{user_id}/groups
identity:create_group                                      POST /v3/groups
identity:update_group                                      PATCH /v3/groups/{group_id}
identity:delete_group                                      DELETE /v3/groups/{group_id}
identity:list_users_in_group                               GET /v3/groups/{group_id}/users
identity:remove_user_from_group                            DELETE /v3/groups/{group_id}/users/{user_id}
identity:check_user_in_group                               GET /v3/groups/{group_id}/users/{user_id}
identity:add_user_to_group                                 PUT /v3/groups/{group_id}/users/{user_id}

identity:get_credential                                    GET /v3/credentials/{credential_id}
identity:list_credentials                                  GET /v3/credentials
identity:create_credential                                 POST /v3/credentials
identity:update_credential                                 PATCH /v3/credentials/{credential_id}
identity:delete_credential                                 DELETE /v3/credentials/{credential_id}

identity:ec2_get_credential                                GET /v3/users/{user_id}/credentials/OS-EC2/{credential_id}
identity:ec2_list_credentials                              GET /v3/users/{user_id}/credentials/OS-EC2
identity:ec2_create_credential                             POST /v3/users/{user_id}/credentials/OS-EC2
identity:ec2_delete_credential                             DELETE /v3/users/{user_id}/credentials/OS-EC2/{credential_id}

identity:get_role                                          GET /v3/roles/{role_id}
identity:list_roles                                        GET /v3/roles
identity:create_role                                       POST /v3/roles
identity:update_role                                       PATCH /v3/roles/{role_id}
identity:delete_role                                       DELETE /v3/roles/{role_id}

identity:check_grant                                       GET `grant_resources`_
identity:list_grants                                       GET `grant_collections`_
identity:create_grant                                      PUT `grant_resources`_
identity:revoke_grant                                      DELETE `grant_resources`_

identity:list_role_assignments                             GET /v3/role_assignments

identity:get_policy                                        GET /v3/policy/{policy_id}
identity:list_policies                                     GET /v3/policy
identity:create_policy                                     POST /v3/policy
identity:update_policy                                     PATCH /v3/policy/{policy_id}
identity:delete_policy                                     DELETE /v3/policy/{policy_id}

identity:check_token                                       HEAD /v3/auth/tokens
identity:validate_token                                    - GET /v2.0/tokens/{token_id}
                                                           - GET /v3/auth/tokens
identity:validate_token_head                               HEAD /v2.0/tokens/{token_id}
identity:revocation_list                                   - GET /v2.0/tokens/revoked
                                                           - GET /v3/auth/tokens/OS-PKI/revoked
identity:revoke_token                                      DELETE /v3/auth/tokens
identity:create_trust                                      POST /v3/OS-TRUST/trusts
identity:list_trusts                                       GET /v3/OS-TRUST/trusts
identity:list_roles_for_trust                              GET /v3/OS-TRUST/trusts/{trust_id}/roles
identity:get_role_for_trust                                GET /v3/OS-TRUST/trusts/{trust_id}/roles/{role_id}
identity:delete_trust                                      DELETE /v3/OS-TRUST/trusts/{trust_id}

identity:create_consumer                                   POST /v3/OS-OAUTH1/consumers
identity:get_consumer                                      GET /v3/OS-OAUTH1/consumers/{consumer_id}
identity:list_consumers                                    GET /v3/OS-OAUTH1/consumers
identity:delete_consumer                                   DELETE /v3/OS-OAUTH1/consumers/{consumer_id}
identity:update_consumer                                   PATCH /v3/OS-OAUTH1/consumers/{consumer_id}

identity:authorize_request_token                           PUT /v3/OS-OAUTH1/authorize/{request_token_id}
identity:list_access_token_roles                           GET /v3/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}/roles
identity:get_access_token_role                             GET /v3/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}/roles/{role_id}
identity:list_access_tokens                                GET /v3/users/{user_id}/OS-OAUTH1/access_tokens
identity:get_access_token                                  GET /v3/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}
identity:delete_access_token                               DELETE /v3/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}

identity:list_projects_for_endpoint                        GET /v3/OS-EP-FILTER/endpoints/{endpoint_id}/projects
identity:add_endpoint_to_project                           PUT /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}
identity:check_endpoint_in_project                         GET /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}
identity:list_endpoints_for_project                        GET /v3/OS-EP-FILTER/projects/{project_id}/endpoints
identity:remove_endpoint_from_project                      DELETE /v3/OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

identity:create_endpoint_group                             POST /v3/OS-EP-FILTER/endpoint_groups
identity:list_endpoint_groups                              GET /v3/OS-EP-FILTER/endpoint_groups
identity:get_endpoint_group                                GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}
identity:update_endpoint_group                             PATCH /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}
identity:delete_endpoint_group                             DELETE /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}
identity:list_projects_associated_with_endpoint_group      GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects
identity:list_endpoints_associated_with_endpoint_group     GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/endpoints
identity:get_endpoint_group_in_project                     GET /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}
identity:list_endpoint_groups_for_project                  GET /v3/OS-EP-FILTER/projects/{project_id}/endpoint_groups
identity:add_endpoint_group_to_project                     PUT /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}
identity:remove_endpoint_group_from_project                DELETE /v3/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}

identity:create_identity_provider                          PUT /v3/OS-FEDERATION/identity_providers/{idp_id}
identity:list_identity_providers                           GET /v3/OS-FEDERATION/identity_providers
identity:get_identity_providers                            GET /v3/OS-FEDERATION/identity_providers/{idp_id}
identity:update_identity_provider                          PATCH /v3/OS-FEDERATION/identity_providers/{idp_id}
identity:delete_identity_provider                          DELETE /v3/OS-FEDERATION/identity_providers/{idp_id}

identity:create_protocol                                   PUT /v3/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}
identity:update_protocol                                   PATCH /v3/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}
identity:get_protocol                                      GET /v3/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}
identity:list_protocols                                    GET /v3/OS-FEDERATION/identity_providers/{idp_id}/protocols
identity:delete_protocol                                   DELETE /v3/OS-FEDERATION/identity_providers/{idp_id}/protocols/{protocol_id}

identity:create_mapping                                    PUT /v3/OS-FEDERATION/mappings/{mapping_id}
identity:get_mapping                                       GET /v3/OS-FEDERATION/mappings/{mapping_id}
identity:list_mappings                                     GET /v3/OS-FEDERATION/mappings
identity:delete_mapping                                    DELETE /v3/OS-FEDERATION/mappings/{mapping_id}
identity:update_mapping                                    PATCH /v3/OS-FEDERATION/mappings/{mapping_id}

identity:create_service_provider                           PUT /v3/OS-FEDERATION/service_providers/{sp_id}
identity:list_service_providers                            GET /v3/OS-FEDERATION/service_providers
identity:get_service_provider                              GET /v3/OS-FEDERATION/service_providers/{sp_id}
identity:update_service_provider                           PATCH /v3/OS-FEDERATION/service_providers/{sp_id}
identity:delete_service_provider                           DELETE /v3/OS-FEDERATION/service_providers/{sp_id}

identity:get_auth_catalog                                  GET /v3/auth/catalog
identity:get_auth_projects                                 GET /v3/auth/projects
identity:get_auth_domains                                  GET /v3/auth/domains

identity:list_projects_for_groups                          GET /v3/OS-FEDERATION/projects
identity:list_domains_for_groups                           GET /v3/OS-FEDERATION/domains

identity:list_revoke_events                                GET /v3/OS-REVOKE/events

identity:create_policy_association_for_endpoint            PUT /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/endpoints/{endpoint_id}
identity:check_policy_association_for_endpoint             GET /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/endpoints/{endpoint_id}
identity:delete_policy_association_for_endpoint            DELETE /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/endpoints/{endpoint_id}
identity:create_policy_association_for_service             PUT /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/services/{service_id}
identity:check_policy_association_for_service              GET /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/services/{service_id}
identity:delete_policy_association_for_service             DELETE /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/services/{service_id}
identity:create_policy_association_for_region_and_service  PUT /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/services/{service_id}/regions/{region_id}
identity:check_policy_association_for_region_and_service   GET /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/services/{service_id}/regions/{region_id}
identity:delete_policy_association_for_region_and_service  DELETE /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/services/{service_id}/regions/{region_id}
identity:get_policy_for_endpoint                           GET /v3/endpoints/{endpoint_id}/OS-ENDPOINT-POLICY/policy
identity:list_endpoints_for_policy                         GET /v3/policies/{policy_id}/OS-ENDPOINT-POLICY/endpoints

identity:create_domain_config                              PUT /v3/domains/{domain_id}/config
identity:get_domain_config                                 - GET /v3/domains/{domain_id}/config
                                                           - GET /v3/domains/{domain_id}/config/{group}
                                                           - GET /v3/domains/{domain_id}/config/{group}/{option}
identity:update_domain_config                              - PATCH /v3/domains/{domain_id}/config
                                                           - PATCH /v3/domains/{domain_id}/config/{group}
                                                           - PATCH /v3/domains/{domain_id}/config/{group}/{option}
identity:delete_domain_config                              - DELETE /v3/domains/{domain_id}/config
                                                           - DELETE /v3/domains/{domain_id}/config/{group}
                                                           - DELETE /v3/domains/{domain_id}/config/{group}/{option}

=========================================================  ===

.. _grant_resources:

*grant_resources* are:

- /v3/projects/{project_id}/users/{user_id}/roles/{role_id}
- /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}
- /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}
- /v3/domains/{domain_id}/groups/{group_id}/roles/{role_id}
- /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/{role_id}/inherited_to_projects
- /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects
- /v3/OS-INHERIT/projects/{project_id}/users/{user_id}/roles/{role_id}/inherited_to_projects
- /v3/OS-INHERIT/projects/{project_id}/groups/{group_id}/roles/{role_id}/inherited_to_projects

.. _grant_collections:

*grant_collections* are:

- /v3/projects/{project_id}/users/{user_id}/roles
- /v3/projects/{project_id}/groups/{group_id}/roles
- /v3/domains/{domain_id}/users/{user_id}/roles
- /v3/domains/{domain_id}/groups/{group_id}/role
- /v3/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/inherited_to_projects
- /v3/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/inherited_to_projects

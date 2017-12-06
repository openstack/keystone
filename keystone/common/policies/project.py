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

from oslo_policy import policy

from keystone.common.policies import base

project_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_project',
        check_str=base.RULE_ADMIN_OR_TARGET_PROJECT,
        # FIXME(lbragstad): The default check_str here should change to be just
        # a role. The OR_TARGET_PROJECT bit of this check_str should actually
        # be moved into keystone. A system administrator should be able to get
        # any project in the deployement. A domain administrator should be
        # able to get any project within their domain. A project administrator
        # should be able to get their project or children of their project
        # (maybe). This is going to require policy checks in code that make
        # keystone smarter about handling these cases. Until we have those in
        # place, we should keep scope_type commented out. Otherwise, we risk
        # exposing information to people who don't have the correct
        # authorization.
        # scope_types=['system', 'project'],
        description='Show project details.',
        operations=[{'path': '/v3/projects/{project_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_projects',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): This is set to 'system' until keystone is smart
        # enough to tailor list_project responses for project-scoped tokens
        # without exposing information that doesn't pertain to the scope of the
        # token used to make the request. System administrators should be able
        # to list all projects in the deployment. Domain administrators should
        # be able to list all projects within their domain. Project
        # administrators should be able to list projects they administer or
        # possibly their children.  Until keystone is smart enought to handle
        # those cases, keep scope_types set to 'system'.
        scope_types=['system'],
        description='List projects.',
        operations=[{'path': '/v3/projects',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_user_projects',
        check_str=base.RULE_ADMIN_OR_OWNER,
        # FIXME(lbragstad): This is going to require keystone to be smarter
        # about how it authorizes this API. A system administrator should be
        # able to list all projects for a user. A domain administrator should
        # be able to list all projects to users within their domain. A user
        # should be able to list projects for themselves, including the
        # hierarchy in place. Until we have those cases covered in code and
        # tested, we should keep scope_types commented out.
        # scope_types=['system', 'project'],
        description='List projects for user.',
        operations=[{'path': '/v3/users/{user_id}/projects',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): System administrators should be able to create
        # projects anywhere in the deployment. Domain administrators should
        # only be able to create projects within their domain. Project
        # administrators should only be able to create children projects of the
        # project they administer. Until keystone is smart enough to handle
        # those checks in code, keep this as a system-level operation for
        # backwards compatibility.
        scope_types=['system'],
        description='Create project.',
        operations=[{'path': '/v3/projects',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): See the above comment for create_project as to why
        # this is limited to only system-scope.
        scope_types=['system'],
        description='Update project.',
        operations=[{'path': '/v3/projects/{project_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): See the above comment for create_project as to why
        # this is limited to only system-scope.
        scope_types=['system'],
        description='Delete project.',
        operations=[{'path': '/v3/projects/{project_id}',
                     'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_project_tags',
        check_str=base.RULE_ADMIN_OR_TARGET_PROJECT,
        # FIXME(lbragstad): We need to make sure we check the project in the
        # token scope when authorizing APIs for project tags. System
        # administrators should be able to tag any project with anything.
        # Domain administrators should only be able to tag projects within
        # their domain. Project administrators should only be able to tag their
        # project. Until we have support for these cases in code and tested, we
        # should keep scope_types commented out.
        # scope_types=['system', 'project'],
        description='List tags for a project.',
        operations=[{'path': '/v3/projects/{project_id}/tags',
                     'method': 'GET'},
                    {'path': '/v3/projects/{project_id}/tags',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_project_tag',
        check_str=base.RULE_ADMIN_OR_TARGET_PROJECT,
        # FIXME(lbragstad): See the above comments as to why this is commented
        # out.
        # scope_types=['system', 'project'],
        description='Check if project contains a tag.',
        operations=[{'path': '/v3/projects/{project_id}/tags/{value}',
                     'method': 'GET'},
                    {'path': '/v3/projects/{project_id}/tags/{value}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_project_tags',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): See the above comment for create_project as to why
        # this is limited to only system-scope.
        scope_types=['system'],
        description='Replace all tags on a project with the new set of tags.',
        operations=[{'path': '/v3/projects/{project_id}/tags',
                     'method': 'PUT'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_project_tag',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): See the above comment for create_project as to why
        # this is limited to only system-scope.
        scope_types=['system'],
        description='Add a single tag to a project.',
        operations=[{'path': '/v3/projects/{project_id}/tags/{value}',
                     'method': 'PUT'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_project_tags',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): See the above comment for create_project as to why
        # this is limited to only system-scope.
        scope_types=['system'],
        description='Remove all tags from a project.',
        operations=[{'path': '/v3/projects/{project_id}/tags',
                     'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_project_tag',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): See the above comment for create_project as to why
        # this is limited to only system-scope.
        scope_types=['system'],
        description='Delete a specified tag from project.',
        operations=[{'path': '/v3/projects/{project_id}/tags/{value}',
                     'method': 'DELETE'}])
]


def list_rules():
    return project_policies

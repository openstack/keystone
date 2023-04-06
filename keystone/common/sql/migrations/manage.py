#!/usr/bin/env python3
# Copyright 2012 OpenStack Foundation
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

import copy
import sys

from alembic import command as alembic_command
from alembic import script as alembic_script
from alembic import util as alembic_util
from oslo_config import cfg
from oslo_log import log
import pbr.version

from keystone.common import sql
from keystone.common.sql import upgrades
import keystone.conf
from keystone.i18n import _

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


def import_sql_modules():
    # We need to import all of these so the tables are registered. It would be
    # easier if these were all in a central location :(
    import keystone.application_credential.backends.sql  # noqa: F401
    import keystone.assignment.backends.sql  # noqa: F401
    import keystone.assignment.role_backends.sql_model  # noqa: F401
    import keystone.catalog.backends.sql  # noqa: F401
    import keystone.credential.backends.sql  # noqa: F401
    import keystone.endpoint_policy.backends.sql  # noqa: F401
    import keystone.federation.backends.sql  # noqa: F401
    import keystone.identity.backends.sql_model  # noqa: F401
    import keystone.identity.mapping_backends.sql  # noqa: F401
    import keystone.limit.backends.sql  # noqa: F401
    import keystone.oauth1.backends.sql  # noqa: F401
    import keystone.policy.backends.sql  # noqa: F401
    import keystone.resource.backends.sql_model  # noqa: F401
    import keystone.resource.config_backends.sql  # noqa: F401
    import keystone.revoke.backends.sql  # noqa: F401
    import keystone.trust.backends.sql  # noqa: F401


def do_alembic_command(config, cmd, revision=None, **kwargs):
    args = []
    if revision:
        args.append(revision)

    try:
        getattr(alembic_command, cmd)(config, *args, **kwargs)
    except alembic_util.CommandError as e:
        alembic_util.err(str(e))


def do_generic_show(config, cmd):
    kwargs = {'verbose': CONF.command.verbose}
    do_alembic_command(config, cmd, **kwargs)


def do_validate(config, cmd):
    do_alembic_command(config, 'branches')
    # TODO(stephenfin): Implement these
    # validate_revisions(config)
    # TODO(stephenfin): Implement these
    # validate_head_files(config)


def _find_milestone_revisions(config, milestone, branch=None):
    """Return the revision(s) for a given milestone."""
    script = alembic_script.ScriptDirectory.from_config(config)
    return [
        (m.revision, label)
        for m in _get_revisions(script)
        for label in (m.branch_labels or [None])
        if milestone in getattr(m.module, 'keystone_milestone', [])
        and (branch is None or branch in m.branch_labels)
    ]


def _get_revisions(script):
    return list(script.walk_revisions(base='base', head='heads'))


def do_upgrade(config, cmd):
    branch = None

    if (CONF.command.revision or CONF.command.delta) and (
        CONF.command.expand or CONF.command.contract
    ):
        msg = _('Phase upgrade options do not accept revision specification')
        raise SystemExit(msg)

    if CONF.command.expand:
        branch = upgrades.EXPAND_BRANCH
        revision = f'{upgrades.EXPAND_BRANCH}@head'
    elif CONF.command.contract:
        branch = upgrades.CONTRACT_BRANCH
        revision = f'{upgrades.CONTRACT_BRANCH}@head'
    elif not CONF.command.revision and not CONF.command.delta:
        msg = _('You must provide a revision or relative delta')
        raise SystemExit(msg)
    else:
        revision = CONF.command.revision or ''
        if '-' in revision:
            msg = _('Negative relative revision (downgrade) not supported')
            raise SystemExit(msg)

        delta = CONF.command.delta
        if delta:
            if '+' in revision:
                msg = _('Use either --delta or relative revision, not both')
                raise SystemExit(msg)
            if delta < 0:
                msg = _('Negative delta (downgrade) not supported')
                raise SystemExit(msg)
            revision = '%s+%d' % (revision, delta)

        # leave branchless 'head' revision request backward compatible by
        # applying all heads in all available branches.
        if revision == 'head':
            revision = 'heads'

    if revision in upgrades.MILESTONES:
        expand_revisions = _find_milestone_revisions(
            config,
            revision,
            upgrades.EXPAND_BRANCH,
        )
        contract_revisions = _find_milestone_revisions(
            config,
            revision,
            upgrades.CONTRACT_BRANCH,
        )
        # Expand revisions must be run before contract revisions
        revisions = expand_revisions + contract_revisions
    else:
        revisions = [(revision, branch)]

    for revision, branch in revisions:
        # if not CONF.command.sql:
        #     run_sanity_checks(config, revision)
        do_alembic_command(
            config,
            cmd,
            revision=revision,
            sql=CONF.command.sql,
        )


def do_revision(config, cmd):
    kwargs = {
        'message': CONF.command.message,
        'autogenerate': CONF.command.autogenerate,
        'sql': CONF.command.sql,
    }
    branches = []
    if CONF.command.expand:
        kwargs['head'] = 'expand@head'
        branches.append(upgrades.EXPAND_BRANCH)
    elif CONF.command.contract:
        kwargs['head'] = 'contract@head'
        branches.append(upgrades.CONTRACT_BRANCH)
    else:
        branches = upgrades.MIGRATION_BRANCHES

    if not CONF.command.autogenerate:
        for branch in branches:
            args = copy.copy(kwargs)
            version_path = upgrades.get_version_branch_path(
                release=upgrades.CURRENT_RELEASE,
                branch=branch,
            )
            upgrades.check_bootstrap_new_branch(branch, version_path, args)
            do_alembic_command(config, cmd, **args)
    else:  # CONF.command.autogenerate
        # autogeneration code will take care of enforcing proper directories
        do_alembic_command(config, cmd, **kwargs)

    # TODO(stephenfin): Implement these
    # update_head_files(config)


def add_branch_options(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--expand', action='store_true')
    group.add_argument('--contract', action='store_true')
    return group


def add_alembic_subparser(sub, cmd):
    return sub.add_parser(cmd, help=getattr(alembic_command, cmd).__doc__)


def add_command_parsers(subparsers):
    for name in ['current', 'history', 'branches', 'heads']:
        parser = add_alembic_subparser(subparsers, name)
        parser.set_defaults(func=do_generic_show)
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Display more verbose output for the specified command',
        )

    parser = add_alembic_subparser(subparsers, 'upgrade')
    parser.add_argument('--delta', type=int)
    parser.add_argument('--sql', action='store_true')
    parser.add_argument('revision', nargs='?')
    add_branch_options(parser)
    parser.set_defaults(func=do_upgrade)

    parser = subparsers.add_parser(
        'validate',
        help=alembic_command.branches.__doc__ + ' and validate head file',
    )
    parser.set_defaults(func=do_validate)

    parser = add_alembic_subparser(subparsers, 'revision')
    parser.add_argument('-m', '--message')
    parser.add_argument('--sql', action='store_true')
    group = add_branch_options(parser)
    group.add_argument('--autogenerate', action='store_true')
    parser.set_defaults(func=do_revision)


command_opt = cfg.SubCommandOpt(
    'command',
    title='Command',
    help=_('Available commands'),
    handler=add_command_parsers,
)


def main(argv):
    CONF.register_cli_opt(command_opt)

    keystone.conf.configure()
    sql.initialize()
    keystone.conf.set_default_for_default_log_levels()

    user_supplied_config_file = False
    if argv:
        for argument in argv:
            if argument == '--config-file':
                user_supplied_config_file = True

    CONF(
        project='keystone',
        version=pbr.version.VersionInfo('keystone').version_string(),
    )

    if not CONF.default_config_files and not user_supplied_config_file:
        LOG.warning('Config file not found, using default configs.')

    import_sql_modules()

    config = upgrades.get_alembic_config()

    return bool(CONF.command.func(config, CONF.command.name))


if __name__ == '__main__':
    main(sys.argv)

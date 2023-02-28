# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import warnings

import fixtures
from sqlalchemy import exc as sqla_exc


class WarningsFixture(fixtures.Fixture):
    """Filters out warnings during test runs."""

    def setUp(self):
        super().setUp()

        self._original_warning_filters = warnings.filters[:]

        # NOTE(stephenfin): Make deprecation warnings only happen once.
        # Otherwise this gets kind of crazy given the way that upstream python
        # libs use this.
        warnings.simplefilter('once', DeprecationWarning)

        warnings.filterwarnings(
            'error',
            module='keystone',
            category=DeprecationWarning,
        )

        warnings.filterwarnings(
            'ignore',
            message=(
                'Policy enforcement is depending on the value of '
                '(token|group_ids). '
                'This key is deprecated. Please update your policy '
                'file to use the standard policy values.'
            ),
        )

        # NOTE(stephenfin): Ignore scope check UserWarnings from oslo.policy.
        warnings.filterwarnings(
            'ignore',
            message="Policy .* failed scope check",
            category=UserWarning,
        )

        # TODO(stephenfin): This will be fixed once we drop sqlalchemy-migrate
        warnings.filterwarnings(
            'ignore',
            category=DeprecationWarning,
            message=r"Using function/method 'db_version\(\)' is deprecated",
        )

        warnings.filterwarnings(
            'error',
            module='keystone',
            category=sqla_exc.SAWarning,
        )

        warnings.filterwarnings(
            'ignore',
            category=sqla_exc.SADeprecationWarning,
        )

        # Enable deprecation warnings for keystone itself to capture upcoming
        # SQLALchemy changes

        warnings.filterwarnings(
            'error',
            module='keystone',
            category=sqla_exc.SADeprecationWarning,
        )

        self.addCleanup(self._reset_warning_filters)

    def _reset_warning_filters(self):
        warnings.filters[:] = self._original_warning_filters

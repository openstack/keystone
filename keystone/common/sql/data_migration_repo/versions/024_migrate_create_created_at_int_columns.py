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


def upgrade(migrate_engine):
    # A migration here is not needed because the actual marshalling of data
    # from the old column to the new column is done in the contract phase. This
    # is because using triggers to convert datetime objects to integers is
    # complex and error-prone. Instead, we'll migrate the data once all
    # keystone nodes are on the Pike code-base. From an operator perspective,
    # this shouldn't affect operability of a rolling upgrade since all nodes
    # must be running Pike before the contract takes place.
    pass

..
      Copyright 2011-2012 OpenStack Foundation
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Identity entity ID management between controllers and drivers
=============================================================

Keystone supports the option of having domain-specific backends for the
identity driver (i.e. for user and group storage), allowing, for example,
a different LDAP server for each domain. To ensure that Keystone can determine
to which backend it should route an API call, starting with Juno, the
identity manager will, provided that domain-specific backends are enabled,
build on-the-fly a persistent mapping table between Keystone Public IDs that
are presented to the controller and the domain that holds the entity, along
with whatever local ID is understood by the driver.  This hides, for instance,
the LDAP specifics of whatever ID is being used.

To ensure backward compatibility, the default configuration of either a
single SQL or LDAP backend for Identity will not use the mapping table,
meaning that public facing IDs will be the unchanged. If keeping these IDs
the same for the default LDAP backend is not required, then setting the
configuration variable ``backward_compatible_ids`` to ``False`` will enable
the mapping for the default LDAP driver, hence hiding the LDAP specifics of the
IDs being used.

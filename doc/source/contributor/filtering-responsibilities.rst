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

==========================================================
Filtering responsibilities between controllers and drivers
==========================================================

Keystone supports the specification of filtering on list queries as part of the
v3 identity API. By default these queries are satisfied in the controller
class when a controller calls the ``wrap_collection`` method at the end of a
``list_{entity}`` method.  However, to enable optimum performance, any driver
can implement some or all of the specified filters (for example, by adding
filtering to the generated SQL statements to generate the list).

The communication of the filter details between the controller level and its
drivers is handled by the passing of a reference to a Hints object,
which is a list of dicts describing the filters. A driver that satisfies a
filter must delete the filter from the Hints object so that when it is returned
to the controller level, it knows to only execute any unsatisfied
filters.

The contract for a driver for ``list_{entity}`` methods is therefore:

* It MUST return a list of entities of the specified type
* It MAY either just return all such entities, or alternatively reduce the
  list by filtering for one or more of the specified filters in the passed
  Hints reference, and removing any such satisfied filters. An exception to
  this is that for identity drivers that support domains, then they should
  at least support filtering by domain_id.

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

=================================
Entity list truncation by drivers
=================================

Keystone supports the ability for a deployment to restrict the number of
entries returned from ``list_{entity}`` methods, typically to prevent poorly
formed searches (e.g. without sufficient filters) from becoming a performance
issue.

These limits are set in the configuration file, either for a specific driver or
across all drivers.  These limits are read at the Manager level and passed into
individual drivers as part of the Hints list object. A driver should try and
honor any such limit if possible, but if it is unable to do so then it may
ignore it (and the truncation of the returned list of entities will happen at
the controller level).

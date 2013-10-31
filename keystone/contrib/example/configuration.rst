..
      Copyright 2013 OpenStack, Foundation
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

=================
Extension Example
=================

Please describe here in details how to enable your extension:

1. Add the required fields and values in the ``[example]`` section
   in ``keystone.conf``.

2. Optional: add the required ``filter`` to the ``pipeline`` in ``keystone-paste.ini``

3. Optional: create the extension tables if using the provided sql backend. Example::


    ./bin/keystone-manage db_sync --extension example
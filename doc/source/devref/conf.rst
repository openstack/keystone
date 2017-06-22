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

Configuring Keystone with a sample file
=======================================

Keystone requires a configuration file. Keystone's sample configuration file
``etc/keystone.conf.sample`` is automatically generated based upon all of the
options available within Keystone. These options are sourced from the many
files around Keystone as well as some external libraries.

The sample configuration file will be updated as the end of the development
cycle approaches. Developers should *NOT* generate the config file and propose
it as part of their patches, this will cause unnecessary conflicts.
You can generate one locally using the following command:

.. code-block:: bash

    $ tox -e genconfig

The tox command will place an updated sample config in ``etc/keystone.conf.sample``.
The defaults are enough to get you going, but you can make any changes if
needed.

If there is a new external library (e.g. ``oslo.messaging``) that utilizes the
``oslo.config`` package for configuration, it can be added to the list of libraries
found in ``config-generator/keystone.conf``.

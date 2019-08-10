.. -*- rst -*-

..
      Copyright 2018 SUSE Linux GmbH
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

Limiting list return size
=========================

Keystone provides a method of setting a limit to the number of entities
returned in a collection, which is useful to prevent overly long response times
for list queries that have not specified a sufficiently narrow filter. This
limit can be set globally by setting ``list_limit`` in the default section of
``keystone.conf``, with no limit set by default. Individual driver sections may
override this global value with a specific limit, for example:

.. code-block:: ini

    [resource]
    list_limit = 100

If a response to ``list_{entity}`` call has been truncated, then the response
status code will still be 200 (OK), but the ``truncated`` attribute in the
collection will be set to ``true``.

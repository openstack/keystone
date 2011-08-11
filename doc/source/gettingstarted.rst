..
      Copyright 2011 OpenStack, LLC
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

Quick Guide to Getting Started with Keystone
============================================


Dependencies
---------------------------------
First, you will need to install keystone, if you haven't done so already
 
.. toctree::
   :maxdepth: 1

   installing  
   
Creating your first global admin
---------------------------------   
Change driectory to your install path

   
   
Creating your first tenant admin
---------------------------------   
Change directory to your install path. 
   
   
1. Run the following to create the first tennant::

   $>  bin/keystone-manage tenant add "MyTenant"

2. Run the following to create the first tenant admin::
   
   $>  bin/keystone-manage user add MyAdmin P@ssw0rd MyTenant
   
.. note::
   
   Some reserved roles are defined (and can be modified) through the keystone.conf in the /etc folder.

3. Associate your tenant admin with the Admin role::

   $> bin/keystone-manage role grant Admin MyAdmin

   
   


Curl examples
---------------------------------
.. toctree::
   :maxdepth: 1

   adminAPI_curl_examples
   serviceAPI_curl_examples 

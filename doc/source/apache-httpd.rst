
..
      Copyright 2011-2012 OpenStack, LLC
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

=========================
Running Keystone in HTTPD
=========================


SSL
===

To run Keystone in HTTPD, first enable SSL support.  This is optional,  but highly recommended.

Install mod_nss according to your distribution, then apply the following patch and restart HTTPD::

    --- /etc/httpd/conf.d/nss.conf.orig	2012-03-29 12:59:06.319470425 -0400
    +++ /etc/httpd/conf.d/nss.conf	2012-03-29 12:19:38.862721465 -0400
    @@ -17,7 +17,7 @@
     # Note: Configurations that use IPv6 but not IPv4-mapped addresses need two
     #       Listen directives: "Listen [::]:8443" and "Listen 0.0.0.0:443"
     #
    -Listen 8443
    +Listen 443

     ##
     ##  SSL Global Context
    @@ -81,7 +81,7 @@
     ## SSL Virtual Host Context
     ##

    -<virtualhost _default_:8443="">
    +<virtualhost _default_:443="">

     #   General setup for the virtual host
     #DocumentRoot "/etc/httpd/htdocs"
    </virtualhost></virtualhost>

Firewall
--------

Add the following rule to IPTables in order to ensure the SSL traffic can pass your firewall::

    -A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT

it goes right before::

    -A INPUT -j REJECT --reject-with icmp-host-prohibited

Files
-----

Copy the file keystone.conf to the appropriate location for your apache server, most likely::

    /etc/httpd/conf.d/keystone.conf

Create the directory ``/var/www/cgi-bin/keystone/``. You can either hardlink or softlink the files ``main`` and ``admin`` to the file ``keystone.py`` in this directory.  For a distribution appropriate place, it should probably be copied to::

    /usr/share/openstack/keystone/httpd/keystone.py


SELinux
-------

If you are running with SELinux enabled (and you should be) make sure that the file has the appropriate SELinux context to access the linked file.  If you have the file in /var/www/cgi-bin,  you can do this by running::

    sudo restorecon /var/www/cgi-bin

Putting it somewhere else requires you set up your SELinux policy accordingly.

Keystone Configuration
----------------------

Make sure you use the ``SQL`` driver for ``tokens``, otherwise the tokens will not be shared between the processes of the Apache HTTPD server.  To do that, in ``/etc/keystone/keystone.conf`` make sure you have set::

    [token]
    driver = keystone.token.backends.sql.Token

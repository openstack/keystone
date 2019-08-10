===============
Managing trusts
===============

A trust is an OpenStack Identity extension that enables delegation and,
optionally, impersonation through ``keystone``. See the :doc:`user
guide on using trusts </user/trusts>`.


Removing Expired Trusts
===========================================================

In the SQL trust stores expired and soft deleted trusts, that are not
automatically removed. These trusts can be removed with::

    $ keystone-manage trust_flush [options]

 OPTIONS (optional):

        --project-id <string>:
                    To purge trusts of given project-id.
        --trustor-user-id <string>:
                    To purge trusts of given trustor-id.
        --trustee-user-id <string>:
                    To purge trusts of given trustee-id.
        --date <string>:
                    To purge trusts older than date. If no date is supplied
                    keystone-manage will use the system clock time at runtime.

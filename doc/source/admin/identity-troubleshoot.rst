=================================
Troubleshoot the Identity service
=================================

To troubleshoot the Identity service, review the logs in the
``/var/log/keystone/keystone.log`` file.

Use the ``/etc/keystone/logging.conf`` file to configure the
location of log files.

.. note::

   The ``insecure_debug`` flag is unique to the Identity service.
   If you enable ``insecure_debug``, error messages from the API change
   to return security-sensitive information. For example, the error message
   on failed authentication includes information on why your authentication
   failed.

The logs show the components that have come in to the WSGI request, and
ideally show an error that explains why an authorization request failed.
If you do not see the request in the logs, run keystone with the
``--debug`` parameter. Pass the ``--debug`` parameter before the
command parameters.

Debug PKI middleware
~~~~~~~~~~~~~~~~~~~~

Problem
-------

If you receive an ``Invalid OpenStack Identity Credentials`` message when
you accessing and reaching an OpenStack service, it might be caused by
the changeover from UUID tokens to PKI tokens in the Grizzly release.

The PKI-based token validation scheme relies on certificates from
Identity that are fetched through HTTP and stored in a local directory.
The location for this directory is specified by the ``signing_dir``
configuration option.

Solution
--------

In your services configuration file, look for a section like this:

.. code-block:: ini

   [keystone_authtoken]
   signing_dir = /var/cache/glance/api
   www_authenticate_uri = http://controller:5000/v2.0
   identity_uri = http://controller:35357
   admin_tenant_name = service
   admin_user = glance

The first thing to check is that the ``signing_dir`` does, in fact,
exist. If it does, check for certificate files:

.. code-block:: console

   $ ls -la /var/cache/glance/api/

   total 24
   drwx------. 2 ayoung root 4096 Jul 22 10:58 .
   drwxr-xr-x. 4 root root 4096 Nov 7 2012 ..
   -rw-r-----. 1 ayoung ayoung 1424 Jul 22 10:58 cacert.pem
   -rw-r-----. 1 ayoung ayoung 15 Jul 22 10:58 revoked.pem
   -rw-r-----. 1 ayoung ayoung 4518 Jul 22 10:58 signing_cert.pem

This directory contains two certificates and the token revocation list.
If these files are not present, your service cannot fetch them from
Identity. To troubleshoot, try to talk to Identity to make sure it
correctly serves files, as follows:

.. code-block:: console

   $ curl http://localhost:35357/v2.0/certificates/signing

This command fetches the signing certificate:

.. code-block:: yaml

   Certificate:
       Data:
           Version: 3 (0x2)
           Serial Number: 1 (0x1)
       Signature Algorithm: sha1WithRSAEncryption
           Issuer: C=US, ST=Unset, L=Unset, O=Unset, CN=www.example.com
           Validity
               Not Before: Jul 22 14:57:31 2013 GMT
               Not After : Jul 20 14:57:31 2023 GMT
           Subject: C=US, ST=Unset, O=Unset, CN=www.example.com

Note the expiration dates of the certificate:

.. code-block:: console

    Not Before: Jul 22 14:57:31 2013 GMT
    Not After : Jul 20 14:57:31 2023 GMT

The token revocation list is updated once a minute, but the certificates
are not. One possible problem is that the certificates are the wrong
files or garbage. You can remove these files and run another command
against your server; they are fetched on demand.

The Identity service log should show the access of the certificate files. You
might have to turn up your logging levels. Set ``debug = True`` in your
Identity configuration file and restart the Identity server.

.. code-block:: console

    (keystone.common.wsgi): 2013-07-24 12:18:11,461 DEBUG wsgi __call__
    arg_dict: {}
    (access): 2013-07-24 12:18:11,462 INFO core __call__ 127.0.0.1 - - [24/Jul/2013:16:18:11 +0000]
    "GET http://localhost:35357/v2.0/certificates/signing HTTP/1.0" 200 4518

If the files do not appear in your directory after this, it is likely
one of the following issues:

* Your service is configured incorrectly and cannot talk to Identity.
  Check the ``auth_port`` and ``auth_host`` values and make sure that
  you can talk to that service through cURL, as shown previously.

* Your signing directory is not writable. Use the ``chmod`` command to
  change its permissions so that the service (POSIX) user can write to
  it. Verify the change through ``su`` and ``touch`` commands.

* The SELinux policy is denying access to the directory.

SELinux troubles often occur when you use Fedora or RHEL-based packages and
you choose configuration options that do not match the standard policy.
Run the ``setenforce permissive`` command. If that makes a difference,
you should relabel the directory. If you are using a sub-directory of
the ``/var/cache/`` directory, run the following command:

.. code-block:: console

   # restorecon /var/cache/

If you are not using a ``/var/cache`` sub-directory, you should. Modify
the ``signing_dir`` configuration option for your service and restart.

Set back to ``setenforce enforcing`` to confirm that your changes solve
the problem.

If your certificates are fetched on demand, the PKI validation is
working properly. Most likely, the token from Identity is not valid for
the operation you are attempting to perform, and your user needs a
different role for the operation.


Flush expired tokens from the token database table
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Problem
-------

As you generate tokens, the token database table on the Identity server
grows.

Solution
--------

To clear the token table, an administrative user must run the
:command:`keystone-manage token_flush` command to flush the tokens. When you
flush tokens, expired tokens are deleted and traceability is eliminated.

Use ``cron`` to schedule this command to run frequently based on your
workload. For large workloads, running it every minute is recommended.


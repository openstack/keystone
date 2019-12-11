.. -*- rst -*-

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

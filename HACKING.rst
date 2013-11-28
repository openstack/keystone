Keystone Style Commandments
===========================

- Step 1: Read the OpenStack Style Commandments
  http://docs.openstack.org/developer/hacking/
- Step 2: Read on

Keystone Specific Commandments
------------------------------

- Avoid using "double quotes" where you can reasonably use 'single quotes'


TODO vs FIXME
-------------

- TODO(name): implies that something should be done (cleanup, refactoring,
  etc), but is expected to be functional.
- FIXME(name): implies that the method/function/etc shouldn't be used until
  that code is resolved and bug fixed.


Logging
-------

Use the common logging module, and ensure you ``getLogger``::

    from keystone.openstack.common import log as logging

    LOG = logging.getLogger(__name__)

    LOG.debug('Foobar')

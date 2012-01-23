=============
Release notes
=============


E3 (January 26, 2012)
==========================================
* Contract compliance: version response and ATOM, 300 multiple choice
* Global endpoints returned for unscoped calls
* adminUrl only shown to admin clients
* Endpoints have unique ID
* Auth-N/Auth-Z for S3 API (OS-KSS3 extension)
* Default tenant scope optionally returned when authenticating
* Vary header returned for caching proxies

* Portable identifiers: modifiable, string identifiers in database backend
* Much improved keystone-manage command (see --help and docs)
* OS-KSVALIDATE extension to support not passing tokens in URL
* OS-KSEC2 and OS-KSS3 extensions respond on /tokens
* HP-IDM extension to filter roles to a given service ID
* Additional caching options in middleware (memcache and swift cache)

* Enhanced configuration management (in line with other OpenStack projects)
* Additional logging
* Enhanced tracer tool (-t or --trace-calls)

See comprehensive list here https://launchpad.net/keystone/+milestone/essex-3


E2 (December 15, 2011)
========================
* D5 compatibility middleware
* Database versioning
* Much more documentation: http://keystone.openstack.org

See https://launchpad.net/keystone/+milestone/essex-2

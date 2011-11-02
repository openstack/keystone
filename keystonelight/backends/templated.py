class TemplatedCatalog(object):
  """A backend that generates endpoints for the Catalog based on templates.

  It is usually configured via config entries that look like:

    catalog.$REGION.$SERVICE.$key = $value

  and is stored in a similar looking hierarchy. Where a value can contain
  values to be interpolated by standard python string interpolation that look
  like (the % is replaced by a $ due to paste attmepting to interpolate on its
  own:

    http://localhost:$(public_port)s/

  When expanding the template it will pass in a dict made up of the options
  instance plus a few additional key-values, notably tenant_id and user_id.

  It does not care what the keys and values are but it is worth noting that
  keystone_compat will expect certain keys to be there so that it can munge
  them into the output format keystone expects. These keys are:

    name - the name of the service, most likely repeated for all services of
           the same type, across regions.
    adminURL - the url of the admin endpoint
    publicURL - the url of the public endpoint
    internalURL - the url of the internal endpoint

  """

  def __init__(self, options, templates=None):
    self.options = options

    if templates:
      self.templates = templates
    else:
      self._load_templates(options)

  def _load_templates(self, options):
    o = {}
    for k, v in options.iteritems():
      if not k.startswith('catalog.'):
        continue

      parts = k.split('.')

      region = parts[1]
      service = parts[2]
      key = parts[3]

      region_ref = o.get(region, {})
      service_ref = region_ref.get(service, {})
      service_ref[key] = v

      region_ref[service] = service_ref
      o[region] = region_ref

    self.templates = o

  def get_catalog(self, user_id, tenant_id, extras=None):
    d = self.options.copy()
    d.update({'tenant_id': tenant_id,
              'user_id': user_id})

    o = {}
    for region, region_ref in self.templates.iteritems():
      o[region] = {}
      for service, service_ref in region_ref.iteritems():
        o[region][service] = {}
        for k, v in service_ref.iteritems():
          v = v.replace('$(', '%(')
          o[region][service][k] = v % d

    return o








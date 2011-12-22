import logging


class TrivialTrue(object):
  def __init__(self, options):
    self.options = options

  def can_haz(self, target, credentials):
    return True


class SimpleMatch(object):
  def __init__(self, options):
    self.options = options

  def can_haz(self, target, credentials):
    """Check whether key-values in target are present in credentials."""
    # TODO(termie): handle ANDs, probably by providing a tuple instead of a
    #               string
    for requirement in target:
      key, match = requirement.split(':', 1)
      check = credentials.get(key)
      if check == match:
        return True


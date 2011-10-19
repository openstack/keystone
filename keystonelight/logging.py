from __future__ import absolute_import

import functools
import logging
import pprint


from logging import *


def log_debug(f):
  @functools.wraps(f)
  def wrapper(*args, **kw):
    logging.debug('%s(%s, %s) ->', f.func_name, str(args), str(kw))
    rv = f(*args, **kw)
    logging.debug(pprint.pformat(rv, indent=2))
    logging.debug('')
    return rv
  return wrapper

from __future__ import absolute_import

import functools
import logging
import pprint


# A list of things we want to replicate from logging.
# levels
CRITICAL = logging.CRITICAL
FATAL = logging.FATAL
ERROR = logging.ERROR
WARNING = logging.WARNING
WARN = logging.WARN
INFO = logging.INFO
DEBUG = logging.DEBUG
NOTSET = logging.NOTSET


# methods
getLogger = logging.getLogger
debug = logging.debug
info = logging.info
warning = logging.warning
warn = logging.warn
error = logging.error
exception = logging.exception
critical = logging.critical
log = logging.log


# handlers
StreamHandler = logging.StreamHandler
#WatchedFileHandler = logging.handlers.WatchedFileHandler
# logging.SysLogHandler is nicer than logging.logging.handler.SysLogHandler.
#SysLogHandler = logging.handlers.SysLogHandler


def log_debug(f):
  @functools.wraps(f)
  def wrapper(*args, **kw):
    logging.debug('%s(%s, %s) ->', f.func_name, str(args), str(kw))
    rv = f(*args, **kw)
    logging.debug(pprint.pformat(rv, indent=2))
    logging.debug('')
    return rv
  return wrapper

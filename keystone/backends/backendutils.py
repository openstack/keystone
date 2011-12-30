import logging
logger = logging.getLogger(__name__)  # pylint: disable=C0103

from keystone.backends import models
import keystone.backends as backends
# pylint: disable=E0611
try:
    from passlib.hash import sha512_crypt as sc
except ImportError as exc:
    logger.exception(exc)
    raise exc


def __get_hashed_password(password):
    if password:
        return __make_password(password)
    else:
        return None


def set_hashed_password(values):
    """
    Sets hashed password for password.
    """
    if backends.SHOULD_HASH_PASSWORD:
        if isinstance(values, dict) and 'password' in values.keys():
            values['password'] = __get_hashed_password(values['password'])
        elif isinstance(values, models.User):
            values.password = __get_hashed_password(values.password)
        else:
            logger.warn("Could not hash password on unsupported type: %s" %
                        type(values))


def check_password(raw_password, enc_password):
    """
    Compares raw password and encoded password.
    """
    if not raw_password:
        return False
    if backends.SHOULD_HASH_PASSWORD:
        return sc.verify(raw_password, enc_password)
    else:
        return enc_password == raw_password


def __make_password(raw_password):
    """
     Produce a new encoded password.
    """
    if raw_password is None:
        return None
    hsh = __get_hexdigest(raw_password)
    return '%s' % (hsh)


#Refer http://packages.python.org/passlib/lib/passlib.hash.sha512_crypt.html
#Using the default properties as of now.Salt gets generated automatically.
def __get_hexdigest(raw_password):
    return sc.encrypt(raw_password)

VERSION_STATUS = "ALPHA"
VERSION_DATE = "2011-04-23T00:00:00Z"

from keystone.logic.service import IdentityService
SERVICE = IdentityService()

# These just need to be imported somewhere, nothing appears to access them
from keystone.backends import alterdb, sqlalchemy
ALTERDB = alterdb
SQLALCHEMY = sqlalchemy

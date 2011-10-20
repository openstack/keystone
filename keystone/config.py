"""TODO: This file should be dissolved"""

from keystone.logic.service import IdentityService
SERVICE = IdentityService()

# These just need to be imported somewhere, nothing appears to access them?
from keystone.backends import sqlalchemy
SQLALCHEMY = sqlalchemy

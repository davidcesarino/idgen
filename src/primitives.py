#  Copyright (C) 2024 David Cesarino de Sousa <1624159+davidcesarino@users.noreply.github.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see
#  <https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>
# ###################################################################
# USER FACING LABELS - TRANSLATABLE
# ###################################################################
APP_NAME = 'IdGen'
APP_CALL = 'idgen'
APP_VERSION = '0.9'
APP_YEAR = '2024'
APP_AUTHOR = 'David Cesarino de Sousa <1624159+davidcesarino@users.noreply.github.com>'
ERR_PATH_NODIR = 'no such directory: {}'
ERR_PATH_NOFILE = 'no such file: {}'
HELP_CONFIG_FILE = 'see included example.json for a full example'
HELP_OUTDIR = 'it will be created if it doesn\'t exist'
HELP_VERSION = 'show version and exit'
HELP_LICENSE = 'show program license and exit'
HELP_LOG_LEVEL1 = 'sets log verbosity; defaults to {}'
HELP_DESCRIPTION = \
    'Generates keys and certificates based on a JSON file.'
ABOUT_VERSION = '''{} {}'''.format(APP_NAME, APP_VERSION)
ABOUT_LICENSE = (
    '{} Copyright (C) {} {}\n\n'
    'This program is free software; you can redistribute it and/or modify it '
    'under the terms of the GNU General Public License as published by the '
    'Free Software Foundation; either version 2 of the License, or '
    '(at your option) any later version.\n\n'
    'This program is distributed in the hope that it will be useful, but '
    'WITHOUT ANY WARRANTY; without even the implied warranty of '
    'MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. '
    'See the GNU General Public License for more details.\n\n'
    'You should have received a copy of the GNU General Public License along '
    'with this program. If not, '
    'see <https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>.').format(
    APP_NAME, APP_YEAR, APP_AUTHOR)

# ###################################################################
# ERROR MESSAGES
# ###################################################################
INFO_RSA_SIZE1_MIN2 = 'Replacing RSA size "{}" with the minimum {}.'

WARN_ED_PKCS_ID1_LOAD = \
    ('Reading ED25519 key (id="{}") in PKCS#8 format. '
     'To avoid compatibility issues, use only SSH.')
WARN_ED_PKCS_ID1_WRITE = \
    ('Writing ED25519 key (id="{}") in PKCS#8 format. '
     'To avoid compatibility issues, use only SSH.')
WARN_NAME1_TYPE2_NO_OUTPUT = \
    'Skipping "{}" key for "{}": no outputs configured.'
WARN_CERT1_WRITING_FILE = \
    'Skipping writing certificate id "{}": already in file and loaded.'

ERR_EMPTY_KEYSET = 'Key sets must have at least one defined key.'
ERR_1_ISNT_VALID_FORMAT = '{} is not a valid format name.'
ERR_INVALID_FORMAT1_FOR_KEY2 = 'Invalid file format "{}" for key id "{}".'
ERR_KEY_ID1_FILE2_NOT_FOUND = 'File for key id "{}" not found: {}'
ERR_ID1_PKCSFILE2_NOT_FOUND = 'PKCS#8 file for key id "{}" not found: {}'
ERR_ID1_SSHFILE2_NOT_FOUND = 'SSH file for key id "{}" not found: {}'
ERR_ID1_IS_TYPE2_NO_PKCS1 = 'Key id "{}" is "{}": PKCS1 not supported.'
ERR_TYPE1_2_RSA_OR_ED25519 = 'Key id "{}" must be RSA or ED25519. Got: "{}"'
ERR_DIR2_FOR_OBJ1_NOT_FOUND = 'Folder not found for object id "{}": {}'
ERR_CERT1_INVALID_DURATION2 = \
    ('Certificate named "{}" must be valid at least for today. '
     'Parameter "{}" must be >= 0.')
ERR_OPEN_CHILD1_SUBS2_PARAM3 = \
    ('Certificate named "{}" is a leaf, end-of-chain, certificate, but its '
     'depth is set to "{}". Set "{}" to zero since leaf certificates cannot '
     'have descendants.')
ERR_LEAFED_PARENT1_PARAM2 = \
    ('Certificate named "{}" is a signing certificate, but it is set with '
     'a path length of 0. Set "{}" in the configuration file to a positive '
     'non-zero integer to set the maximum depth of the chain, or a negative '
     'integer to allow for an unlimited depth in the descendants tree.')
ERR_KEY1_FOR_CERT2 = \
    'Cannot find signing key id "{}" for certificate id "{}"'
ERR_ROOT1_FOR_CERT2 = \
    'Cannot find parent certificate id "{}" for certificate id "{}"'
ERR_CERT_ID1_FILE2_NOT_FOUND = 'File for certificate id "{}" not found: {}'

# ###################################################################
# INTERNAL VALUES
# ###################################################################
_STR_KEYSETS = "keysets"
_STR_CERTIFICATES = "certificates"
_STR_NAME = "name"
_STR_ID = "id"
_STR_OUTPUT = "output"
_STR_RSA = "rsa"
_STR_ED25519 = "ed25519"
_STR_SIZE = "size"
_STR_SECRET = "secret"
_STR_DAYS_VALID = "days_valid"
_STR_USE = "use"
_STR_KEY = "key"
_STR_FILE = "file"
_STR_ROOT = "root"
_STR_SUBJECT = "subject"
_STR_SUBJ_COUNTRY = "c"
_STR_SUBJ_PROVINCE = "st"
_STR_SUBJ_CITY = "l"
_STR_SUBJ_ORG = "o"
_STR_SUBJ_ORG_UNIT = "ou"
_STR_SUBJ_COMMON_NAME = "cn"
_STR_SUBJ_EMAIL = "emailAddress"
_STR_PKCS8 = "pkcs8"
_STR_PKCS1 = "pkcs1"
_STR_PRIV_SSH = "private_ssh"
_STR_PUB_SSH = "public_ssh"
_STR_MAX_SUBS = "max_subordinates"
_STR_SIGN_OTHER = "sign_other"
STR_EMPTY = ''
FILE_SEP_SMALL: str = '-'
FILE_SEP_LARGE: str = '_-_'
FILE_SEP_EXT = '.'
FILE_EXT_PRIVATE_PKCS8 = 'pkcs8.pem'
FILE_EXT_PRIVATE_SSH = 'ssh.pem'
FILE_EXT_PUBLIC_PKCS1 = 'pkcs1.pem'
FILE_EXT_PUBLIC_SSH = 'ssh.pub'
FILE_EXT_CERT = 'crt'
FILE_PREFFIX_KEY = 'id'
FILE_PREFFIX_CERTIFICATE = 'cert'
FILE_PREFFIX_RSA = _STR_RSA
FILE_PREFFIX_ED25519 = _STR_ED25519
FILE_ENCODING_DEFAULT = 'utf-8'
VALUE_PRIVATE_FORMAT_PKCS8 = _STR_PKCS8
VALUE_PUBLIC_FORMAT_PKCS1 = _STR_PKCS1
VALUE_PRIVATE_FORMAT_SSH = _STR_PRIV_SSH
VALUE_PUBLIC_FORMAT_SSH = _STR_PUB_SSH

# ###################################################################
# ENTITIES
# ###################################################################
KEY_TYPE_RSA_NAME = _STR_RSA
KEY_TYPE_ED25519_NAME = _STR_ED25519

# ###################################################################
# CONFIGURATION FILE
# ###################################################################
FIELD_KEYSETS = _STR_KEYSETS
FIELD_CERTS = _STR_CERTIFICATES

FIELD_K_NAME = _STR_NAME
FIELD_K_RSA = _STR_RSA
FIELD_K_ED25519 = _STR_ED25519
FIELD_K_ID = _STR_ID
FIELD_K_SECRET = _STR_SECRET
FIELD_K_OUTPUT = _STR_OUTPUT
FIELD_K_SIZE = _STR_SIZE
FIELD_K_FILE = _STR_FILE
FIELD_K_PKCS8 = _STR_PKCS8
FIELD_K_PRIVATE_SSH = _STR_PRIV_SSH
FIELD_K_USE = _STR_USE

FIELD_C_ID = _STR_ID
FIELD_C_NAME = _STR_NAME
FIELD_C_VALID = _STR_DAYS_VALID
FIELD_C_KEY = _STR_KEY
FIELD_C_ROOT = _STR_ROOT
FIELD_C_SIGN_OTHER = _STR_SIGN_OTHER
FIELD_C_MAX_SUBS = _STR_MAX_SUBS
FIELD_C_FILE = _STR_FILE
FIELD_C_SUBJ = _STR_SUBJECT
FIELD_C_S_COUNTRY = _STR_SUBJ_COUNTRY
FIELD_C_S_PROVINCE = _STR_SUBJ_PROVINCE
FIELD_C_S_CITY = _STR_SUBJ_CITY
FIELD_C_S_ORG = _STR_SUBJ_ORG
FIELD_C_S_ORG_UNIT = _STR_SUBJ_ORG_UNIT
FIELD_C_S_CN = _STR_SUBJ_COMMON_NAME
FIELD_C_S_EMAIL = _STR_SUBJ_EMAIL

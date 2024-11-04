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
from typing import NamedTuple

from cryptography.x509.name import Name
from cryptography.x509.name import NameAttribute
from cryptography.x509.oid import NameOID


class Subject(NamedTuple):
    """A wrapper, friendlier class to the `x509.name.Name` class."""
    country: str
    province: str
    locality: str
    organization: str
    org_unit: str
    common_name: str
    email: str

    def x509_name(self) -> Name:
        return Name([
            NameAttribute(NameOID.COUNTRY_NAME, self.country),
            NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.province),
            NameAttribute(NameOID.LOCALITY_NAME, self.locality),
            NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
            NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.org_unit),
            NameAttribute(NameOID.COMMON_NAME, self.common_name),
            NameAttribute(NameOID.EMAIL_ADDRESS, self.email)])

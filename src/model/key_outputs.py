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
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat

from src.log import Log
from src.primitives import ERR_1_ISNT_VALID_FORMAT
from src.primitives import FIELD_K_OUTPUT
from src.primitives import VALUE_PRIVATE_FORMAT_PKCS8
from src.primitives import VALUE_PRIVATE_FORMAT_SSH
from src.primitives import VALUE_PUBLIC_FORMAT_PKCS1
from src.primitives import VALUE_PUBLIC_FORMAT_SSH


class KeyOutputs:
    def __init__(self, *,
            pkcs8: bool=False,
            pkcs1: bool=False,
            private_ssh: bool=False,
            public_ssh: bool=False):
        self.pkcs8=pkcs8
        self.pkcs1=pkcs1
        self.private_ssh=private_ssh
        self.public_ssh=public_ssh

    def available(self) -> list:
        formats=[]
        if self.pkcs8: formats.append(PrivateFormat.PKCS8)
        if self.pkcs1: formats.append(PublicFormat.PKCS1)
        if self.private_ssh: formats.append(PrivateFormat.OpenSSH)
        if self.public_ssh: formats.append(PublicFormat.OpenSSH)
        return formats

    def has_private_format(self):
        return self.pkcs8 or self.private_ssh

    def has_public_format(self):
        return self.pkcs1 or self.public_ssh

    def no_private_formats(self):
        return not self.has_private_format()

    def no_public_formats(self):
        return not self.has_public_format()

    def has_only_public_formats(self):
        return self.has_public_format() and self.no_private_formats()

    def has_only_private_formats(self):
        return self.has_private_format() and self.no_public_formats()

    @staticmethod
    def from_format(log: Log, key_format: PrivateFormat | PublicFormat):
        if key_format == PrivateFormat.PKCS8:
            return KeyOutputs(pkcs8=True)
        elif key_format == PublicFormat.PKCS1:
            return KeyOutputs(pkcs1=True)
        elif key_format == PrivateFormat.OpenSSH:
            return KeyOutputs(private_ssh=True)
        elif key_format == PublicFormat.OpenSSH:
            return KeyOutputs(public_ssh=True)
        else:
            msg=ERR_1_ISNT_VALID_FORMAT.format(key_format.name)
            log.e(ValueError(msg))

    @staticmethod
    def from_format_name(log: Log, format_name: str):
        if format_name == VALUE_PRIVATE_FORMAT_PKCS8:
            return KeyOutputs(pkcs8=True)
        elif format_name == VALUE_PUBLIC_FORMAT_PKCS1:
            return KeyOutputs(pkcs1=True)
        elif format_name == VALUE_PRIVATE_FORMAT_SSH:
            return KeyOutputs(private_ssh=True)
        elif format_name == VALUE_PUBLIC_FORMAT_SSH:
            return KeyOutputs(public_ssh=True)
        else:
            msg=ERR_1_ISNT_VALID_FORMAT.format(format_name)
            log.e(ValueError(msg))

    @staticmethod
    def from_output(output_data: list):
        pkcs8=output_data.__contains__(VALUE_PRIVATE_FORMAT_PKCS8)
        pkcs1=output_data.__contains__(VALUE_PUBLIC_FORMAT_PKCS1)
        priv_ssh=output_data.__contains__(VALUE_PRIVATE_FORMAT_SSH)
        pub_ssh=output_data.__contains__(VALUE_PUBLIC_FORMAT_SSH)
        return KeyOutputs(pkcs8=pkcs8, pkcs1=pkcs1,
            private_ssh=priv_ssh, public_ssh=pub_ssh)

    @staticmethod
    def from_key(key_data: dict):
        output_data=key_data[FIELD_K_OUTPUT]
        return KeyOutputs.from_output(output_data)


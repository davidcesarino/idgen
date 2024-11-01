#  Copyright (C) 2024 David Cesarino de Sousa <david@cesarino.pro>
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
import os
from abc import ABC
from abc import abstractmethod
from stat import S_IRGRP
from stat import S_IROTH
from stat import S_IRUSR
from stat import S_IWUSR

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat

from src.model.key_outputs import KeyOutputs
from src.primitives import FIELD_K_FILE
from src.primitives import FIELD_K_ID
from src.primitives import FIELD_K_OUTPUT
from src.primitives import FIELD_K_PKCS8
from src.primitives import FIELD_K_PRIVATE_SSH
from src.primitives import FIELD_K_SECRET
from src.primitives import FIELD_K_SIZE
from src.primitives import FIELD_K_USE
from src.primitives import FILE_ENCODING_DEFAULT
from src.primitives import FILE_EXT_PRIVATE_PKCS8
from src.primitives import FILE_EXT_PRIVATE_SSH
from src.primitives import FILE_EXT_PUBLIC_PKCS1
from src.primitives import FILE_EXT_PUBLIC_SSH
from src.primitives import FILE_PREFFIX_ED25519
from src.primitives import FILE_PREFFIX_KEY
from src.primitives import FILE_PREFFIX_RSA
from src.primitives import FILE_SEP_EXT
from src.primitives import FILE_SEP_LARGE
from src.primitives import FILE_SEP_SMALL
from src.primitives import KEY_TYPE_ED25519_NAME
from src.primitives import STR_EMPTY
from src.primitives import VALUE_PRIVATE_FORMAT_PKCS8
from src.primitives import VALUE_PRIVATE_FORMAT_SSH
from src.primitives import VALUE_PUBLIC_FORMAT_PKCS1
from src.primitives import VALUE_PUBLIC_FORMAT_SSH


class Key(ABC):
    @abstractmethod
    def _supports_pkcs1(self) -> bool:
        pass

    @abstractmethod
    def _generate_key(self) -> "RsaKey | Ed25519Key":
        pass

    @abstractmethod
    def _key_filename_preffix(self) -> str:
        pass

    def __init__(self, *,
            key_id: int,
            secret: str,
            outputs: KeyOutputs,
            private_key: RSAPrivateKey | Ed25519PrivateKey=None):
        self.key_id=key_id
        self.secret=secret
        self.outputs=outputs
        if private_key is None:
            self.private_key=self._generate_key()
        else:
            self.private_key=private_key
        self.public_key=self.private_key.public_key()

    @staticmethod
    def from_json(key_data: dict):
        output_data=key_data[FIELD_K_OUTPUT]
        outputs=KeyOutputs(
            pkcs8=output_data.__contains__(VALUE_PRIVATE_FORMAT_PKCS8),
            pkcs1=output_data.__contains__(VALUE_PUBLIC_FORMAT_PKCS1),
            private_ssh=output_data.__contains__(VALUE_PRIVATE_FORMAT_SSH),
            public_ssh=output_data.__contains__(VALUE_PUBLIC_FORMAT_SSH))
        k_id=key_data[FIELD_K_ID]
        is_rsa=key_data.__contains__(FIELD_K_SIZE)

        file_data=key_data[FIELD_K_FILE]
        use=file_data[FIELD_K_USE]
        use_pkcs8=use == VALUE_PRIVATE_FORMAT_PKCS8
        use_ssh=use == VALUE_PRIVATE_FORMAT_SSH
        file_pkcs8=file_data[FIELD_K_PKCS8]
        file_ssh=file_data[FIELD_K_PRIVATE_SSH]

        # Error scenarios.
        if use != STR_EMPTY and not use_pkcs8 and not use_ssh:
            raise ValueError('Invalid file format for key "{}": "{}"'
            .format(k_id, use))
        if use_pkcs8 and not os.path.isfile(file_pkcs8):
            raise ValueError('PKCS8 file for key "{}" not found: {}'
            .format(k_id, file_pkcs8))
        if use_ssh and not os.path.isfile(file_ssh):
            raise ValueError('SSH file for key "{}" not found: {}'
            .format(k_id, file_ssh))
        if not is_rsa and outputs.pkcs1:
            raise ValueError('Key "{}" is "{}": cannot have PKCS1 output'
            .format(k_id, KEY_TYPE_ED25519_NAME))

        k_secret=key_data[FIELD_K_SECRET]
        k_size=key_data[FIELD_K_SIZE] if is_rsa else -1
        file_fmt=PrivateFormat.PKCS8 if use_pkcs8 else PrivateFormat.OpenSSH

        if use == STR_EMPTY:
            if is_rsa:
                return RsaKey(key_id=k_id, secret=k_secret, outputs=outputs,
                    size=k_size)
            else:
                return Ed25519Key(key_id=k_id, secret=k_secret, outputs=outputs)
        else:  # use_pkcs8 or use_ssh:
            Key.from_file(
                key_id=k_id,
                private_format=file_fmt,
                secret=k_secret,
                outputs=outputs,
                file_path=file_pkcs8 if use_pkcs8 else file_ssh)

    @staticmethod
    def from_file(*,
            key_id: int,
            private_format: PrivateFormat,
            secret: str,
            outputs: KeyOutputs,
            file_path: str,
            file_encoding: str=FILE_ENCODING_DEFAULT):
        with open(file_path, "rb") as key_file:
            if private_format == PrivateFormat.PKCS8:
                key=load_pem_private_key(
                    key_file.read(),
                    secret.encode(file_encoding))
            elif private_format == PrivateFormat.OpenSSH:
                key=load_ssh_private_key(
                    key_file.read(),
                    secret.encode(file_encoding))
            else:
                raise ValueError('{} is not a valid format.'
                .format(private_format.name.upper()))
        return Key(key_id=key_id,
            secret=secret,
            outputs=outputs,
            private_key=key)

    def write(self, *,
            name: str,
            timestamp: int,
            outdir: str,
            file_encoding: str=FILE_ENCODING_DEFAULT,
            append_ssh_info: bool=True):
        available_formats = self.outputs.available()
        if available_formats.__len__() == 0:
            print("Skipping '{} (type: {})': no configurable outputs."
                .format(name, self._friendly_name()))
            return
        for key_format in available_formats:
            self.write_format(
                name=name,
                timestamp=timestamp,
                key_format=key_format,
                outdir=outdir,
                file_encoding=file_encoding,
                append_ssh_info=append_ssh_info)
        
    def write_format(self, *,
            key_format: PrivateFormat | PublicFormat,
            name: str,
            timestamp: int,
            outdir: str,
            file_encoding: str=FILE_ENCODING_DEFAULT,
            append_ssh_info: bool=True):
        if not os.path.isdir(outdir):
            raise NotADirectoryError(outdir)
        else:
            outfile=self._file_name(key_format, name, timestamp)
            contents=self._key_bytes(key_format, file_encoding)
            if append_ssh_info and key_format == PublicFormat.OpenSSH:
                # Remove extension.
                identity=outfile.split(FILE_SEP_EXT, 1)[0]
                contents += ' {}\n'.format(identity).encode(file_encoding)
            outpath=os.path.join(outdir, outfile)
            with open(outpath, "wb") as file:
                file.write(contents)
                if key_format == PrivateFormat.PKCS8 \
                        or key_format == PrivateFormat.OpenSSH:
                    os.chmod(outpath, S_IRUSR | S_IWUSR)
                else:
                    os.chmod(outpath, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

    def _file_name(self,
            key_format: PrivateFormat | PublicFormat,
            name: str,
            timestamp: int) -> str:
        if key_format == PrivateFormat.PKCS8:
            extension=FILE_EXT_PRIVATE_PKCS8
        elif key_format == PrivateFormat.OpenSSH:
            extension=FILE_EXT_PRIVATE_SSH
        elif key_format == PublicFormat.PKCS1:
            extension=FILE_EXT_PUBLIC_PKCS1
        elif key_format == PublicFormat.OpenSSH:
            extension=FILE_EXT_PUBLIC_SSH
        else:
            raise ValueError("Unsupported key format: {}"
            .format(key_format.name))
        return \
            FILE_SEP_EXT.join([
                FILE_SEP_LARGE.join([
                    str(timestamp),
                    FILE_SEP_SMALL.join([
                        FILE_PREFFIX_KEY,
                        name,
                        self._key_filename_preffix()
                    ])
                ]),
                extension
            ])

    def _key_bytes(self,
            key_format: PrivateFormat | PublicFormat,
            file_encoding: str) -> bytes:
        is_pkcs8=key_format == PrivateFormat.PKCS8
        is_priv_ssh=key_format == PrivateFormat.OpenSSH
        is_pkcs1=key_format == PublicFormat.PKCS1
        is_pub_ssh=key_format == PublicFormat.OpenSSH

        if is_pkcs8 or is_priv_ssh:
            return self._private_bytes(key_format, file_encoding)
        elif is_pub_ssh:
            return self._public_bytes(Encoding.OpenSSH, key_format)
        elif is_pkcs1:
            if self._supports_pkcs1():
                return self._public_bytes(Encoding.PEM, key_format)
            else:
                raise ValueError("Key does not support PKCS1: {}"
                .format(self._friendly_name()))
        else:
            raise ValueError("Unsupported key format: {}"
            .format(key_format.name))
    
    def _private_bytes(self,
            private_format: PrivateFormat,
            file_encoding: str) -> bytes:
        if self.secret == STR_EMPTY:
            encryption=NoEncryption()
        else:
            secret_bytes=bytes(self.secret, file_encoding)
            encryption=BestAvailableEncryption(secret_bytes)
        return self.private_key.private_bytes(
            Encoding.PEM,
            private_format,
            encryption)

    def _public_bytes(self,
            key_encoding: Encoding,
            public_format: PublicFormat) -> bytes:
        return self.public_key.public_bytes(
            key_encoding,
            public_format)

    def _friendly_name(self) -> str: return self._key_filename_preffix()


class Ed25519Key(Key):
    def __init__(self, *,
            key_id: int,
            secret: str,
            outputs: KeyOutputs,
            private_key: Ed25519PrivateKey=None):
        if outputs.pkcs1:
            raise ValueError("Key does not support PKCS1: {}"
            .format(self._friendly_name()))
        super().__init__(
            key_id=key_id,
            secret=secret,
            outputs=outputs,
            private_key=private_key)

    def _supports_pkcs1(self) -> bool:
        return False

    def _generate_key(self) -> Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.generate()

    def _key_filename_preffix(self) -> str:
        return Ed25519Key.key_filename_preffix()

    @staticmethod
    def key_filename_preffix(): return FILE_PREFFIX_ED25519
    

class RsaKey(Key):
    _EXP=65537
    _MIN_SIZE=2048

    def __init__(self, *,
            key_id: int,
            size: int,
            secret: str,
            outputs: KeyOutputs,
            private_key: RSAPrivateKey=None):
        self.size=size
        super().__init__(
            key_id=key_id,
            secret=secret,
            outputs=outputs,
            private_key=private_key)

    def _supports_pkcs1(self) -> bool:
        return True

    def _generate_key(self) -> RSAPrivateKey:
        size=max(self.size, RsaKey._MIN_SIZE)
        return rsa.generate_private_key(RsaKey._EXP, size, default_backend())

    def _key_filename_preffix(self) -> str:
        return RsaKey.key_filename_preffix()

    @staticmethod
    def key_filename_preffix(): return FILE_PREFFIX_RSA

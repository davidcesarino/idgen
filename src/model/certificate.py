#  Copyright (C) 2024 David Cesarino de Sousa <david@cesarino.pro>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see
#  <https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>
import os
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.base import Certificate as X509Certificate

from src.model.key import Key
from src.model.subject import Subject
from src.primitives import FIELD_C_ID
from src.primitives import FIELD_C_KEY
from src.primitives import FIELD_C_MAX_SUBS
from src.primitives import FIELD_C_NAME
from src.primitives import FIELD_C_ROOT
from src.primitives import FIELD_C_S_CITY
from src.primitives import FIELD_C_S_CN
from src.primitives import FIELD_C_S_COUNTRY
from src.primitives import FIELD_C_S_EMAIL
from src.primitives import FIELD_C_S_ORG
from src.primitives import FIELD_C_S_ORG_UNIT
from src.primitives import FIELD_C_S_PROVINCE
from src.primitives import FIELD_C_SIGN_OTHER
from src.primitives import FIELD_C_SUBJ
from src.primitives import FIELD_C_VALID
from src.primitives import FILE_EXT_CERT
from src.primitives import FILE_PREFFIX_CERTIFICATE
from src.primitives import FILE_SEP_EXT
from src.primitives import FILE_SEP_LARGE
from src.primitives import FILE_SEP_SMALL


class Certificate:
    STANDARD_USAGE=x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False)

    def __init__(self, *,
            name: str,
            timestamp: int,
            days_valid: int,
            subject: Subject,
            key: Key,
            sign_other: bool=True,
            max_subordinates: int=-1,
            root_certificate: "Certificate",
            usage: x509.KeyUsage=STANDARD_USAGE):
        if days_valid < 0:
            raise ValueError('Certificate must be valid at least for today.')
        self.name=name
        self.timestamp=timestamp
        self.subject=subject
        self.key=key
        self.valid_from=datetime.fromtimestamp(timestamp, timezone.utc)
        delta_end=timedelta(days=days_valid)
        self.expiration=self.valid_from.replace(
            hour=23, minute=59, second=59, microsecond=0) + delta_end
        self.sign_other=sign_other
        self.max_subordinates=max_subordinates
        self.root_certificate=root_certificate
        self.usage=usage
        self.x509_certificate=self._make_certificate()

    @staticmethod
    def _raise_leafed_parent():
        raise ValueError('A signing certificate must allow at least one '
                         'subordinate, or any negative number for an '
                         'unlimited number of children certificates.')

    @staticmethod
    def _raise_open_leaf():
        raise ValueError('A leaf (final) certificate must have exactly '
                         'zero subordinates.')

    def _make_certificate(self) -> X509Certificate:
        # Root certificate has no parent.
        is_root=self.root_certificate is None
        # Errors.
        if self.sign_other and self.max_subordinates == 0:
            Certificate._raise_leafed_parent()
        if not self.sign_other and self.max_subordinates != 0:
            Certificate._raise_open_leaf()
        # Other.
        issuer_name=self.subject.x509_name() if is_root \
            else self.root_certificate.subject.x509_name()
        private_key=self.key.private_key if is_root \
            else self.root_certificate.key.private_key
        depth=None if not self.sign_other or self.max_subordinates < 0 \
            else self.max_subordinates
        constraints=x509.BasicConstraints(ca=self.sign_other, path_length=depth)
        public_id=x509.SubjectKeyIdentifier.from_public_key(self.key.public_key)
        # Builder.
        builder=x509.CertificateBuilder() \
            .subject_name(self.subject.x509_name()) \
            .issuer_name(issuer_name) \
            .public_key(self.key.public_key) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(self.valid_from) \
            .not_valid_after(self.expiration) \
            .add_extension(constraints, critical=True) \
            .add_extension(self.usage, critical=True) \
            .add_extension(public_id, critical=False)
        if not is_root:
            builder.add_extension(
                x509
                .AuthorityKeyIdentifier
                .from_issuer_subject_key_identifier(
                    self.root_certificate
                    .x509_certificate
                    .extensions
                    .get_extension_for_class(x509.SubjectKeyIdentifier)
                    .value),
                critical=False)
        return builder.sign(private_key, hashes.SHA256())

    @staticmethod
    def from_json(*,
            certificate_data: dict,
            timestamp: int,
            keys_cache: dict,
            certificates_cache: dict):
        name=certificate_data[FIELD_C_NAME]
        days_valid=certificate_data[FIELD_C_VALID]
        subject=Certificate._subject(certificate_data[FIELD_C_SUBJ])
        key_id=certificate_data[FIELD_C_KEY]
        root_id=certificate_data[FIELD_C_ROOT]
        sign_other=certificate_data[FIELD_C_SIGN_OTHER]
        max_subordinates=certificate_data[FIELD_C_MAX_SUBS]
        is_child=root_id > 0

        # Errors.
        if sign_other and max_subordinates == 0:
            Certificate._raise_leafed_parent()
        if not sign_other and max_subordinates != 0:
            Certificate._raise_open_leaf()
        if not keys_cache.__contains__(key_id):
            raise ValueError('Cannot find signing key with id "{}" for '
                             'certificate with id "{}"'
            .format(key_id, certificate_data[FIELD_C_ID]))
        if is_child and not certificates_cache.__contains__(root_id):
            raise ValueError('Cannot find parent certificate with id "{}" for '
                             'certificate with id "{}"'
            .format(root_id, certificate_data[FIELD_C_ID]))

        root_cert=certificates_cache[root_id] if root_id > 0 else None
        return Certificate(
            name=name,
            timestamp=timestamp,
            days_valid=days_valid,
            subject=subject,
            key=keys_cache[key_id],
            sign_other=sign_other,
            max_subordinates=max_subordinates,
            root_certificate=root_cert)

    @staticmethod
    def _subject(subject_data: dict) -> Subject:
        """Returns a `Subject` representing the JSON data passed."""
        return Subject(
            country=subject_data[FIELD_C_S_COUNTRY],
            province=subject_data[FIELD_C_S_PROVINCE],
            locality=subject_data[FIELD_C_S_CITY],
            organization=subject_data[FIELD_C_S_ORG],
            org_unit=subject_data[FIELD_C_S_ORG_UNIT],
            common_name=subject_data[FIELD_C_S_CN],
            email=subject_data[FIELD_C_S_EMAIL])

    def write(self, outdir: str):
        """Writes this certificate to a file in the `outdir` folder."""
        if not os.path.isdir(outdir):
            raise NotADirectoryError(outdir)
        else:
            path=os.path.join(outdir, self._file_name())
            with open(path, "wb") as file:
                file.write(self.x509_certificate.public_bytes(Encoding.PEM))
        return

    def _file_name(self):
        """The file name (with extension, without path) for this certificate."""
        return \
            FILE_SEP_EXT.join([
                FILE_SEP_LARGE.join([
                    str(self.timestamp),
                    FILE_SEP_SMALL.join([
                        FILE_PREFFIX_CERTIFICATE,
                        self.name
                    ])
                ]),
                FILE_EXT_CERT
            ])

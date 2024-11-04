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
from src.log import Log
from src.model.key import Ed25519Key
from src.model.key import KeyOutputs
from src.model.key import RsaKey
from src.primitives import ERR_EMPTY_KEYSET
from src.primitives import FIELD_K_ED25519
from src.primitives import FIELD_K_ID
from src.primitives import FIELD_K_NAME
from src.primitives import FIELD_K_RSA
from src.primitives import FIELD_K_SECRET
from src.primitives import FIELD_K_SIZE


class KeySet:
    def __init__(self, *,
            log: Log,
            timestamp: int,
            name: str,
            rsa_key: RsaKey | None,
            ed25519_key: Ed25519Key | None):
        if rsa_key is None and ed25519_key is None:
            log.e(ValueError(ERR_EMPTY_KEYSET))
        self.timestamp=timestamp
        self.name=name
        self.rsa_key=rsa_key
        self.ed25519_key=ed25519_key

    @staticmethod
    def from_json(log: Log, timestamp: int, keyset_data: dict):
        has_rsa=keyset_data.__contains__(FIELD_K_RSA)
        has_ed=keyset_data.__contains__(FIELD_K_ED25519)
        if has_rsa:
            rsa_data=keyset_data[FIELD_K_RSA]
            rsa_key=RsaKey(
                log=log,
                key_id=rsa_data[FIELD_K_ID],
                size=rsa_data[FIELD_K_SIZE],
                secret=rsa_data[FIELD_K_SECRET],
                outputs=KeyOutputs.from_key(rsa_data))
        else:
            rsa_key=None
        if has_ed:
            ed_data=keyset_data[FIELD_K_ED25519]
            ed25519_key=Ed25519Key(
                log=log,
                key_id=ed_data[FIELD_K_ID],
                secret=ed_data[FIELD_K_SECRET],
                outputs=KeyOutputs.from_key(ed_data))
        else:
            ed25519_key=None
        return KeySet(
            log=log,
            timestamp=timestamp,
            name=keyset_data[FIELD_K_NAME],
            rsa_key=rsa_key,
            ed25519_key=ed25519_key)

    @staticmethod
    def all_from_json(log: Log, timestamp: int, keysets_data: dict):
        keysets=[]
        for keyset_data in keysets_data:
            keysets.append(KeySet.from_json(
                log=log,
                timestamp=timestamp,
                keyset_data=keyset_data))
        return keysets

    def write(self, outdir: str):
        if self.rsa_key is not None:
            self.rsa_key.write(
                name=self.name,
                timestamp=self.timestamp,
                outdir=outdir)
        if self.ed25519_key is not None:
            self.ed25519_key.write(
                name=self.name,
                timestamp=self.timestamp,
                outdir=outdir)

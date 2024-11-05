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
import json
import os
from math import floor
from time import time

from src.arg_parser import get_parser
from src.log import Log
from src.log import LogLevel
from src.model.certificate import Certificate
from src.model.keyset import KeySet
from src.primitives import ERR_PATH_NOFILE
from src.primitives import FIELD_C_ID
from src.primitives import FIELD_C_KEY
from src.primitives import FIELD_C_ROOT
from src.primitives import FIELD_CERTS
from src.primitives import FIELD_KEYSETS


def start_app():
    parser=get_parser()
    args=parser.parse_args()
    args.verbosity=LogLevel[args.verbosity.lower()]
    if not os.path.isfile(args.config_file):
        raise parser.error(ERR_PATH_NOFILE.format(args.config_file))
    elif not os.path.isdir(args.output_dir):
        os.mkdir(args.output_dir)
    else:
        _process_data(args.verbosity, args.config_file, args.output_dir)

def _load_json(json_path: str) -> dict:
    with open(json_path, "r") as file:
        return json.load(file)

def _referred_ids(certificates_data: dict, id_field: str) -> list:
    referred_ids=[]
    for certificate_data in certificates_data:
        tested_id=certificate_data[id_field]
        if tested_id <= 0:
            continue
        if not referred_ids.__contains__(tested_id):
            referred_ids.append(tested_id)
    return referred_ids

def _process_data(level: LogLevel, json_path: str, outdir: str):
    log=Log(level)
    all_data=_load_json(json_path)
    certificates_data=all_data[FIELD_CERTS]
    timestamp=floor(time())
    keysets=KeySet.all_from_json(log, timestamp, all_data[FIELD_KEYSETS])
    referred_key_ids=_referred_ids(certificates_data, FIELD_C_KEY)
    keys_cache={}
    for keyset in keysets:
        if keyset.rsa_key is not None:
            rsa_id=keyset.rsa_key.key_id
            is_referred=referred_key_ids.__contains__(rsa_id)
            unsaved=not keys_cache.__contains__(rsa_id)
            if is_referred and unsaved:
                keys_cache[rsa_id]=keyset.rsa_key
        if keyset.ed25519_key is not None:
            ed_id=keyset.ed25519_key.key_id
            is_referred=referred_key_ids.__contains__(ed_id)
            unsaved=not keys_cache.__contains__(ed_id)
            if is_referred and unsaved:
                keys_cache[ed_id]=keyset.ed25519_key
        keyset.write(outdir)

    referred_certificate_ids=_referred_ids(certificates_data, FIELD_C_ROOT)
    certificates_cache={}
    for certificate_data in certificates_data:
        certificate_id=certificate_data[FIELD_C_ID]
        certificate=Certificate.from_json(
            log=log,
            certificate_data=certificate_data,
            timestamp=timestamp,
            keys_cache=keys_cache,
            certificates_cache=certificates_cache)
        is_referred=referred_certificate_ids.__contains__(certificate_id)
        unsaved=not certificates_cache.__contains__(certificate_id)
        if is_referred and unsaved:
            certificates_cache[certificate_id]=certificate
        certificate.write(outdir=outdir)

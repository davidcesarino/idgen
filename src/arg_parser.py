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
from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

from src.log import Log
from src.log import LogLevel
from src.primitives import ABOUT_LICENSE
from src.primitives import ABOUT_VERSION
from src.primitives import APP_CALL
from src.primitives import HELP_CONFIG_FILE
from src.primitives import HELP_DESCRIPTION
from src.primitives import HELP_LICENSE
from src.primitives import HELP_LOG_LEVEL1
from src.primitives import HELP_OUTDIR
from src.primitives import HELP_VERSION


def get_parser() -> ArgumentParser:
    arg_parser = ArgumentParser(
        prog=APP_CALL,
        description=HELP_DESCRIPTION,
        formatter_class=RawDescriptionHelpFormatter)
    arg_parser.add_argument(
        "-l", "--license",
        help=HELP_LICENSE,
        action='version',
        version=ABOUT_LICENSE)
    arg_parser.add_argument(
        "-a", "--about",
        help=HELP_VERSION,
        action='version',
        version=ABOUT_VERSION)
    arg_parser.add_argument("-v",
        help=HELP_LOG_LEVEL1.format(Log.LEVEL_DEFAULT.name),
        type=str,
        action="store",
        choices=tuple(level.name.lower() for level in LogLevel),
        default=Log.LEVEL_DEFAULT.name.lower(),
        dest="verbosity")
    arg_parser.add_argument(
        "config_file",
        help=HELP_CONFIG_FILE)
    arg_parser.add_argument(
        "output_dir",
        help=HELP_OUTDIR)
    return arg_parser

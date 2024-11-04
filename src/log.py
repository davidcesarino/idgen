import enum
from functools import total_ordering
from sys import stdout


@total_ordering
class LogLevel(enum.Enum):
    error=0
    warning=1
    info=2
    debug=3

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class Log:
    LEVEL_DEFAULT=LogLevel.warning

    def __init__(self, level: LogLevel):
        self.level=Log.LEVEL_DEFAULT if level is None else level

    def e(self, exception: Exception):
        raise exception

    def w(self, msg: str):
        if self.level >= LogLevel.warning:
            print(f'[WARNING] {msg}', file=stdout)

    def i(self, msg: str):
        if self.level >= LogLevel.info:
            print(f'[INFO] {msg}', file=stdout)

    def d(self, msg: str):
        if self.level >= LogLevel.debug:
            print(f'[DEBUG] {msg}', file=stdout)

    def always(self, msg: str):
        print(f'[MANDATORY] {msg}', file=stdout)




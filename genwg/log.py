import logging
import sys


class ANSIColors:
    RES = "\033[0;39m"

    LBLK = "\033[0;30m"
    LRED = "\033[0;31m"
    LGRN = "\033[0;32m"
    LYEL = "\033[0;33m"
    LBLU = "\033[0;34m"
    LMGN = "\033[0;35m"
    LCYN = "\033[0;36m"
    LWHI = "\033[0;37m"

    BBLK = "\033[1;30m"
    BRED = "\033[1;31m"
    BGRN = "\033[1;32m"
    BYEL = "\033[1;33m"
    BBLU = "\033[1;34m"
    BMGN = "\033[1;35m"
    BCYN = "\033[1;36m"
    BWHI = "\033[1;37m"

    def __init__(self):
        pass


c = ANSIColors()


class ShutdownHandler(logging.StreamHandler):
    def emit(self, record):
        if record.levelno >= logging.ERROR:
            sys.exit(1)


class GenWGFormatter(logging.Formatter):
    _FMT_DATE = "%H:%M:%S"
    _FMT_BEGIN = f"{c.BBLK}["
    _FMT_END = f"{c.BBLK}]{c.RES}"

    _FORMATS = {
        logging.NOTSET: c.LCYN,
        logging.DEBUG: c.BWHI,
        logging.INFO: c.BBLU,
        logging.WARNING: c.LGRN,
        logging.ERROR: c.LRED,
        logging.CRITICAL: c.LRED,
    }

    def format(self, record):
        finfmt = f"{self._FMT_BEGIN}{self._FORMATS.get(record.levelno)}"
        finfmt += f"%(levelname)-.1s{self._FMT_END} %(message)s"

        return logging.Formatter(
            fmt=finfmt, datefmt=self._FMT_DATE, validate=True
        ).format(record)


def set_root_logger(debug=False):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    formatter = GenWGFormatter()
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.addHandler(ShutdownHandler())

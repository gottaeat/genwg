import argparse
import logging

from . import __version__ as pkg_version
from .config import ConfigYAML
from .genfiles import GenFiles
from .log import set_root_logger


class CLI:
    def __init__(self):
        self.config_file = None
        self.debug = None
        self.logger = None

    def _gen_args(self):
        parser_desc = f"wireguard config generator, ver. {pkg_version}"
        parser_c_help = "configuration file."
        parser_d_help = "enable debugging."

        parser = argparse.ArgumentParser(description=parser_desc)
        parser.add_argument("-c", type=str, required=True, help=parser_c_help)
        parser.add_argument("-d", dest="debug", action="store_true", help=parser_d_help)
        args = parser.parse_args()

        self.config_file = args.c
        self.debug = args.debug

    def run(self):
        # parse args
        self._gen_args()

        # create root logger and init our own
        set_root_logger(self.debug)
        self.logger = logging.getLogger("genwg")

        # action
        self.logger.info("started genwg ver. %s", pkg_version)

        # parse yaml
        config = ConfigYAML(self.config_file, self.logger)
        config.run()

        # generate files
        genfiles = GenFiles(config, self.logger)
        genfiles.run()


def run():
    c = CLI()
    c.run()

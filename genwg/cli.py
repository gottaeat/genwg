import argparse
import logging

from .log import ShutdownHandler
from .log import GenWGFormatter

from .config import ConfigYAML
from .genfiles import GenFiles


# pylint: disable=too-few-public-methods
class CLI:
    def __init__(self):
        self.config_file = None
        self.debug = None

        self.logger = None

    def _gen_args(self):
        parser_desc = "WireGuard client and server configuartion generator."
        parser_c_help = "Configuration YAML file."
        parser_d_help = "Enable debugging."

        parser = argparse.ArgumentParser(description=parser_desc)
        parser.add_argument("-c", type=str, required=True, help=parser_c_help)
        parser.add_argument("-d", dest="debug", action="store_true", help=parser_d_help)
        args = parser.parse_args()

        self.config_file = args.c
        self.debug = args.debug

    def run(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG if self.debug else logging.INFO)

        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG if self.debug else logging.INFO)

        handler.setFormatter(GenWGFormatter())

        self.logger.addHandler(handler)
        self.logger.addHandler(ShutdownHandler())

        self.logger.info("started genwg")

        self._gen_args()

        config = ConfigYAML(self.config_file)
        config.logger = self.logger
        config.parse_yaml()

        genfiles = GenFiles()
        genfiles.clients = config.clients
        genfiles.servers = config.servers
        genfiles.udp2raw = config.udp2raw
        genfiles.bind = config.bind

        genfiles.logger = self.logger

        genfiles.run()


def run():
    # pylint: disable=invalid-name
    c = CLI()
    c.run()

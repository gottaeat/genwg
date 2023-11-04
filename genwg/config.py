import ipaddress
import os

import yaml

from .util import gen_wg_priv, gen_wg_pub


class ClientConfig:
    def __init__(self):
        name = None
        priv = None
        pub = None
        tcp = None
        bind = None


class ServerConfig:
    def __init__(self):
        proto = None
        name = None
        priv = None
        pub = None
        ip = None
        port = None
        net = None
        mtu = None


class UDP2RAWConfig:
    def __init__(self):
        secret = None
        port = None


class ConfigYAML:
    def __init__(self, config_file):
        self.config_file = config_file

        self.logger = None

        self.clients = []
        self.servers = []
        self.udp2raw = None

    def parse_yaml(self):
        self.logger.info("parsing configuration")

        if os.path.isfile(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as yaml_file:
                    yaml_parsed = yaml.load(yaml_file.read(), Loader=yaml.Loader)
            # pylint: disable=broad-exception-caught
            except Exception:
                self.logger.exception("%s parsing has failed", self.config_file)
        else:
            self.logger.error("%s is not a file", self.config_file)

        self.logger.info("parsing servers")

        try:
            servers = yaml_parsed["servers"]
        except KeyError:
            self.logger.exception("server section in the YAML file is missing")

        server_must_have = ["name", "proto", "ip", "port", "net", "mtu"]

        for server in servers:
            for item in server_must_have:
                if item not in server.keys():
                    self.logger.error("%s is missing from the YAML.", item)

            svconf = ServerConfig()
            svconf.name = str(server["name"])

            svconf.proto = str(server["proto"]).lower()
            if svconf.proto not in ["tcp", "udp"]:
                self.logger.error("proto must be either tcp or udp")

            try:
                svconf.priv = str(server["priv"])
            except KeyError:
                svconf.priv = gen_wg_priv()

            if svconf.priv is None:
                svconf.priv = gen_wg_priv()

            svconf.pub = gen_wg_pub(f"{svconf.priv.encode('utf-8')}\n")

            try:
                svconf.ip = ipaddress.ip_address(server["ip"])
            except ValueError:
                self.logger.exception("invalid ip address")

            try:
                svconf.port = int(server["port"])
            except ValueError:
                self.logger.exception("invalid port")

            try:
                svconf.net = ipaddress.ip_network(server["net"], strict=False)
            except ValueError:
                self.logger.exception("invalid network")

            if svconf.net.prefixlen == 32:
                self.logger.exception("network cannot be a /32")

            try:
                svconf.mtu = int(server["mtu"])
            except ValueError:
                self.logger.exception("invalid mtu")

            if svconf.proto == "udp" and svconf.mtu > 1460:
                self.logger.error("mtu cannot be greater than 1460")

            if svconf.proto == "tcp" and svconf.mtu > 1340:
                self.logger.error("mtu cannot be greater than 1340 w/ udp2raw")

            self.servers.append(svconf)

        self.logger.info("parsing clients")

        try:
            clients = yaml_parsed["clients"]
        except KeyError:
            self.logger.exception("client section in the YAML file is missing")

        client_must_have = ["name"]

        for client in clients:
            for item in client_must_have:
                if item not in client.keys():
                    self.logger.error("%s is missing from the YAML.", item)

            clconf = ClientConfig()
            clconf.name = str(client["name"])

            try:
                clconf.priv = str(client["priv"])
            except KeyError:
                clconf.priv = gen_wg_priv()

            if clconf.priv is None:
                clconf.priv = gen_wg_priv()

            clconf.pub = gen_wg_pub(f"{clconf.priv.encode('utf-8')}\n")

            try:
                if type(client["tcp"]).__name__ != "bool":
                    self.logger.error("tcp must be a bool")
            except KeyError:
                clconf.tcp = False

            try:
                if type(client["bind"]).__name__ != "bool":
                    self.logger.error("bind must be a bool")
            except KeyError:
                clconf.bind = False

            self.clients.append(clconf)

        for server in self.servers:
            if server.proto == "tcp":
                self.logger.info("found a server that requires udp2raw")
                need_udp2raw = True
                break

        if need_udp2raw:
            self.logger.info("parsing udp2raw")

            try:
                udp2raw = yaml_parsed["udp2raw"]
            except KeyError:
                self.logger.exception("udp2raw section in the YAML file is missing")

            udp2raw_must_have = ["port"]

            for item in udp2raw_must_have:
                if item not in udp2raw.keys():
                    self.logger.error("%s is missing from the YAML.", item)

            u2rconf = UDP2RAWConfig()

            try:
                u2rconf.port = int(udp2raw["port"])
            except ValueError:
                self.logger.exception("invalid udp2raw port")

            self.udp2raw = u2rconf

import ipaddress
import os
import re
import secrets
import subprocess

import yaml


# pylint: disable=too-few-public-methods
class ClientConfig:
    def __init__(self):
        self.name = None
        self.priv = None
        self.pub = None
        self.tcp = None
        self.bind = None


# pylint: disable=too-many-instance-attributes
class ServerConfig:
    def __init__(self):
        self.proto = None
        self.name = None
        self.priv = None
        self.pub = None
        # pylint: disable=invalid-name
        self.ip = None
        self.port = None
        self.net = None
        self.pfx = None
        self.mtu = None
        self.last_ip = None


class UDP2RAWConfig:
    def __init__(self):
        self.secret = None
        self.port = None


class BINDConfig:
    def __init__(self):
        self.tmp_dir = None
        self.root_zone = None


class ConfigYAML:
    def __init__(self, config_file):
        self.config_file = config_file
        self.want_bind = None

        self.logger = None

        self.clients = []
        self.servers = []
        self.udp2raw = None
        self.bind = None

    def gen_wg_priv(self):
        try:
            proc = subprocess.run(["wg", "genkey"], check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            self.logger.error("%s", exc.stderr.decode("utf-8"))

        return proc.stdout.decode("utf-8").rstrip("\n")

    def gen_wg_pub(self, priv_key):
        priv_key = f"{priv_key}\n".encode("utf-8")

        try:
            proc = subprocess.run(
                ["wg", "pubkey"], input=priv_key, check=True, capture_output=True
            )
        except subprocess.CalledProcessError as exc:
            self.logger.error("%s", exc.stderr.decode("utf-8"))

        return proc.stdout.decode("utf-8").rstrip("\n")

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
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

            if len(svconf.name) >= 16 or " " in svconf.name or "/" in svconf.name:
                self.logger.error("%s is not a valid interface name.", svconf.name)

            zone_regex = re.compile(r"^[a-zA-Z0-9.-]{1,255}$")

            if not zone_regex.match(svconf.name):
                self.logger.error("%s is not a valid zone owner name.", svconf.name)

            svconf.proto = str(server["proto"]).lower()
            if svconf.proto not in ["tcp", "udp"]:
                self.logger.error("proto must be either tcp or udp")

            try:
                svconf.priv = str(server["priv"])
            except KeyError:
                svconf.priv = self.gen_wg_priv()

            if svconf.priv == "None":
                svconf.priv = self.gen_wg_priv()

            svconf.pub = self.gen_wg_pub(svconf.priv)

            try:
                svconf.ip = ipaddress.ip_address(server["ip"])
            except ValueError:
                self.logger.exception("invalid ip address")

            try:
                svconf.port = int(server["port"])
            except ValueError:
                self.logger.exception("invalid port")

            try:
                yaml_net = ipaddress.ip_network(server["net"])
            except ValueError:
                self.logger.exception("invalid network")

            svconf.net = yaml_net.network_address
            svconf.pfx = yaml_net.prefixlen

            svconf.last_ip = svconf.net + 1

            if svconf.pfx == 32:
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

            subd_regex = re.compile(r"^[a-zA-Z0-9-]{1,63}$")

            if not subd_regex.match(clconf.name):
                self.logger.error("%s cannot be used as a subdomain.", clconf.name)

            try:
                clconf.priv = str(client["priv"])
            except KeyError:
                clconf.priv = self.gen_wg_priv()

            if clconf.priv == "None":
                clconf.priv = self.gen_wg_priv()

            clconf.pub = self.gen_wg_pub(clconf.priv)

            try:
                if type(client["tcp"]).__name__ != "bool":
                    self.logger.error("tcp must be a bool")
            except KeyError:
                pass

            try:
                clconf.tcp = client["tcp"]
            except KeyError:
                clconf.tcp = False

            try:
                if type(client["bind"]).__name__ != "bool":
                    self.logger.error("bind must be a bool")
            except KeyError:
                pass

            try:
                clconf.bind = client["bind"]
            except KeyError:
                clconf.bind = False

            self.clients.append(clconf)

        need_udp2raw = False
        for server in self.servers:
            if server.proto == "tcp":
                self.logger.info("found a server that requires udp2raw")
                need_udp2raw = True
                break

        if need_udp2raw:
            self.logger.info("parsing udp2raw")

            try:
                udp2raw = yaml_parsed["udp2raw"][0]
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

            try:
                u2rconf.secret = str(udp2raw["secret"])
            except KeyError:
                u2rconf.secret = secrets.token_urlsafe(12)

            if u2rconf.secret == "None":
                u2rconf.secret = secrets.token_urlsafe(12)

            self.udp2raw = u2rconf

        # bind
        if self.want_bind:
            self.logger.info("bind zone file generation requested")

        client_needs_bind = False
        for client in self.clients:
            if client.bind:
                self.logger.info("found a client that requires bind")
                client_needs_bind = True
                break

        if self.want_bind or client_needs_bind:
            self.logger.info("parsing bind")

            try:
                bind = yaml_parsed["bind"][0]
            except KeyError:
                self.logger.exception("bind section in the YAML file is missing")

            bindconf = BINDConfig()

            # tmp_dir
            if self.want_bind and "tmp_dir" not in bind.keys():
                self.logger.error("tmp_dir is missing from the YAML.")

            try:
                bindconf.tmp_dir = str(bind["tmp_dir"])
            except ValueError:
                self.logger.exception("invalid tmp_dir")

            # root_zone
            if client_needs_bind and "root_zone" not in bind.keys():
                self.logger.error("root_zone is missing from the YAML.")

            try:
                bindconf.root_zone = str(bind["root_zone"])
            except ValueError:
                self.logger.exception("invalid root_zone")

            self.bind = bindconf

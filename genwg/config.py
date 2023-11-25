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
        self.android = None


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
        self.arpa_ptr = None
        self.mtu = None
        self.last_ip = None


class UDP2RAWConfig:
    def __init__(self):
        self.secret = None
        self.port = None


class BINDConfig:
    def __init__(self):
        self.hostname = None
        self.named_conf_path = None
        self.root_zone_file = None


class ConfigYAML:
    def __init__(self, config_file):
        self.config_file = config_file
        self.want_bind = None

        self.logger = None

        self.clients = []
        self.servers = []
        self.udp2raw = None
        self.bind = None

        self.yaml_parsed = None

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

    # ServerConfig()
    # pylint: disable=too-many-branches,too-many-statements
    def _parse_servers(self):
        self.logger.info("parsing servers")

        try:
            servers = self.yaml_parsed["servers"]
        except KeyError:
            self.logger.exception("server section in the YAML file is missing")

        server_must_have = ["name", "proto", "ip", "port", "net", "mtu"]

        for server in servers:
            for item in server_must_have:
                if item not in server.keys():
                    self.logger.error("%s is missing from the YAML", item)
                if not server[item]:
                    self.logger.error("%s cannot be blank", item)

            svconf = ServerConfig()

            # server.name
            svconf.name = str(server["name"])

            if len(svconf.name) >= 16 or " " in svconf.name or "/" in svconf.name:
                self.logger.error("%s is not a valid interface name", svconf.name)

            zone_regex = re.compile(r"^[a-zA-Z0-9.-]{1,255}$")

            if not zone_regex.match(svconf.name):
                self.logger.error("%s is not a valid zone owner name", svconf.name)

            # server.proto
            svconf.proto = str(server["proto"]).lower()

            if svconf.proto not in ["tcp", "udp"]:
                self.logger.error("proto must be either tcp or udp")

            # server.priv
            try:
                svconf.priv = str(server["priv"])
            except KeyError:
                svconf.priv = self.gen_wg_priv()

            if svconf.priv == "None":
                svconf.priv = self.gen_wg_priv()

            # server.pub
            svconf.pub = self.gen_wg_pub(svconf.priv)

            # server.ip
            try:
                svconf.ip = ipaddress.ip_address(server["ip"])
            except ValueError:
                self.logger.exception("invalid ip address")

            # server.port
            try:
                svconf.port = int(server["port"])
            except ValueError:
                self.logger.exception("invalid port")

            if svconf.port <= 0 or svconf.port > 65535:
                self.logger.error("%s is not a valid port number.", svconf.port)

            # server.net
            try:
                yaml_net = ipaddress.ip_network(server["net"])
            except ValueError:
                self.logger.exception("invalid network")

            svconf.net = yaml_net.network_address

            # server.pfx
            svconf.pfx = yaml_net.prefixlen

            if svconf.pfx == 32:
                self.logger.error("network cannot be a /32")

            # server.arpa_ptr
            svconf.arpa_ptr = re.sub(
                rf"^0/{svconf.pfx}\.", "", str(yaml_net.reverse_pointer)
            )

            # server.last_ip
            svconf.last_ip = svconf.net + 1

            # server.mtu
            try:
                svconf.mtu = int(server["mtu"])
            except ValueError:
                self.logger.exception("invalid mtu")

            if svconf.proto == "udp" and svconf.mtu > 1460:
                self.logger.error("mtu cannot be greater than 1460")

            if svconf.proto == "tcp" and svconf.mtu > 1340:
                self.logger.error("mtu cannot be greater than 1340 w/ udp2raw")

            self.servers.append(svconf)

    # ClientConfig()
    # pylint: disable=too-many-branches
    def _parse_clients(self):
        self.logger.info("parsing clients")

        try:
            clients = self.yaml_parsed["clients"]
        except KeyError:
            self.logger.exception("client section in the YAML file is missing")

        client_must_have = ["name"]

        for client in clients:
            for item in client_must_have:
                if item not in client.keys():
                    self.logger.error("%s is missing from the YAML", item)
                if not client[item]:
                    self.logger.error("%s cannot be empty", item)

            clconf = ClientConfig()

            # client.name
            clconf.name = str(client["name"])

            subd_regex = re.compile(r"^[a-zA-Z0-9-]{1,63}$")

            if not subd_regex.match(clconf.name):
                self.logger.error("%s cannot be used as a subdomain", clconf.name)

            # client.priv
            try:
                clconf.priv = str(client["priv"])
            except KeyError:
                clconf.priv = self.gen_wg_priv()

            if clconf.priv == "None":
                clconf.priv = self.gen_wg_priv()

            # client.pub
            clconf.pub = self.gen_wg_pub(clconf.priv)

            # client.tcp
            try:
                if type(client["tcp"]).__name__ != "bool":
                    self.logger.error("tcp must be a bool")
            except KeyError:
                pass

            try:
                clconf.tcp = client["tcp"]
            except KeyError:
                clconf.tcp = False

            # client.bind
            try:
                if type(client["bind"]).__name__ != "bool":
                    self.logger.error("bind must be a bool")
            except KeyError:
                pass

            try:
                clconf.bind = client["bind"]
            except KeyError:
                clconf.bind = False

            # client.android
            try:
                if type(client["android"]).__name__ != "bool":
                    self.logger.error("android must be a bool")
            except KeyError:
                pass

            try:
                clconf.android = client["android"]
            except KeyError:
                clconf.android = False

            # colission
            if clconf.android and clconf.bind:
                self.logger.error("android clients do not support bind")

            self.clients.append(clconf)

    # UDP2RAWConfig()
    def _parse_udp2raw(self):
        need_udp2raw = False
        for server in self.servers:
            if server.proto == "tcp":
                self.logger.info("found a server that requires udp2raw")
                need_udp2raw = True
                break

        if need_udp2raw:
            self.logger.info("parsing udp2raw")

            try:
                udp2raw = self.yaml_parsed["udp2raw"][0]
            except KeyError:
                self.logger.exception("udp2raw section in the YAML file is missing")
            except TypeError:
                self.logger.exception(
                    "udp2raw section cannot be specified then left blank"
                )

            udp2raw_must_have = ["port"]

            for item in udp2raw_must_have:
                if item not in udp2raw.keys():
                    self.logger.error("%s is missing from the YAML", item)
                if not udp2raw[item]:
                    self.logger.error("%s cannot be empty", item)

            u2rconf = UDP2RAWConfig()

            # udp2raw.port
            try:
                u2rconf.port = int(udp2raw["port"])
            except ValueError:
                self.logger.exception("invalid udp2raw port")

            if u2rconf.port <= 0 or u2rconf.port > 65535:
                self.logger.error("%s is not a valid port number.", u2rconf.port)

            # udp2raw.secret
            try:
                u2rconf.secret = str(udp2raw["secret"])
            except KeyError:
                u2rconf.secret = secrets.token_urlsafe(12)

            if u2rconf.secret == "None":
                u2rconf.secret = secrets.token_urlsafe(12)

            self.udp2raw = u2rconf

    # BINDConfig()
    def _parse_bind(self):
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
                bind = self.yaml_parsed["bind"][0]
            except KeyError:
                self.logger.exception("bind section in the YAML file is missing")
            except TypeError:
                self.logger.exception(
                    "bind section cannot be specified then left blank"
                )

            bindconf = BINDConfig()

            # want_bind handling
            bind_must_have = ["hostname", "named_conf_path"]

            for item in bind_must_have:
                if item not in bind.keys():
                    self.logger.error("%s is missing from the YAML", item)
                if not bind[item]:
                    self.logger.error("%s cannot be empty", item)

            # bind.hostname
            bindconf.hostname = str(bind["hostname"])

            # bind.named_conf_path
            bindconf.named_conf_path = str(bind["named_conf_path"])

            # client.bind handling
            if client_needs_bind:
                if "root_zone_file" not in bind.keys():
                    self.logger.error("root_zone_file is missing from the YAML")
                if not bind["root_zone_file"]:
                    self.logger.error("root_zone_file cannot be empty")

            # bind.root_zone_file
            bindconf.root_zone_file = str(bind["root_zone_file"])

            self.bind = bindconf

    def parse_yaml(self):
        # yaml->dict
        self.logger.info("loading yaml")

        if os.path.isfile(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as yaml_file:
                    self.yaml_parsed = yaml.load(yaml_file.read(), Loader=yaml.Loader)
            # pylint: disable=bare-except
            except:
                self.logger.exception("%s parsing has failed", self.config_file)
        else:
            self.logger.error("%s is not a file", self.config_file)

        self._parse_servers()
        self._parse_clients()
        self._parse_udp2raw()
        self._parse_bind()

import ipaddress
import os
import re
import secrets
import subprocess

import yaml

from .log import ANSIColors

ac = ANSIColors()


class UDP2RAW:
    def __init__(self):
        self.port = None
        self.secret = None


class Named:
    def __init__(self):
        self.hostname = None
        self.conf_dir = None


class Server:
    def __init__(self):
        self.name = None
        self.priv = None
        self.pub = None
        self.ip = None
        self.port = None
        self.net = None
        self.pfx = None
        self.last_ip = None
        self.udp2raw = None
        self.mtu = None
        self.named = None
        self.arpa_ptr = None
        self.extra_address = []
        self.clients = []


class Client:
    def __init__(self):
        self.name = None
        self.udp2raw_log_path = None
        self.priv = None
        self.pub = None
        self.android = None
        self.wgquick_path = None
        self.udp2raw_path = None
        self.bind = False
        self.root_zone_file = None
        self.append_extra = False
        self.extra_allowed = []


class ConfigYAML:
    def __init__(self, config_file, parent_logger):
        self.config_file = config_file
        self.logger = parent_logger.getChild(self.__class__.__name__)

        self.yaml_parsed = None

    def _load_yaml(self):
        self.logger.info("loading configuration")

        if os.path.isfile(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as yaml_file:
                    self.yaml_parsed = yaml.load(yaml_file.read(), Loader=yaml.Loader)
            except:
                self.logger.exception("%s parsing has failed", self.config_file)
        else:
            self.logger.error("%s is not a file", self.config_file)

    def _gen_wg_priv(self):
        try:
            proc = subprocess.run(["wg", "genkey"], check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            self.logger.error("%s", exc.stderr.decode("utf-8"))

        return proc.stdout.decode("utf-8").rstrip("\n")

    def _gen_wg_pub(self, priv_key):
        priv_key = f"{priv_key}\n".encode("utf-8")

        try:
            proc = subprocess.run(
                ["wg", "pubkey"], input=priv_key, check=True, capture_output=True
            )
        except subprocess.CalledProcessError as exc:
            self.logger.error("%s", exc.stderr.decode("utf-8"))

        return proc.stdout.decode("utf-8").rstrip("\n")

    def _check_port(self, port):
        try:
            port = int(port)
        except ValueError:
            self.logger.error("invalid port: %s", port)

        if port <= 0 or port > 65535:
            self.logger.error("%s is not a valid port number", port)

        return port

    def _parse_yaml(self):
        self.logger.info("processing servers")

        try:
            servers = self.yaml_parsed["servers"]
        except KeyError:
            self.logger.error("servers section in the YAML file is missing")

        # - - servers - - #
        for server_yaml in servers:
            server = Server()

            # server.name
            try:
                server.name = server_yaml["name"]

                if not server.name:
                    self.logger.error("name cannot be blank")

                if len(server.name) >= 16 or " " in server.name or "/" in server.name:
                    self.logger.error("%s is not a valid interface name", server.name)

                self.logger.info("%s", f"{ac.BRED}{server.name}{ac.RES}")
            except KeyError:
                self.logger.error("name is missing from the server YAML")

            # prechecks
            for item in ["ip", "port", "net", "mtu", "clients"]:
                if item not in server_yaml.keys():
                    self.logger.error("%s is missing from the server YAML", item)
                if not server_yaml[item]:
                    self.logger.error("%s cannot be blank", item)

            # server.priv
            try:
                if not server_yaml["priv"]:
                    self.logger.error("priv cannot be blank")

                server.priv = server_yaml["priv"]
            except KeyError:
                server.priv = self._gen_wg_priv()

            # server.pub (internal)
            server.pub = self._gen_wg_pub(server.priv)

            # server.ip
            try:
                server.ip = ipaddress.ip_address(server_yaml["ip"])
            except ValueError:
                self.logger.error("invalid ip address")

            # server.port
            server.port = self._check_port(server_yaml["port"])

            # server.net
            try:
                yaml_net = ipaddress.ip_network(server_yaml["net"])
            except ValueError:
                self.logger.error("invalid net")

            server.net = yaml_net.network_address

            # server.pfx (internal)
            server.pfx = yaml_net.prefixlen

            if server.pfx == 32:
                self.logger.error("net prefix length cannot be 32")

            # server.last_ip (internal)
            server.last_ip = server.net + 1

            # server.udp2raw
            if "udp2raw" in server_yaml.keys():
                server.udp2raw = UDP2RAW()

                # server.udp2raw.port
                try:
                    if not server_yaml["udp2raw"]["port"]:
                        self.logger.error("udp2raw port cannot be blank")

                    server.udp2raw.port = self._check_port(
                        server_yaml["udp2raw"]["port"]
                    )
                except KeyError:
                    self.logger.error("port is missing from the udp2raw YAML")

                # server.udp2raw.secret
                try:
                    if not server_yaml["udp2raw"]["secret"]:
                        server.udp2raw.secret = secrets.token_urlsafe(12)
                    else:
                        server.udp2raw.secret = server_yaml["udp2raw"]["secret"]
                except KeyError:
                    server.udp2raw.secret = secrets.token_urlsafe(12)

            # server.mtu
            try:
                server.mtu = int(server_yaml["mtu"])
            except ValueError:
                self.logger.error("invalid mtu")

            if server.udp2raw and server.mtu > 1340:
                self.logger.error("mtu cannot be greater than 1340 w/ udp2raw")
            else:
                if server.mtu > 1460:
                    self.logger.error("mtu cannot be greater than 1460")

            # server.named
            if "named" in server_yaml.keys():
                for item in ["hostname", "conf_dir"]:
                    try:
                        if item not in server_yaml["named"].keys():
                            self.logger.error("%s is missing from the named YAML", item)
                    except AttributeError:
                        self.logger.error("named cannot be blank")

                    if not server_yaml["named"][item]:
                        self.logger.error("%s cannot be blank", item)

                zone_regex = re.compile(r"^[a-zA-Z0-9.-]{1,255}$")

                if not zone_regex.match(server.name):
                    self.logger.error("%s is not a valid zone owner name", server.name)

                server.named = Named()

                # server.named.hostname
                server.named.hostname = server_yaml["named"]["hostname"]

                # server.named.named_conf_dir
                server.named.conf_dir = server_yaml["named"]["conf_dir"]

                # server.arpa_ptr (internal)
                server.arpa_ptr = re.sub(
                    rf"^0/{server.pfx}\.", "", str(yaml_net.reverse_pointer)
                )

            # server.extra_address
            if "extra_address" in server_yaml.keys():
                if not server_yaml["extra_address"]:
                    self.logger.error("extra_address cannot be blank")

                for index, item in enumerate(server_yaml["extra_address"]):
                    try:
                        server_yaml["extra_address"][index] = ipaddress.ip_network(item)
                    except ValueError:
                        self.logger.error("invalid ip address: %s", item)

                    if server_yaml["extra_address"][index].prefixlen != 32:
                        self.logger.error("%s is not a /32", item)

                server.extra_address = server_yaml["extra_address"]

            # - - clients - - #
            for client_yaml in server_yaml["clients"]:
                client = Client()

                # client.name
                try:
                    client.name = client_yaml["name"]

                    if not client.name:
                        self.logger.error("name cannot be blank")

                    self.logger.info("%s", f"{ac.BWHI}→ {ac.BGRN}{client.name}{ac.RES}")
                except KeyError:
                    self.logger.error("name is missing from the client YAML")

                # server prechecks
                if server.named:
                    subd_regex = re.compile(r"^[a-zA-Z0-9-]{1,63}$")
                    if not subd_regex.match(client.name):
                        self.logger.error(
                            "%s cannot be used as a subdomain", client.name
                        )

                # client.udp2raw_log_path
                if server.udp2raw:
                    try:
                        if not client_yaml["udp2raw_log_path"]:
                            self.logger.error("udp2raw_log_path cannot be blank")

                        client.udp2raw_log_path = client_yaml["udp2raw_log_path"]
                    except KeyError:
                        self.logger.error(
                            "udp2raw_log_path is missing from the client YAML"
                        )

                # client.priv
                try:
                    if not client_yaml["priv"]:
                        self.logger.error("priv cannot be left blank")

                    client.priv = client_yaml["priv"]
                except KeyError:
                    client.priv = self._gen_wg_priv()

                # client.pub (internal)
                client.pub = self._gen_wg_pub(client.priv)

                # client.android
                try:
                    if type(client_yaml["android"]).__name__ != "bool":
                        self.logger.error("android must be a bool")

                    client.android = client_yaml["android"]
                except KeyError:
                    client.android = False

                # client.wgquick_path + client.udp2raw_path
                if server.udp2raw and client.android:
                    for item in ["wgquick_path", "udp2raw_path"]:
                        if item not in client_yaml.keys():
                            self.logger.error(
                                "%s is missing from the client YAML", item
                            )
                        if not client_yaml[item]:
                            self.logger.error("%s cannot be blank", item)

                    client.wgquick_path = client_yaml["wgquick_path"]
                    client.udp2raw_path = client_yaml["udp2raw_path"]

                # client.bind
                try:
                    if type(client_yaml["bind"]).__name__ != "bool":
                        self.logger.error("bind must be a bool")

                    client.bind = client_yaml["bind"]
                except KeyError:
                    pass

                if client.bind:
                    if client.android:
                        self.logger.error("android clients do not support bind")

                    try:
                        if not client_yaml["root_zone_file"]:
                            self.logger.error("root_zone_file cannot be blank")

                        client.root_zone_file = client_yaml["root_zone_file"]
                    except KeyError:
                        self.logger.error(
                            "root_zone_file is missing from the client YAML"
                        )

                # client.append_extra
                try:
                    if type(client_yaml["append_extra"]).__name__ != "bool":
                        self.logger.error("append_extra must be a bool")

                    client.append_extra = client_yaml["append_extra"]
                except KeyError:
                    pass

                # client.extra_allowed
                try:
                    for address in client_yaml["extra_allowed"]:
                        try:
                            if ipaddress.ip_network(address):
                                pass
                        except ValueError:
                            self.logger.error("invalid network")

                    client.extra_allowed = client_yaml["extra_allowed"]
                except TypeError:
                    self.logger.error("extra_allowed cannot be blank.")
                except KeyError:
                    pass

                # append
                server.clients.append(client)
                self.logger.info(
                    "%s", f"{ac.BWHI}→ {ac.BGRN}{client.name} {ac.BMGN}✓{ac.RES}"
                )

    def run(self):
        self._load_yaml()
        self._parse_yaml()

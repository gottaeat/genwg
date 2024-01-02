import ipaddress
import os
import re
import secrets
import subprocess

import yaml


# pylint: disable=too-many-instance-attributes,too-few-public-methods
class ClientConfig:
    def __init__(self):
        # required
        self.name = None

        # wg keys
        self.priv = None
        self.pub = None

        # faketcp
        self.tcp = None
        self.udp2raw_log_path = None

        # bind
        self.bind = None
        self.root_zone_file = None

        # android
        self.android = None
        self.wgquick_path = None
        self.udp2raw_path = None

        # extra Address and AllowedIPs logic
        self.append_extra = None
        self.extra_allowed = None


# pylint: disable=too-many-instance-attributes,too-few-public-methods
class ServerConfig:
    def __init__(self):
        # required
        self.name = None
        self.proto = None

        # required if --bind for zone SOA
        self.hostname = None
        self.named_conf_path = None

        # required
        self.ip = None  # pylint: disable=invalid-name
        self.port = None
        self.net = None
        self.mtu = None

        # wg keys
        self.priv = None
        self.pub = None

        # udp2raw, required if proto == tcp
        self.udp2raw_secret = None
        self.udp2raw_port = None

        # derived from self.ip
        self.pfx = None
        self.arpa_ptr = None
        self.last_ip = None

        # extra Address and AllowedIPs logic
        self.extra_address = None


class ConfigYAML:
    def __init__(self, config_file):
        self.config_file = config_file
        self.want_bind = None

        self.logger = None

        self.clients = []
        self.servers = []

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

        if self.want_bind:
            for i in "hostname", "named_conf_path":
                server_must_have.append(i)

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

            # --bind
            if self.want_bind:
                # server.hostname
                svconf.hostname = str(server["hostname"])
                # server.named_conf_path
                svconf.named_conf_path = str(server["named_conf_path"])

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

            # server.mtu
            try:
                svconf.mtu = int(server["mtu"])
            except ValueError:
                self.logger.exception("invalid mtu")

            if svconf.proto == "udp" and svconf.mtu > 1460:
                self.logger.error("mtu cannot be greater than 1460")

            if svconf.proto == "tcp" and svconf.mtu > 1340:
                self.logger.error("mtu cannot be greater than 1340 w/ udp2raw")

            # server.priv
            try:
                svconf.priv = str(server["priv"])
            except KeyError:
                svconf.priv = self.gen_wg_priv()

            if svconf.priv == "None":
                svconf.priv = self.gen_wg_priv()

            # udp2raw
            if svconf.proto == "tcp":
                udp2raw_must_have = ["udp2raw_port"]
                for item in udp2raw_must_have:
                    if item not in server.keys():
                        self.logger.error("%s is missing from the YAML", item)
                    if not server[item]:
                        self.logger.error("%s cannot be blank", item)

                # server.udp2raw_port
                try:
                    svconf.udp2raw_port = int(server["udp2raw_port"])
                except ValueError:
                    self.logger.exception("invalid udp2raw port")

                if svconf.udp2raw_port <= 0 or svconf.udp2raw_port > 65535:
                    self.logger.error(
                        "%s is not a valid port number.", svconf.udp2raw_port
                    )

                # server.udp2raw_secret
                try:
                    svconf.udp2raw_secret = str(server["udp2raw_secret"])
                except KeyError:
                    svconf.udp2raw_secret = secrets.token_urlsafe(12)

                if svconf.udp2raw_secret == "None":
                    svconf.udp2raw_secret = secrets.token_urlsafe(12)

            # server.pub
            svconf.pub = self.gen_wg_pub(svconf.priv)

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

            # server.extra_address
            try:
                yaml_extra_addr_list = server["extra_address"]

                for address in yaml_extra_addr_list:
                    try:
                        if ipaddress.ip_network(address).prefixlen != 32:
                            self.logger.error("%s is not a /32.", address)
                    except ValueError:
                        self.logger.exception("invalid network")

                svconf.extra_address = yaml_extra_addr_list
            except TypeError:
                self.logger.exception("extra_address cannot be blank.")
            except KeyError:
                pass

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

            if clconf.tcp:
                tcp_must_have = ["udp2raw_log_path"]
                for item in tcp_must_have:
                    if item not in client.keys():
                        self.logger.error("%s is missing from the YAML", item)
                    if not client[item]:
                        self.logger.error("%s cannot be blank", item)

                # client.udp2raw_log_path
                clconf.udp2raw_log_path = str(client["udp2raw_log_path"])

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

            if clconf.bind:
                bind_must_have = ["root_zone_file"]
                for item in bind_must_have:
                    if item not in client.keys():
                        self.logger.error("%s is missing from the YAML", item)
                    if not client[item]:
                        self.logger.error("%s cannot be blank", item)

                # client.root_zone_file
                clconf.root_zone_file = str(client["root_zone_file"])

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

            if clconf.android:
                android_must_have = ["wgquick_path", "udp2raw_path"]
                for item in android_must_have:
                    if item not in client.keys():
                        self.logger.error("%s is missing from the YAML", item)
                    if not client[item]:
                        self.logger.error("%s cannot be blank", item)

                # client.wgquick_path
                clconf.wgquick_path = str(client["wgquick_path"])

                # client.udp2raw_path
                clconf.udp2raw_path = str(client["udp2raw_path"])

            # collision
            if clconf.android and clconf.bind:
                self.logger.error("android clients do not support bind")

            # client.append_extra
            try:
                if type(client["append_extra"]).__name__ != "bool":
                    self.logger.error("append_extra must be a bool")
            except KeyError:
                pass

            try:
                clconf.append_extra = client["append_extra"]
            except KeyError:
                clconf.append_extra = False

            # client.extra_allowed
            try:
                yaml_extra_allow_list = client["extra_allowed"]

                for address in yaml_extra_allow_list:
                    try:
                        if ipaddress.ip_network(address):
                            pass
                    except ValueError:
                        self.logger.exception("invalid network")

                clconf.extra_allowed = yaml_extra_allow_list
            except TypeError:
                self.logger.exception("extra_allowed cannot be blank.")
            except KeyError:
                pass

            self.clients.append(clconf)

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

        client_wants_tcp = False
        server_is_tcp = False

        for client in self.clients:
            if client.tcp:
                client_wants_tcp = True
                break

        for server in self.servers:
            if server.proto == "tcp":
                server_is_tcp = True
                break

        for client in self.clients:
            if client.bind:
                client_wants_bind = True
                break

        if client_wants_bind and not self.want_bind:
            warnmsg = "a client wants bind but none of the servers are\n"
            warnmsg += "configured to serve local zones."

            for line in warnmsg.split("\n"):
                self.logger.warning(line)

        if client_wants_tcp and not server_is_tcp:
            errmsg = "a client requested faketcp support but none of the\n"
            errmsg += "no server is configured to use tcp."

            for line in errmsg.split("\n"):
                self.logger.error(line)

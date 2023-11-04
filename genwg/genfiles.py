import os
import shutil
import time

import yaml


# pylint: disable=too-few-public-methods
class GenFiles:
    def __init__(self):
        self.logger = None

        self.servers = None
        self.clients = None
        self.udp2raw = None
        self.bind = None

    def _create_dirs(self):
        self.logger.info("creating directories")

        for i in ["server", "client"]:
            if os.path.exists(i):
                self.logger.warning(" - collision found, removing")

                try:
                    shutil.rmtree(i)
                except NotADirectoryError:
                    os.remove(i)
            os.mkdir(i)

    def _create_client(self, server, client):
        self.logger.info(
            " - client: %s (tcp: %s, bind: %s)", client.name, client.tcp, client.bind
        )

        conf = f"# - server : {server.name}\n"
        conf += f"# - client : {client.name}\n"
        conf += f"# - private: {client.priv}\n"
        conf += f"# - public : {client.pub}\n"

        conf += "[Interface]\n"
        conf += f"Address = {server.last_ip}/32\n"
        conf += f"PrivateKey = {client.priv}\n"
        conf += f"MTU = {server.mtu}\n\n"

        if client.bind:
            conf += 'PostUp = mkdir -p "/tmp/bind"\n'
            conf += 'PostUp = echo "zone \\".\\" { type forward; forwarders '
            conf += f'{{ {server.net + 1}; }}; }};" '
            conf += '> "/tmp/bind/named.conf.local"\n'
            conf += "PostUp = rndc reload\n"

            conf += 'PreDown = mkdir -p "/tmp/bind"\n'
            conf += 'PreDown = echo "zone \\".\\" { type hint; file '
            conf += f'\\"{self.bind.root_zone}\\"; }};" '
            conf += '> "/tmp/bind/named.conf.local"\n'
            conf += "PreDown = rndc reload\n"
        else:
            conf += f"DNS = {server.net + 1}\n"

        if server.proto == "tcp" and client.tcp:
            conf += f"PreUp = ip route add {server.ip} via `ip route list match "
            conf += "0 table all scope global | awk '{print $3}'` dev `ip route "
            conf += "list match 0 table all scope global | awk '{print $5}'`\n"

            conf += "PreUp = udp2raw -c -l 127.0.0.1:50001 -r "
            conf += f'{server.ip}:{self.udp2raw.port} -k "{self.udp2raw.secret}" '
            conf += "-a >/var/log/udp2raw.log 2>&1 &\n"

            conf += f"PostDown = ip route del {server.ip} via `ip route list match "
            conf += "0 table all scope global | awk '{print $3}'` dev `ip route "
            conf += "list match 0 table all scope global | awk '{print $5}'`\n"

            conf += "PostDown = pkill -15 udp2raw || true\n"

        conf += "\n[Peer]\n"
        conf += f"PublicKey = {server.pub}\n"

        if server.proto == "tcp":
            conf += "Endpoint = 127.0.0.1:50001\n"
        else:
            conf += f"Endpoint = {server.ip}:{server.port}\n"
        conf += "AllowedIPs = 0.0.0.0/0\n"

        if server.proto == "tcp":
            conf += "PersistentKeepalive = 120\n"
        else:
            conf += "PersistentKeepalive = 25\n"

        with open(
            f"./client/{client.name}-{server.name}.conf", "w", encoding="utf-8"
        ) as file:
            file.write(conf)

    def _create_servers(self):
        for server in self.servers:
            self.logger.info("creating server %s (%s)", server.name, server.proto)

            svconf = f"# - server : {server.name}\n"
            svconf += f"# - private: {server.priv}\n"
            svconf += f"# - public : {server.pub}\n\n"
            svconf += "[Interface]\n"
            svconf += f"PrivateKey = {server.priv}\n"
            svconf += f"Address = {server.last_ip}/{server.pfx}\n"
            svconf += f"ListenPort = {server.port}\n"
            svconf += f"MTU = {server.mtu}\n\n"

            if server.proto == "tcp":
                svconf += f"PreUp = udp2raw -s -l {server.ip}:{self.udp2raw.port} "
                svconf += f'-r 127.0.0.1:{server.port} -k "{self.udp2raw.secret}" '
                svconf += "-a >/var/log/udp2raw.log 2>&1 &\n"

                svconf += "PostDown = pkill -15 udp2raw || true\n\n"

                for client in self.clients:
                    if client.tcp:
                        server.last_ip += 1
                        self._create_client(server, client)

                        svconf += f"# {client.name}\n"
                        svconf += "[Peer]\n"
                        svconf += f"PublicKey = {client.pub}\n"
                        svconf += f"AllowedIPs = {server.last_ip}/32\n\n"
            else:
                for client in self.clients:
                    server.last_ip += 1
                    self._create_client(server, client)

                    svconf += f"# {client.name}\n"
                    svconf += "[Peer]\n"
                    svconf += f"PublicKey = {client.pub}\n"
                    svconf += f"AllowedIPs = {server.last_ip}/32\n\n"

            with open(f"./server/{server.name}.conf", "w", encoding="utf-8") as svfile:
                svfile.write(svconf)

    def _save_yaml(self):
        self.logger.info("generating yaml")

        yaml_dict = {"servers": [], "clients": [], "udp2raw": []}

        for server in self.servers:
            sv_dict = {
                "name": server.name,
                "proto": server.proto,
                "priv": server.priv,
                "ip": str(server.ip),
                "port": server.port,
                "net": f"{str(server.net)}/{server.pfx}",
                "mtu": server.mtu,
            }

            yaml_dict["servers"].append(sv_dict)

        for client in self.clients:
            cl_dict = {
                "name": client.name,
                "priv": client.priv,
                "tcp": client.tcp,
                "bind": client.bind,
            }

            yaml_dict["clients"].append(cl_dict)

        yaml_dict["udp2raw"].append(
            {"secret": self.udp2raw.secret, "port": self.udp2raw.port}
        )

        yaml_str = yaml.dump(yaml_dict, sort_keys=False)

        yaml_filename = f"{time.strftime('%Y%m%d_%H%M%S')}-genpw.yml"
        self.logger.info("saving current state as: %s", yaml_filename)

        with open(yaml_filename, "w", encoding="utf-8") as yaml_file:
            yaml_file.write(yaml_str)

    def run(self):
        self._create_dirs()
        self._create_servers()
        self._save_yaml()

import ipaddress
import os
import re
import shutil
import time

import yaml


# pylint: disable=too-few-public-methods
class GenFiles:
    def __init__(self):
        self.want_bind = None
        self.logger = None
        self.servers = None
        self.clients = None

    @staticmethod
    # pylint: disable=invalid-name
    def _get_host_bits(ip, prefix):
        netmask = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False).netmask)

        ip_split = list(map(int, str(ip).split(".")))
        netmask_split = list(map(int, netmask.split(".")))

        host_bits = [
            ip_split & (255 - netmask_split)
            for ip_split, netmask_split in zip(ip_split, netmask_split)
        ]

        return ".".join([str(bit) for bit in host_bits if bit != 0])

    def _create_dirs(self):
        self.logger.info("creating directories")

        for i in ["genwg_dump"]:
            if os.path.exists(i):
                self.logger.warning(" - collision found, removing")

                try:
                    shutil.rmtree(i)
                except NotADirectoryError:
                    os.remove(i)

            try:
                os.mkdir(i)
            # pylint: disable=bare-except
            except:
                self.logger.exception("_create_dirs() failed")

        want_dirs = ["server", "client"]

        if self.want_bind:
            want_dirs.append("bind/zone/genwg")

        try:
            for i in want_dirs:
                os.makedirs(f"./genwg_dump/{i}", exist_ok=True)
        # pylint: disable=bare-except
        except:
            self.logger.exception("_create_dirs() failed")

    # pylint: disable=too-many-statements
    def _create_client(self, server, client):
        self.logger.info(
            " - client: %s (tcp: %s, bind: %s, android: %s)",
            client.name,
            client.tcp,
            client.bind,
            client.android,
        )

        conf = f"# - server : {server.name}\n"
        conf += f"# - client : {client.name}\n"
        conf += f"# - private: {client.priv}\n"
        conf += f"# - public : {client.pub}\n"

        if client.android and client.tcp and server.proto == "tcp":
            conf += f"\n# actual_endpoint {server.ip}\n"
            conf += f"# wgquick_path    {client.wgquick_path}\n"
            conf += f"# udp2raw_path    {client.udp2raw_path}\n"
            conf += f"# udp2raw_port    {server.udp2raw_port}\n"
            conf += f"# udp2raw_pass    {server.udp2raw_secret}\n\n"

        conf += "[Interface]\n"
        conf += f"Address = {server.last_ip}/32\n"
        conf += f"PrivateKey = {client.priv}\n"
        conf += f"MTU = {server.mtu}\n"

        if client.bind:
            conf += '\nPostUp = mkdir -p "/tmp/bind"\n'
            conf += 'PostUp = echo "zone \\".\\" { type forward; forwarders '
            conf += f'{{ {server.net + 1}; }}; }};" '
            conf += '> "/tmp/bind/named.conf.local"\n'
            conf += "PostUp = rndc reload\n"

            conf += 'PreDown = mkdir -p "/tmp/bind"\n'
            conf += 'PreDown = echo "zone \\".\\" { type hint; file '
            conf += f'\\"{client.root_zone_file}\\"; }};" '
            conf += '> "/tmp/bind/named.conf.local"\n'
            conf += "PreDown = rndc reload\n"
        else:
            conf += f"DNS = {server.net + 1}\n"

        if server.proto == "tcp" and client.tcp and not client.android:
            conf += f"PreUp = ip route add {server.ip} via `ip route list match "
            conf += "0 table all scope global | awk '{print $3}'` dev `ip route "
            conf += "list match 0 table all scope global | awk '{print $5}'`\n"

            conf += "PreUp = udp2raw -c -l 127.0.0.1:50001 -r "
            conf += f'{server.ip}:{server.udp2raw_port} -k "{server.udp2raw_secret}" '
            conf += f"-a >{client.udp2raw_log_path} 2>&1 &\n"

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
            f"./genwg_dump/client/{client.name}-{server.name}.conf",
            "w",
            encoding="utf-8",
        ) as file:
            file.write(conf)

    # pylint: disable=too-many-locals,too-many-statements
    def _create_servers(self):
        if self.want_bind:
            named_conf = ""

        for server in self.servers:
            self.logger.info("creating server %s (%s)", server.name, server.proto)

            # bind root zones for local domains of the wireguard interfaces
            if self.want_bind:
                zone_begin = "$TTL 5M\n"
                zone_begin += (
                    f"@ IN SOA {server.name}. root.{server.name}. ( 1 1W 1D 4W 1W )\n"
                )
                zone_begin += f"@ IN NS {server.hostname}.{server.name}.\n"

                # zone_path/zone.A
                a_zone = zone_begin
                a_zone += f"{server.hostname} IN A {server.last_ip}\n"

                # zone_path/zone.PTR
                ptr_zone = zone_begin
                ptr_zone += f"1 IN PTR {server.hostname}.{server.name}.\n"

                # named_conf_path/zone_path/genwg.conf
                ptr_zone_file_name = re.sub(r"\.in-addr\.arpa$", "", server.arpa_ptr)

                a_path = f"{server.named_conf_path}/zone/genwg/{server.name}"
                ptr_path = f"{server.named_conf_path}/zone/genwg/{ptr_zone_file_name}"

                named_conf += f'zone "{server.name}" {{\n'
                named_conf += "    type master;\n"
                named_conf += f'    file "{a_path}";\n'
                named_conf += "};\n"

                named_conf += f'zone "{server.arpa_ptr}" {{\n'
                named_conf += "    type master;\n"
                named_conf += f'    file "{ptr_path}";\n'
                named_conf += "};\n"

            # wireguard server config
            svconf = f"# - server : {server.name}\n"
            svconf += f"# - private: {server.priv}\n"
            svconf += f"# - public : {server.pub}\n\n"
            svconf += "[Interface]\n"
            svconf += f"PrivateKey = {server.priv}\n"
            svconf += f"Address = {server.last_ip}/{server.pfx}\n"
            svconf += f"ListenPort = {server.port}\n"
            svconf += f"MTU = {server.mtu}\n\n"

            # tcp server handling
            if server.proto == "tcp":
                svconf += f"PreUp = udp2raw -s -l {server.ip}:{server.udp2raw_port} "
                svconf += f'-r 127.0.0.1:{server.port} -k "{server.udp2raw_secret}" '
                svconf += "-a >/var/log/udp2raw.log 2>&1 &\n"

                svconf += "PostDown = pkill -15 udp2raw || true\n\n"

            # wireguard client config
            for client in self.clients:
                if server.proto == "tcp" and not client.tcp:
                    pass
                else:
                    server.last_ip += 1

                    if self.want_bind:
                        # A and PTR records for clients
                        ptr_ip = self._get_host_bits(server.last_ip, server.pfx)

                        a_zone += f"{client.name} IN A {server.last_ip}\n"
                        ptr_zone += f"{ptr_ip} IN PTR {client.name}.{server.name}.\n"

                    # create and write client configs
                    self._create_client(server, client)

                    # append client to server master config
                    svconf += f"# {client.name}\n"
                    svconf += "[Peer]\n"
                    svconf += f"PublicKey = {client.pub}\n"
                    svconf += f"AllowedIPs = {server.last_ip}/32\n\n"

            # write server config
            with open(
                f"./genwg_dump/server/{server.name}.conf", "w", encoding="utf-8"
            ) as svfile:
                svfile.write(svconf)

            if self.want_bind:
                # write genwg.conf
                with open(
                    "./genwg_dump/bind/genwg.conf", "w", encoding="utf-8"
                ) as named_conf_file:
                    named_conf_file.write(named_conf)

                # write a record zone
                with open(
                    f"./genwg_dump/bind/zone/genwg/{server.name}", "w", encoding="utf-8"
                ) as a_zone_file:
                    a_zone_file.write(a_zone)

                # write ptr record zone
                with open(
                    f"./genwg_dump/bind/zone/genwg/{ptr_zone_file_name}",
                    "w",
                    encoding="utf-8",
                ) as ptr_zone_file:
                    ptr_zone_file.write(ptr_zone)

    def _save_yaml(self):
        self.logger.info("generating yaml")

        yaml_dict = {"servers": [], "clients": []}

        # server
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

            try:
                sv_dict["hostname"] = server.hostname
            except AttributeError:
                pass

            try:
                sv_dict["named_conf_path"] = server.named_conf_path
            except AttributeError:
                pass

            if server.proto == "tcp":
                sv_dict["udp2raw_secret"] = server.udp2raw_secret
                sv_dict["udp2raw_port"] = server.udp2raw_port

            yaml_dict["servers"].append(sv_dict)

        # client
        for client in self.clients:
            cl_dict = {"name": client.name, "priv": client.priv}

            if client.tcp:
                cl_dict["tcp"] = client.tcp
                cl_dict["udp2raw_log_path"] = client.udp2raw_log_path

            if client.bind:
                cl_dict["bind"] = client.bind
                cl_dict["root_zone_file"] = client.root_zone_file

            if client.android:
                cl_dict["android"] = client.android
                cl_dict["wgquick_path"] = client.wgquick_path
                cl_dict["udp2raw_path"] = client.udp2raw_path

            yaml_dict["clients"].append(cl_dict)

        # dump
        yaml_str = yaml.dump(yaml_dict, sort_keys=False)

        yaml_filename = f"{time.strftime('%Y%m%d_%H%M%S')}-genwg.yml"
        self.logger.info("saving current state as: %s", yaml_filename)

        with open(f"./genwg_dump/{yaml_filename}", "w", encoding="utf-8") as yaml_file:
            yaml_file.write(yaml_str)

    def run(self):
        self._create_dirs()
        self._create_servers()
        self._save_yaml()

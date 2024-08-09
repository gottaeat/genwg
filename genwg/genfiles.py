import os
import shutil
import time

import jinja2
import yaml


class GenFiles:
    _TEMPLATES_DIR = f"{os.path.dirname(os.path.realpath(__file__))}/templates"

    def __init__(self, config, root_logger):
        self.servers = config.servers
        self.logger = root_logger.getChild(self.__class__.__name__)

    def _create_dirs(self):
        self.logger.info("creating directories")

        if os.path.exists("genwg_dump"):
            self.logger.warning("collision found, removing")

            try:
                shutil.rmtree("genwg_dump")
            except NotADirectoryError:
                try:
                    os.remove("genwg_dump")
                except:
                    self.logger.exception("removing collision failed")
            except:
                self.logger.exception("removing collision failed")

        try:
            os.mkdir("genwg_dump")
        except:
            self.logger.exception("failed creating the root directory")

        try:
            for i in ["server", "client", "bind/zone/genwg"]:
                os.makedirs(f"./genwg_dump/{i}", exist_ok=True)
        except:
            self.logger.exception("failed creating subdirectories")

    def _template(self):
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self._TEMPLATES_DIR),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        for server in self.servers:
            self.logger.info("generating %s", server.name)

            # wireguard server peer configuration
            template = env.get_template("wg_server.conf.j2")
            result = template.render(server=server)

            with open(
                f"./genwg_dump/server/{server.name}.conf", "w", encoding="utf-8"
            ) as svfile:
                svfile.write(result)

            for client in server.clients:
                self.logger.info(" - client: %s", client.name)
                # wireguard client peer configuration
                template = env.get_template("wg_client.conf.j2")
                result = template.render(server=server, client=client)

                with open(
                    f"./genwg_dump/client/{client.name}-{server.name}.conf",
                    "w",
                    encoding="utf-8",
                ) as clfile:
                    clfile.write(result)

            if server.named:
                # bind A zonefile
                self.logger.info(" - bind: A records")
                template = env.get_template("bind_a_zone.j2")
                result = template.render(server=server)

                with open(
                    f"./genwg_dump/bind/zone/genwg/{server.name}", "w", encoding="utf-8"
                ) as bindazonefile:
                    bindazonefile.write(result)

                # bind PTR zonefile
                self.logger.info(" - bind: PTR records")
                template = env.get_template("bind_ptr_zone.j2")
                result = template.render(server=server)

                with open(
                    f"./genwg_dump/bind/zone/genwg/{server.ptr}",
                    "w",
                    encoding="utf-8",
                ) as bindptrzonefile:
                    bindptrzonefile.write(result)

                # bind config
                self.logger.info(" - bind: ISC configuration")
                template = env.get_template("bind.conf.j2")
                result = template.render(server=server)

                with open(
                    f"./genwg_dump/bind/{server.name}.conf",
                    "w",
                    encoding="utf-8",
                ) as bindconfigfile:
                    bindconfigfile.write(result)

    def _dump_yaml(self):
        self.logger.info("generating yaml dump")

        yaml_dict = {"servers": []}

        for server in self.servers:
            sv_dict = {
                "name": server.name,
                "priv": server.priv,
                "ip": str(server.ip),
                "port": server.port,
                "net": f"{server.net}/{server.pfx}",
                "mtu": server.mtu,
            }

            if server.extra_allowed:
                client_extra_allowed_all = []
                for client in server.clients:
                    if client.extra_allowed:
                        for network in client.extra_allowed:
                            client_extra_allowed_all.append(network)

                for index, network in enumerate(server.extra_allowed):
                    if network in client_extra_allowed_all:
                        del server.extra_allowed[index]

                if server.extra_allowed:
                    sv_dict["extra_allowed"] = server.extra_allowed

            if server.named:
                sv_dict["named"] = {
                    "hostname": server.named.hostname,
                    "conf_dir": server.named.conf_dir,
                }

            if server.udp2raw:
                sv_dict["udp2raw"] = {
                    "secret": server.udp2raw.secret,
                    "port": server.udp2raw.port,
                }

            if server.extra_address_str:
                sv_dict["extra_address"] = sv_dict["extra_address"] = [
                    x for x in server.extra_address_str.split(",") if x
                ]

            sv_dict["clients"] = []

            for client in server.clients:
                cl_dict = {"name": client.name, "priv": client.priv}

                if client.append_extra:
                    cl_dict["append_extra"] = True

                if client.wg_handled_dns:
                    cl_dict["wg_handled_dns"] = True

                if client.bind:
                    cl_dict["bind"] = True
                    cl_dict["root_zone_file"] = client.root_zone_file

                if server.udp2raw:
                    cl_dict["udp2raw_log_path"] = client.udp2raw_log_path

                    if client.android:
                        cl_dict["android"] = True
                        cl_dict["wgquick_path"] = client.wgquick_path
                        cl_dict["udp2raw_path"] = client.udp2raw_path

                if client.extra_allowed:
                    cl_dict["extra_allowed"] = client.extra_allowed

                sv_dict["clients"].append(cl_dict)

            yaml_dict["servers"].append(sv_dict)

        yaml_str = yaml.dump(yaml_dict, indent=2, sort_keys=False)
        yaml_filename = f"{time.strftime('%Y%m%d_%H%M%S')}-genwg.yml"

        with open(f"./genwg_dump/{yaml_filename}", "w", encoding="utf-8") as yaml_file:
            yaml_file.write(yaml_str)

    def run(self):
        self._create_dirs()
        self._template()
        self._dump_yaml()

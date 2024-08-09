import os
import shutil

import jinja2


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

    def run(self):
        self._create_dirs()
        self._template()

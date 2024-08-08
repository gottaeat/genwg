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

    def _create_servers(self):
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self._TEMPLATES_DIR),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        for server in self.servers:
            template = env.get_template("wg_server.conf.j2")
            result = template.render(server=server)

            with open(
                f"./genwg_dump/server/{server.name}.conf", "w", encoding="utf-8"
            ) as svfile:
                svfile.write(result)

            for client in server.clients:
                template = env.get_template("wg_client.conf.j2")
                result = template.render(server=server, client=client)

                with open(
                    f"./genwg_dump/client/{client.name}-{server.name}.conf",
                    "w",
                    encoding="utf-8",
                ) as clfile:
                    clfile.write(result)

    def run(self):
        self._create_dirs()
        self._create_servers()

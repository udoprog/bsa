import sys
import os
import logging
import contextlib
import argparse

from bsa.named import parse_config
from bsa.named import BindConfig

LOGGING_FORMAT = "%(levelname)-7s %(asctime)s [%(name)20s] %(message)s"

__version__ = '0.2.1'


class DefaultReporter(object):
    ERROR = "error"
    WARNING = "warning"
    WARNING = "info"

    def __init__(self, name=None):
        self.messages = list()
        if name is None:
            self.name = "SUITE"
        else:
            self.name = name

    def error(self, message):
        self.messages.append((self.ERROR, message))

    def print_all(self):
        log = logging.getLogger(self.name)

        for (level, message) in self.messages:
            if level == self.ERROR:
                log.error(message)
                continue

            if level == self.WARNING:
                log.warning(message)
                continue

            if level == self.INFO:
                log.info(message)
                continue

        self.messages = []


class DefaultBootstrap(object):
    """
    Allow a user to interactively bootstrap and rerun tests.
    """

    default_reporter_type = DefaultReporter

    def __init__(self, db, reporter_type=None, name=None):
        self.db = db
        self.modcache = dict()

        if reporter_type is not None:
            self.reporter_type = reporter_type
        else:
            self.reporter_type = self.default_reporter_type

        self.name = name

    def get_refresh_module(self, module):
        mod = self.modcache.get(module)

        if mod is not None:
            reload(mod)
            return mod

        mod = __import__(module)

        for n in module.split(".")[1:]:
            mod = getattr(mod, n)

        self.modcache[module] = mod
        return mod

    def execute(self, module, no_report=False):
        mod = self.get_refresh_module(module)

        reporter = self.reporter_type(name=module)
        result = mod.run(self.db, reporter)

        if not no_report:
            reporter.print_all()

        return result


def run_interactive(zones):
    """
    Run an interactive session against the database.
    """
    try:
        from IPython.frontend.terminal.embed import InteractiveShellEmbed
    except:
        logging.error(
            "Could not import ipython, is it properly installed?",
            exc_info=sys.exc_info())
        return 1

    import bsa.bind

    def setup_b():
        reload(bsa.bind)
        return bsa.bind.FakeBind(zones)

    b = None

    try:
        b = bsa.bind.FakeBind(zones)
    except:
        logging.warning("Could not setup FakeBind", exc_info=sys.exc_info())
        logging.info(
            "Fix the problem and run: "
            "b = setup_b(); "
            "bootstrap.db = b;")

    shell = InteractiveShellEmbed(
        banner1=os.linesep.join([
            "Available variables:",
            "    zones - List of objects containing all the available zones.",
            "    b - A utility that allows you to query the available zones.",
            "    reporter - A default reporter.",
            "    bootstrap - A dynamic test bootstrapper: "
            "bootstrap.execute(<module>)",
        ])
    )

    reporter = DefaultReporter()
    bootstrap = DefaultBootstrap(b)

    assert reporter
    assert bootstrap

    # assign some convenience functions.
    shell()

    return 0


def run_modules(zones, modules):
    import bsa.bind

    log = logging.getLogger("modules")

    try:
        b = bsa.bind.FakeBind(zones)
    except:
        log.error("FakeBind setup failed", exc_info=sys.exc_info())
        return 1

    bootstrap = DefaultBootstrap(b)

    result = list()

    for m in modules:
        log.info("[running module: {0}]".format(m))
        result.append(bootstrap.execute(m))

    if not all(result):
        log.error("All test suites did not pass!")
        return 1

    log.info("All test suites passed!")
    return 0


@contextlib.contextmanager
def prefix_file_reader(root_directory, path):
    generated_path = os.path.join(root_directory, 'generated')

    if path.startswith(generated_path):
        path = os.path.join(
            root_directory,
            os.path.relpath(path, generated_path))

    with open(path) as f:
        yield f


def bsa_main(args):

    parser = argparse.ArgumentParser(version="bsa " + __version__)
    parser.add_argument("config", nargs='+')

    parser.add_argument(
        "-i", "--interactive", dest="interactive",
        help=("Start an interactive terminal using ipython to query the "
              "local database."),
        default=False, action='store_true')

    parser.add_argument(
        "-m", "--module", dest="modules", nargs='*',
        help="Run the specified test suites.",
        default=[])

    parser.add_argument(
        "-R", "--fake-root",
        dest="fake_root",
        default="/etc/bind",
        metavar="<directory>",
        help="Assume that all absolute paths reffering to <directory> is "
             "relative to the current working directory. Default: /etc/bind")

    parser.add_argument(
        "-C", "--parser-cache", dest="parser_cache",
        default=None,
        metavar="<directory>",
        help="Store pickled ASTs to speed up subsequent parsing.")

    parser.add_argument(
        "-l", "--log-level", dest="log_level",
        default="ERROR",
        metavar="<level>",
        help="Set log level. default: ERROR")

    ns = parser.parse_args(args)

    logging.basicConfig(level=getattr(logging, ns.log_level),
                        format=LOGGING_FORMAT)

    config = BindConfig(parser_cache=ns.parser_cache)

    if not ns.config:
        raise Exception("No configurations specified")

    root_directory = os.path.dirname(ns.config[0])

    for path in ns.config:
        root_section = parse_config(
            path, ns.fake_root,
            root_directory=root_directory,
            file_reader=prefix_file_reader)

        config.update_from_section(root_section)

    def zone_reporter(i, config, zone):
        logging.info(
            "{0:05}: {zone.file} ({zone.origin})".format(i, zone=zone)
        )

    zones = config.parse_zones(
        root_directory=root_directory,
        fake_root=ns.fake_root,
        file_reader=prefix_file_reader,
        reporter=zone_reporter)

    if ns.modules:
        return run_modules(zones, ns.modules)

    if ns.interactive:
        return run_interactive(zones)

    return 0

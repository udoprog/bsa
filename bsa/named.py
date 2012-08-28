import os
import logging

import ipaddr
import hashlib

try:
    import cPickle as pickle
except ImportError:
    import pickle

from bsa.include_handler import IncludeHandler
from bsa.zone import parse_zone


log = logging.getLogger(__name__)


def convert_bool(value):
    return value.lower() in ("true", "yes")


def convert_ipv4(value):
    return ipaddr.IPv4Address(value)


def convert_ident_list(section, converter=str):
    return map(lambda (p, i, a, s): converter(i), section)


class BindConfig(object):
    def __init__(self, parser_cache=None):
        self.views = dict()
        self.zones = dict()
        self.options = {
            "directory": "/etc/bind",
            "also-notify": [],
            "auth-nxdomain": None,
            "listen-on-v6": False,
            "allow-recursion": True,
            "allow-transfer": True,
            "statistics-file": None,
        }
        self.acl = dict()
        self.parser_cache = parser_cache

        super(BindConfig, self).__init__()

    def update_attribute(self, ident, args, section):
        if ident == "options":
            self.options.update(self.read_options(section))
            return

        if ident == "acl":
            self.acl[ident] = convert_ident_list(section)
            return

        if ident == "logging":
            # ignore
            return

        log.warning("unhandled section: {0}".format(ident))

    def read_options(self, source_section):
        options = dict()

        for state, ident, args, section in source_section:
            if ident == "directory":
                options["directory"] = args[0]
                continue

            if ident == "also-notify":
                options["also-notify"] = \
                    convert_ident_list(section, convert_ipv4)
                continue

            if ident == "auth-nxdomain":
                options["auth-nxdomain"] = convert_bool(args[0])
                continue

            if ident == "allow-recursion":
                options["allow-recursion"] = \
                    convert_ident_list(section)
                continue

            if ident == "allow-transfer":
                options["allow-recursion"] = \
                    convert_ident_list(section)
                continue

            if ident == "statistics-file":
                options["statistics-file"] = args[0]
                continue

            if ident == "listen-on-v6":
                options["listen-on-v6"] = \
                    convert_ident_list(section)
                continue

            log.warning("unhandled option: {0}".format(ident))

        return options

    def update_from_section(self, source_section):
        """
        Update configuration object from an ast section.

        source_section - The root section AST.
        """

        queue = [(self, source_section)]

        while queue:
            config, source_section = queue.pop()

            for state, ident, args, section in source_section:
                if ident == "zone":
                    zone = BindZone(*args)
                    zone.update_attributes(section)
                    config.zones[zone.origin] = zone
                    continue

                if ident == "view":
                    view = BindView(config, *args)
                    config.views[view.name] = view
                    queue.insert(0, (view, section))
                    continue

                config.update_attribute(ident, args, section)

    @property
    def all_zones(self):
        """
        Generates all available zones in a configuration.
        """

        configs = [self]

        while configs:
            config = configs.pop()

            for zone in config.zones.values():
                yield config, zone

            configs.extend(config.views.values())

    @classmethod
    def get_mtime(cls, path):
        return os.stat(path).st_mtime

    @classmethod
    def is_newer(cls, path1, path2):
        return cls.get_mtime(path1) > cls.get_mtime(path2)

    def get_cache_path(self, zone):
        cache_name = hashlib.md5(zone.file + zone.origin).hexdigest()
        return os.path.join(self.parser_cache, cache_name)

    def get_cached(self, zone):
        if self.parser_cache is None:
            return None

        cache_path = self.get_cache_path(zone)

        if not os.path.isfile(cache_path):
            return None

        if self.is_newer(zone.file, cache_path):
            return None

        try:
            with open(cache_path) as f:
                return pickle.load(f)
        except Exception as e:
            log.warning("ignoring broken cache file: {0}: {1}".format(
                cache_path, str(e)))
            return None

    def put_cache(self, zone, ast):
        if self.parser_cache is None:
            return

        cache_path = self.get_cache_path(zone)

        with open(cache_path, "w") as f:
            return pickle.dump(ast, f)

    def parse_zones(self, fake_dir=None, reporter=None):
        """
        Parse all available zones.

        Utilizes two levels of caching.

        1) An in memory cache, the 'cache' dict which stores any previously
           parsed zone.
        2) An optional file level cache, which is triggered when 'parser_cache'
           is defined.
           ASTs will be pickled and stored in the specified directory for
           future runs.
        """

        if fake_dir is None:
            fake_dir = os.getcwd()

        cache = dict()

        for i, (config, zone) in enumerate(self.all_zones):
            if reporter:
                reporter(i, config, zone)

            key = (zone.file, zone.origin)

            value = cache.get(key)

            if value is not None:
                ast, configs = value
                configs.append(config)
                cache[key] = (ast, configs)
                continue

            ast = self.get_cached(zone)

            if ast is None:
                ast = parse_zone(zone.file, zone.origin, fake_dir=fake_dir)
                self.put_cache(zone, ast)

            cache[key] = (ast, [config])

        return cache.values()

    def __repr__(self):
        return "<BindConfig (root)>"


class BindZone(object):
    def __init__(self, origin):
        self.origin = origin
        self.file = None
        self.allow_update = list()

    def update_attributes(self, section_ast):
        for state, ident, args, section in section_ast:
            if ident == "file":
                self.file = state.build_path(args[0])
                continue

            if ident == "allow-update":
                self.allow_update.extend(map(lambda (p, i, a, s): i, section))
                continue

    def __repr__(self):
        return (
            "<BindZone origin={self.origin} "
            "file={self.file}>"
        ).format(self=self)


class BindView(BindConfig):
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name
        self.match_clients = list()
        super(BindView, self).__init__()

    def update_attribute(self, ident, args, section):
        if ident == "match-clients":
            self.match_clients.extend(map(lambda (p, i, a, s): i, section))
            return

        super(BindView, self).update_attributes(ident, args, section)

    def __repr__(self):
        return "<BindView name={self.name}>".format(self=self)


def build_parser(path, fake_dir=os.getcwd(), file_reader=None):
    from pyparsing import nestedExpr
    from pyparsing import QuotedString
    from pyparsing import Group
    from pyparsing import restOfLine
    from pyparsing import Word
    from pyparsing import alphanums
    from pyparsing import cStyleComment
    from pyparsing import OneOrMore
    from pyparsing import ZeroOrMore
    from pyparsing import Optional
    from pyparsing import Forward
    from pyparsing import Literal
    from pyparsing import Keyword

    root = Forward()

    include_handler = IncludeHandler(
        path,
        root,
        fake_dir=fake_dir,
        file_reader=file_reader)

    # relaxed grammar
    identifier = Word(alphanums + "-_.:/")

    comment = ("//" + restOfLine).suppress() \
            | ("#" + restOfLine).suppress() \
            | cStyleComment

    endstmt = Literal(";").suppress()

    argument = QuotedString('"') \
             | identifier

    arguments = ZeroOrMore(argument)

    statements = Forward()

    section = nestedExpr("{", "}", statements)

    include = Keyword("include").suppress() + QuotedString('"')

    regular = identifier + Group(arguments) + Optional(section, default=[])

    statement = include.setParseAction(include_handler) \
              | regular.setParseAction(include_handler.mark)

    statements << OneOrMore(statement + endstmt)

    root << Optional(statements)

    root.ignore(comment)

    return root


def parse_config(path, fake_dir=None):
    if fake_dir is None:
        fake_dir = os.getcwd()
    parser = build_parser(path, fake_dir)
    return parser.parseFile(path, parseAll=True)

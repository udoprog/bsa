import os
import logging

import ipaddr
import pyparsing as p

from bsa.include_handler import IncludeHandler
from bsa.include_handler import IncludeStack
from bsa.utils import join_origin

log = logging.getLogger(__name__)


def convert_ipv4(s, l, t):
    try:
        return ipaddr.IPv4Address(t[0])
    except:
        raise p.ParseFatalException("Invalid IPv4-address: {0}".format(t[0]))


ipv4 = p.Word(p.nums + ".").setParseAction(convert_ipv4)
domain = p.Word(p.alphanums + "-_#.")
number = p.Word(p.nums)


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


class Record(object):
    __slots__ = (
        "label",
        "ttl",
        "class_type",
        "origin",
        "path",
    )

    record_type = None
    grammar = None

    def __init__(self, label, ttl, class_type, origin, path):
        self.label = label
        self.ttl = ttl
        self.class_type = class_type
        self.path = path

        if not origin:
            self.origin = "."
        else:
            self.origin = origin

    def __eq__(self, o):
        return self.__key__() == o.__key__()

    def __hash__(self):
        return hash(self.__key__())

    def __key__(self):
        return (
            self.label,
            self.ttl,
            self.class_type,
            self.origin,
            self.__key__()
        )

    def __repr__(self):
        return (
            "<{self.record_type} "
                "\"{self.label}\" "
                "path={self.path} "
                "origin={self.origin} "
                "ttl={self.ttl} "
                "class_type={self.class_type} "
                "values={values}"
            ">"
        ).format(self=self, values=self.values())

    def __str__(self):
        return (
            "{self.resolved_label} "
            "{self.ttl} "
            "{self.class_type} "
            "{self.record_type} "
            "{values}"
        ).format(self=self,
                 values=" ".join(map(str, self.origin_values())))

    @property
    def resolved_label(self):
        return join_origin(self.label, self.origin)

    def __getstate__(self):
        return (self.label, self.ttl, self.class_type, self.origin, self.path)

    def __setstate__(self, state):
        (self.label, self.ttl, self.class_type, self.origin, self.path) = state


class A(Record):
    __slots__ = (
        "address",
    )

    record_type = "A"
    grammar = ipv4

    def __init__(self, args, address):
        self.address = address
        super(A, self).__init__(*args)

    def __key__(self):
        return (self.address,)

    def values(self):
        return (
            self.address,
        )

    def origin_values(self):
        return (
            self.address,
        )

    def __getstate__(self):
        parent_state = super(A, self).__getstate__()
        return (self.address, parent_state)

    def __setstate__(self, state):
        (self.address, parent_state) = state
        super(A, self).__setstate__(parent_state)


class TXT(Record):
    __slots__ = (
        "labels",
    )

    record_type = "TXT"
    grammar = p.Group(p.ZeroOrMore(p.QuotedString('"')))

    str_fmt = '"{0}"'.format

    def __init__(self, args, labels):
        self.labels = tuple(labels)
        super(TXT, self).__init__(*args)

    def __key__(self):
        return (self.labels,)

    def values(self):
        return map(self.str_fmt, self.labels)

    def origin_values(self):
        return self.values()

    def __getstate__(self):
        parent_state = super(TXT, self).__getstate__()
        return (self.labels, parent_state)

    def __setstate__(self, state):
        (self.labels, parent_state) = state
        super(TXT, self).__setstate__(parent_state)


class NS(Record):
    __slots__ = (
        "target",
    )

    record_type = "NS"
    grammar = domain

    def __init__(self, args, target):
        self.target = target
        super(NS, self).__init__(*args)

    def __key__(self):
        return (self.target,)

    @property
    def resolved_target(self):
        return join_origin(self.target, self.origin)

    def values(self):
        return (
            self.target,
        )

    def origin_values(self):
        return (
            join_origin(self.target, self.origin),
        )

    def __getstate__(self):
        parent_state = super(NS, self).__getstate__()
        return (self.target, parent_state)

    def __setstate__(self, state):
        (self.target, parent_state) = state
        super(NS, self).__setstate__(parent_state)


class MX(Record):
    __slots__ = (
        "priority",
        "target",
    )

    record_type = "MX"
    grammar = number + domain

    def __init__(self, args, priority, target):
        self.priority = priority
        self.target = target
        super(MX, self).__init__(*args)

    def __key__(self):
        return (self.target, self.priority)

    @property
    def resolved_target(self):
        return join_origin(self.target, self.origin)

    def values(self):
        return (
            self.priority,
            self.target,
        )

    def origin_values(self):
        return (
            self.priority,
            self.resolved_target,
        )

    def __getstate__(self):
        parent_state = super(MX, self).__getstate__()
        return (self.priority, self.target, parent_state)

    def __setstate__(self, state):
        (self.priority, self.target, parent_state) = state
        super(MX, self).__setstate__(parent_state)


class SRV(Record):
    __slots__ = (
        "priority",
        "weight",
        "port",
        "target",
    )

    record_type = "SRV"
    grammar = number + number + number + domain

    def __init__(self, args, priority, weight, port, target):
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target
        super(SRV, self).__init__(*args)

    def __key__(self):
        return (self.priority, self.weight, self.port, self.target)

    @property
    def resolved_target(self):
        return join_origin(self.target, self.origin)

    def values(self):
        return (
            self.priority,
            self.weight,
            self.port,
            self.target,
        )

    def origin_values(self):
        return (
            self.priority,
            self.weight,
            self.port,
            self.resolved_target,
        )

    def __getstate__(self):
        parent_state = super(SRV, self).__getstate__()
        return (
            self.priority,
            self.weight,
            self.port,
            self.target,
            parent_state
        )

    def __setstate__(self, state):
        (
            self.priority,
            self.weight,
            self.port,
            self.target,
            parent_state
        ) = state
        super(SRV, self).__setstate__(parent_state)


class CNAME(Record):
    __slots__ = (
        "target",
    )

    record_type = "CNAME"
    grammar = domain

    def __init__(self, args, target):
        self.target = target
        super(CNAME, self).__init__(*args)

    def __key__(self):
        return (self.target,)

    @property
    def resolved_target(self):
        return join_origin(self.target, self.origin)

    def values(self):
        return (
            self.target,
        )

    def origin_values(self):
        return (
            join_origin(self.target, self.origin),
        )

    def __getstate__(self):
        parent_state = super(CNAME, self).__getstate__()
        return (self.target, parent_state)

    def __setstate__(self, state):
        (self.target, parent_state) = state
        super(CNAME, self).__setstate__(parent_state)


class PTR(Record):
    __slots__ = (
        "target",
    )

    record_type = "PTR"
    grammar = domain

    def __init__(self, args, target):
        self.target = target
        super(PTR, self).__init__(*args)

    def __key__(self):
        return (self.target,)

    def values(self):
        return (
            self.target,
        )

    def origin_values(self):
        return (
            join_origin(self.target, self.origin),
        )

    def __getstate__(self):
        parent_state = super(PTR, self).__getstate__()
        return (self.target, parent_state)

    def __setstate__(self, state):
        (self.target, parent_state) = state
        super(PTR, self).__setstate__(parent_state)


class SOA(Record):
    __slots__ = (
        "primary",
        "mail",
        "serials",
    )

    record_type = "SOA"
    grammar = domain + domain + p.nestedExpr("(", ")", p.And([number] * 5))

    def __init__(self, args, primary, mail, serials):
        self.primary = primary
        self.mail = mail
        self.serials = tuple(serials)
        super(SOA, self).__init__(*args)

    def __key__(self):
        return (self.primary, self.mail, self.serials)

    @property
    def resolved_primary(self):
        return join_origin(self.primary, self.origin)

    def values(self):
        return (
            self.primary,
            self.mail,
            "({0})".format(" ".join(map(str, self.serials)))
        )

    def origin_values(self):
        return (
            self.resolved_primary,
            self.mail,
            "({0})".format(" ".join(map(str, self.serials))),
        )

    def __getstate__(self):
        parent_state = super(SOA, self).__getstate__()
        return (self.primary, self.mail, self.serials, parent_state)

    def __setstate__(self, state):
        (self.primary, self.mail, self.serials, parent_state) = state
        super(SOA, self).__setstate__(parent_state)


class AFSDB(Record):
    record_type = "AFSDB"
    grammar = number + domain

    def __init__(self, args, priority, target):
        self.priority = priority
        self.target = target
        super(AFSDB, self).__init__(*args)

    def __key__(self):
        return (self.priority, self.target)

    def values(self):
        return (
            self.priority,
            self.target,
        )

    def origin_values(self):
        return (
            self.priority,
            join_origin(self.target, self.origin),
        )

    def __getstate__(self):
        parent_state = super(AFSDB, self).__getstate__()
        return (self.priority, self.target, parent_state)

    def __setstate__(self, state):
        (self.priority, self.target, parent_state) = state
        super(AFSDB, self).__setstate__(parent_state)


class RecordBuilder(IncludeStack):
    """
    Is responsible for keeping track of origin and building records properly
    according to grammar.
    """
    def __init__(self, path, origin, records):
        self.previous_label = origin
        self.ttl = 3600 * 24

        self.records = dict(map(lambda r: (r.record_type, r), records))

        # Maintain a stack of all traversed paths and origins.
        self.stack = [(path, origin)]

    def update_origin(self, s, l, t):
        path, _ = self.stack[-1]
        self.stack[-1] = (path, t[0])
        return []

    def update_ttl(self, s, l, t):
        self.ttl = int(t[0])
        return []

    def build_name_record(self, s, l, t):
        if len(t) == 4:
            label, ttl, class_type, (record_type, record) = t
        else:
            ttl, class_type, (record_type, record) = t
            label = None

        path, origin = self.stack[-1]

        if label is None:
            label = self.previous_label
        else:
            self.previous_label = label

        if ttl is None:
            ttl = self.ttl

        record_args = (label, ttl, class_type, origin, path)

        record_type = self.records.get(record_type)

        if record_type is None:
            log.error("unknown record type: {0}".format(record[0]))
            return None

        return record_type(record_args, *record)

    def push_stack(self, path):
        _, origin = self.stack[-1]
        self.stack.append((path, origin))

    def pop_stack(self):
        path, _ = self.stack.pop()
        return path

    def peek_stack(self):
        path, _ = self.stack[-1]
        return path


def build_record_parser(R):
    """
    Used to dynamically build records for each record type.
    """

    record = p.Group(p.Keyword(R.record_type) + p.Group(R.grammar))
    return record


def build_parser(
        path,
        origin=".",
        fake_dir=None,
        file_reader=None,
        custom_records=[]):
    """
    Build a zone file parser using pyparsing.

    The default parser will completely ignore whitespace unless specified in
    the match pattern.
    """

    # root grammar
    root = p.Forward()

    records = [A, CNAME, PTR, TXT, NS, MX, SRV, AFSDB, SOA]
    records += custom_records

    rb = RecordBuilder(path, origin, records)

    if fake_dir is None:
        fake_dir = os.getcwd()

    def convert_bool(s, l, t):
        if t[0].lower() in ["yes", "true"]:
            return True
        return False

    def convert_number(s, l, t):
        return int(t[0])

    include_handler = IncludeHandler(
        path,
        root,
        fake_dir=fake_dir,
        file_reader=file_reader,
        stack=rb)

    number = p.Word(p.nums)

    comment = p.Literal(";") + p.restOfLine

    path = p.Word(p.alphanums + "._/-")

    include = p.Keyword("$INCLUDE").suppress() + path
    origin = p.Keyword("$ORIGIN").suppress() + domain
    ttl = p.Keyword("$TTL").suppress() + number

    record = p.Or(map(build_record_parser, records))

    class_type = p.Keyword("IN") | p.Keyword("CH")

    name_spec = domain | p.Keyword("@") | p.Keyword("*")

    value_spec = p.Optional(number, default=None) + \
                 p.Optional(class_type, default="IN") + \
                 record

    name_record = name_spec + value_spec \
                | value_spec

    name_record.setParseAction(rb.build_name_record)

    statement = include \
              | origin \
              | ttl \
              | name_record

    root << p.ZeroOrMore(statement + p.LineEnd().suppress())

    number.setParseAction(convert_number)
    ipv4.setParseAction(convert_ipv4)
    origin.setParseAction(rb.update_origin)
    ttl.setParseAction(rb.update_ttl)
    include.setParseAction(include_handler)

    root.ignore(comment)

    return root


def parse_zone(path, origin, fake_dir=None):
    if fake_dir is None:
        fake_dir = os.getcwd()
    parser = build_parser(path, origin, fake_dir)
    return parser.parseFile(path, parseAll=True)

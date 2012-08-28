import os
import logging

import ipaddr
import pyparsing as p

from bsa.utils import join_origin

from bsa.include_handler import IncludeStack
from bsa.include_handler import IncludeHandler

log = logging.getLogger(__name__)


def convert_ipv4(s, l, t):
    try:
        return ipaddr.IPv4Address(t[0])
    except:
        raise p.ParseFatalException("Invalid IPv4-address: {0}".format(t[0]))


ipv4 = p.Word(p.nums + ".").setParseAction(convert_ipv4)
domain = p.Word(p.alphanums + "-_#.")
number = p.Word(p.nums)


class Record(object):
    __slots__ = (
        "label",
        "ttl",
        "class_type",
        "origin",
        "path",
    )

    VALID_CLASS_TYPES = set(["IN", "CH"])

    DEFAULT_TTL = 3600 * 24
    DEFAULT_CLASS_TYPE = "IN"

    record_type = None

    def __init__(self, label, ttl, class_type, origin, path):
        if label is not None:
            self.label = label
        else:
            self.label = ""

        if ttl is not None:
            self.ttl = ttl
        else:
            self.ttl = self.DEFAULT_TTL

        if class_type is not None:
            if class_type not in self.VALID_CLASS_TYPES:
                raise ValueError("Invalid class type: {0}".format(class_type))
            self.class_type = class_type
        else:
            self.class_type = self.DEFAULT_CLASS_TYPE

        self.path = path

        if not origin:
            self.origin = "."
        else:
            self.origin = origin

    def __eq__(self, o):
        return self.__full_key__() == o.__full_key__()

    def __hash__(self):
        return hash(self.__full_key__())

    def __full_key__(self):
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

    str_fmt = '"{0}"'.format

    def __init__(self, args, *labels):
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
        "serial",
        "refresh",
        "retry",
        "expire",
        "minimum",
    )

    record_type = "SOA"

    def __init__(self, args, primary, mail,
            serial, refresh, retry, expire, minimum):
        self.primary = primary
        self.mail = mail
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum
        super(SOA, self).__init__(*args)

    @property
    def numbers(self):
        return self.serial, self.refresh, self.retry, self.expire, self.minimum

    @numbers.setter
    def set_numbers(self, numbers):
        (self.serial,
         self.refresh,
         self.retry,
         self.expire,
         self.minimum) = numbers

    def __key__(self):
        return (self.primary, self.mail, self.numbers)

    @property
    def resolved_primary(self):
        return join_origin(self.primary, self.origin)

    def values(self):
        return (
            self.primary,
            self.mail,
            "({0})".format(" ".join(map(str, self.numbers)))
        )

    def origin_values(self):
        return (
            self.resolved_primary,
            self.mail,
            "({0})".format(" ".join(map(str, self.numbers))),
        )

    def __getstate__(self):
        parent_state = super(SOA, self).__getstate__()
        return (self.primary, self.mail, self.numbers, parent_state)

    def __setstate__(self, state):
        (self.primary, self.mail, self.numbers, parent_state) = state
        super(SOA, self).__setstate__(parent_state)


class AFSDB(Record):
    record_type = "AFSDB"

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
        self.previous_label = None
        self.ttl = 3600 * 24

        self.records = dict(map(lambda r: (r.record_type, r), records))

        # Maintain a stack of all traversed paths and origins.
        self.stack = [(path, origin)]

    def update_origin(self, origin):
        path, _ = self.stack[-1]
        self.stack[-1] = (path, origin)
        return []

    def update_ttl(self, ttl):
        self.ttl = ttl
        return []

    def build_name_record(self, record):
        label, ttl, class_type, (record_type, record) = record

        path, origin = self.stack[-1]

        if not label:
            if not self.previous_label:
                raise ValueError("No previous label")
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


class ZoneParser(object):
    PRAGMA = "P"
    RECORD = "R"

    def __init__(self, path,
                 origin=None,
                 fake_dir=None,
                 custom_records=[],
                 file_reader=None):

        self.path = path
        self.origin = origin
        self.fake_dir = fake_dir
        self.records = [A, CNAME, PTR, TXT, NS, MX, SRV, AFSDB, SOA]
        self.records += custom_records
        self.record_names = set(r.record_type for r in self.records)
        self.rb = RecordBuilder(path, origin, self.records)

        self.include_handler = IncludeHandler(
            path,
            self,
            fake_dir=fake_dir,
            file_reader=file_reader)

        self.whitespace = "\t\r "
        self.newline = "\n"

    @classmethod
    def yield_file_characters(cls, f):
        while True:
            buf = f.read(4096)

            if not buf:
                return

            for c in buf:
                yield c

    def zone_tokenizer(self, generator):
        collected = ""

        quoted = False
        multiline = False
        comment = False
        escape = False
        first = False

        for c in generator:
            if first:
                first = False
                if c in self.whitespace:
                    yield ""
                    continue

            if c in self.newline:
                comment = False
                quoted = False

                if collected:
                    yield collected

                if not multiline:
                    first = True
                    yield None

                collected = ""
                continue

            if escape:
                collected += c
                escape = False
                continue

            if c == ';':
                comment = True
                continue

            if comment:
                continue

            if not quoted and c in self.whitespace:
                if collected:
                    yield collected
                    collected = ""

                continue

            if c == '\\':
                escape = True
                continue

            if c == '"':
                quoted = not quoted
                continue

            if c == '(':
                multiline = True
                continue

            if c == ')':
                multiline = False
                continue

            collected += c

        if collected:
            yield collected
            yield None

    def generate_lines(self, generator):
        collected = []

        for t in self.zone_tokenizer(generator):
            if t is None:
                if collected:
                    yield tuple(collected)
                    collected = []
                continue

            collected.append(t)

    def parse_generator(self, generator):
        result = list()

        for line in self.generate_lines(generator):
            t, val = self.parse_zone_line(line)

            if t == self.PRAGMA:
                result.extend(self.handle_pragma(val))
                continue

            record = self.rb.build_name_record(val)

            result.append(record)

        return result

    def parse_zone_line(self, line):
        l = line

        if l[0].startswith("$"):
            return self.PRAGMA, tuple(l)

        if l[1] in self.record_names:
            return self.RECORD, (l[0], None, None, (l[1], l[2:]))

        if l[2] in self.record_names:
            if l[1] in Record.VALID_CLASS_TYPES:
                return self.RECORD, (l[0], None, l[1], (l[2], l[3:]))
            return self.RECORD, (l[0], int(l[1]), None, (l[2], l[3:]))

        if l[3] in self.record_names:
            if l[2] in Record.VALID_CLASS_TYPES:
                return self.RECORD, (l[0], int(l[1]), l[2], (l[3], l[4:]))

            if l[1] in Record.VALID_CLASS_TYPES:
                return self.RECORD, (l[0], int(l[2]), l[1], (l[3], l[4:]))

        raise ValueError("Cannot handle: {0}".format(line))

    def handle_pragma(self, val):
        name = val[0]

        if name == "$ORIGIN":
            self.rb.update_origin(val[1])
            return []

        if name == "$TTL":
            self.rb.update_ttl(int(val[1]))
            return []

        if name == "$INCLUDE":
            return self.include_handler(None, None, val)

        raise ValueError(val)

    def parse_file(self, path):
        with open(path) as f:
            generator = self.yield_file_characters(f)
            return self.parse_generator(generator)

    def parse_string(self, string):
        generator = (c for c in string)
        return self.parse_generator(generator)

    def parseString(self, string):
        return self.parse_string(string)


def parse_zone(path, origin, fake_dir=None):
    if fake_dir is None:
        fake_dir = os.getcwd()

    parser = ZoneParser(path, origin, fake_dir)
    return parser.parse_file(path)

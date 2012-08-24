from bsa.named import BindConfig
from bsa.utils import normalize_label
from bsa.zone import Record


import fnmatch


class record_filter(object):
    def __init__(self, record_type):
        self.record_type = record_type

        self.filter_f = None

        if record_type is not None:
            if isinstance(record_type, list):
                self.filter_f = self.filter_by_list
            elif isinstance(record_type, Record):
                self.filter_f = self.filter_by_type
            else:
                self.filter_f = self.filter_by_name

    def filter_by_list(self, (rr, __)):
        return rr.record_type in self.record_type or \
                type(rr) in self.record_type

    def filter_by_name(self, (rr, __)):
        return rr.record_type == self.record_type

    def filter_by_type(self, (rr, __)):
        return type(rr) == self.record_type

    def __call__(self, item):
        if self.filter_f is None:
            return True

        return self.filter_f(item)


class config_filter(object):
    """
    A configurable configuration filter.
    """
    def __init__(self, view_name=None):
        self.view_name = view_name

        self.view_f = None

        if view_name is not None:
            if isinstance(view_name, list):
                self.view_f = self.filter_view_by_list
            else:
                self.view_f = self.filter_view_by_name

    def filter_view_by_list(self, config):
        return config.name in self.view_name

    def filter_view_by_name(self, config):
        return config.name == self.view_name

    def __call__(self, config):
        if self.view_f is None:
            return True

        # root configuration
        if type(config) == BindConfig:
            return True

        # view configuration.
        if self.view_f(config):
            return True

        return False


class FakeBind(object):
    """
    Pretend to be a bind daemon, giving the programmer some nifty tools to
    query the available zones.
    """

    ANY = object()

    @classmethod
    def map_label(cls, label):
        """
        Map a label using a filter to a tuple.
        """
        label = normalize_label(label)
        return map(lambda v: cls.ANY if v == '*' else v, label.split("."))

    @classmethod
    def build_keys(cls, label):
        """
        Generate all permutations for the keys to look up.
        """
        k = cls.map_label(label)

        yield True, tuple(k)
        yield True, tuple([cls.ANY] + k[1:])

    def __init__(self, zones):
        self.zones = zones
        self.cache = self.build_cache(zones)

    def build_cache(self, zones):
        cache = dict()

        for (zone, configs) in zones:
            for rr in zone:
                k = self.map_label(rr.resolved_label)
                values = cache.setdefault(tuple(k), [])
                values.append((rr, configs))

        return cache

    def wildcard_records(self, name):
        for (zone, configs) in self.zones:
            for rr in zone:
                if not fnmatch.fnmatch(rr.resolved_label, name):
                    continue

                yield (rr, configs)

    def wildcard_iquery(self, label, record=None, view=None):
        label = normalize_label(label)

        result = list(self.wildcard_records(label))

        rec_filter = record_filter(record)
        cfg_filter = config_filter(view)

        for (rr, configs) in filter(rec_filter, result):
            if any(filter(cfg_filter, configs)):
                yield rr

    def regular_iquery(self, label, record=None, view=None):
        rec_filter = record_filter(record)
        cfg_filter = config_filter(view)

        found_any = False

        for direct, key in self.build_keys(label):
            result = filter(rec_filter, self.cache.get(key, []))

            for (rr, configs) in result:
                if not any(filter(cfg_filter, configs)):
                    continue

                found_any = True
                yield rr

            if found_any:
                break

    def unqiue_generator(self, gen):
        unique = set()

        for r in gen:
            if r in unique:
                continue
            yield r
            unique.add(r)

    def iquery(self, label, record=None, view=None, unique=False):
        if '*' in label:
            gen = self.wildcard_iquery(label, record=record, view=view)
        else:
            gen = self.regular_iquery(label, record=record, view=view)

        if unique:
            return self.unqiue_generator(gen)

        return gen

    def query(self, label, **kw):
        return list(self.iquery(label, **kw))

    def q(self, name, **kw):
        """
        Helper function that prints the results directly.
        """
        c = -1

        for c, rr in enumerate(self.iquery(name, **kw)):
            print "{0:05}: {1}".format(c, str(rr))

        print "{0} record(s)".format(c + 1)

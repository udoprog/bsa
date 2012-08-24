import ipaddr


def reversed_address(address):
    """
    Generate the reverse address assuming that the argument has an attribute
    named 'packed' that returns the address packed in octet by octet form.

    The length of the packed form determines address type.
        4: IPv4
        16: IPv6
    """
    if isinstance(address, basestring):
        address = ipaddr.IPAddress(address)

    tuples = tuple(reversed(map(str, map(ord, address.packed))))

    if len(tuples) == 16:
        return "{0}.ip6.arpa".format(".".join(tuples))
    elif len(tuples) == 4:
        return "{0}.in-addr.arpa".format(".".join(tuples))

    raise ValueError("Invalid argument length: {0}".format(len(tuples)))


def normalize_label(label):
    if not label.endswith("."):
        return label + "."
    return label


def join_origin(label, origin):
    """
    Join a label with it's origin, depending on if it's absolute or not.
    """
    if not origin.endswith("."):
        origin += "."

    label = label.replace("@", origin)

    if not label.endswith("."):
        if origin == ".":
            return label + "."

        return label + "." + origin

    return label


def domain_in(label, domains):
    return any(label.endswith(domain) for domain in domains)


def generate_records(db, record_type):
    for (zone, configs) in db.zones:
        for rr in zone:
            if rr.record_type == record_type:
                yield rr


def generate_soa_domains(db):
    for rr in generate_records(db, 'SOA'):
        yield rr.resolved_label

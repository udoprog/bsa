from bsa.utils import generate_soa_domains
from bsa.utils import generate_records
from bsa.utils import domain_in


def run(db, reporter):
    """
    Check all CNAMEs within the database that they actually point to something.

    Decide which domains to check depending on available SOA records.
    """

    checked_zones = set(generate_soa_domains(db))

    for rr in generate_records(db, 'CNAME'):
        if not domain_in(rr.resolved_target, checked_zones):
            continue

        lookup = rr.resolved_target

        if db.query(lookup, record=['A', 'NS', 'CNAME', 'PTR']):
            continue

        reporter.error(
            "Missing target [A, NS, CNAME, PTR]: {0} ({1})".format(
                lookup, repr(rr)))

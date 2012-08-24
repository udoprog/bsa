from bsa.utils import generate_soa_domains
from bsa.utils import generate_records
from bsa.utils import domain_in


def run(db, reporter):
    """
    Check that all A-records have a corresponding PTR record.

    Decide which domains to check depending on available SOA records.
    """

    checked_zones = set(generate_soa_domains(db))

    for rr in generate_records(db, 'SRV'):
        if not domain_in(rr.resolved_label, checked_zones):
            continue

        lookup = rr.resolved_target

        if not domain_in(lookup, checked_zones):
            continue

        if db.query(lookup, record=['A', 'NS', 'CNAME']):
            continue

        reporter.error(
            "Missing target [A, NS, CNAME]: {0}: ({1})".format(
                lookup, repr(rr)))

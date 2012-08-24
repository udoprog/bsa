from bsa.utils import reversed_address
from bsa.utils import domain_in
from bsa.utils import generate_soa_domains
from bsa.utils import generate_records


def run(db, reporter):
    """
    Check that all A-records have a corresponding PTR record.

    Decide which domains to check depending on available SOA records.
    """

    checked_zones = set(generate_soa_domains(db))

    for rr in generate_records(db, 'A'):
        if not domain_in(rr.resolved_label, checked_zones):
            continue

        lookup = reversed_address(rr.address)

        if db.query(lookup, record=['PTR', 'CNAME']):
            continue

        reporter.error(
            "Missing reverse [PTR, CNAME]: {0} ({1})".format(
                lookup, repr(rr)))

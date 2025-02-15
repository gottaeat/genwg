import logging

import dns.resolver


class DNSOps:
    def __init__(self):
        self.resolver = None
        self.logger = logging.getLogger()
        self._init_resolver()

    def _init_resolver(self):
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    def resolve_dns(self, domain):
        records_a = []
        records_aaaa = []

        # resolve both
        for record_type in ["A", "AAAA"]:
            try:
                answers = self.resolver.resolve(domain, record_type)
                if record_type == "A":  # Fixed the comparison operator
                    records_a.extend([str(answer) for answer in answers])
                else:
                    records_aaaa.extend([str(answer) for answer in answers])
            except:
                continue

        # prefer the first A record if found
        if records_a:
            return records_a[0]

        # if no A, prefer the first AAAA
        if records_aaaa:
            return records_aaaa[0]

        # if none found, die
        return self.logger.error("no A or AAAA records found for: %s", domain)

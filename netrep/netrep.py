import csv
import math
import os
import re
from collections import defaultdict
from urllib.parse import urlparse

from ail_typo_squatting import runAll
from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultKeyValueSection, ResultTableSection, TableRow

NETWORK_IOC_TYPES = ["domain", "ip", "uri"]


class NetRep(ServiceBase):
    def __init__(self, config=None):
        super(NetRep, self).__init__(config)
        self.top_1m = set()
        self.bad_iocs = dict()

        top_1m_file = os.environ.get("TOP_1M_CSV", "top-1m.csv")
        if os.path.exists(top_1m_file):
            self.top_1m = set(line[1] for line in csv.reader(open(top_1m_file), delimiter=","))

        self.safelist_interface = self.get_api_interface().get_safelist
        self.safelist_regex = None
        self.safelist_match = []
        # Instantiate safelist(s)
        try:
            safelist = self.safelist_interface(
                [
                    "network.static.uri",
                    "network.dynamic.uri",
                    "network.static.domain",
                    "network.dynamic.domain",
                    "network.static.ip",
                    "network.dynamic.ip",
                ]
            )
            regex_list = []

            # Extend with safelisted matches
            [self.safelist_match.extend(match_list) for _, match_list in safelist.get("match", {}).items()]

            # Extend with safelisted regex
            [regex_list.extend(regex_) for _, regex_ in safelist.get("regex", {}).items()]

            self.safelist_regex = re.compile("|".join(regex_list))

        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service server: {e}. Continuing without it..")

    def _clear_rules(self) -> None:
        # Clear map
        self.bad_iocs = dict()

    def _load_rules(self) -> None:
        for rule_file in self.rules_list:
            self.log.debug(f"Parsing {rule_file}")
            source, ioc_type = rule_file.split(os.sep)[-2:]
            self.bad_iocs.setdefault(ioc_type, list()).append(
                (source, set([r.strip() for r in open(rule_file, "r").readlines()]))
            )

        if self.bad_iocs:
            self.log.debug(self.bad_iocs)
            self.log.info("Reputation list found.")
        else:
            self.log.warning("Reputation list missing. Service will only perform typosquatting detection..")

    def execute(self, request):
        result = Result()

        # Gather existing network tags from AL
        iocs = defaultdict(list)

        for net_ioc_type in NETWORK_IOC_TYPES:
            [
                iocs[net_ioc_type].append(x)
                for k, v in request.task.tags.items()
                if net_ioc_type in k and v not in iocs[net_ioc_type]
                for x in v
            ]

        # Pre-filter network IOCs based on AL safelist
        if self.safelist_regex or self.safelist_match:

            def filter_items(x_list: list):
                regex_matches = list(filter(self.safelist_regex.match, x_list))
                # Remove on regex and exact matches
                [x_list.remove(match_item) for match_item in regex_matches]
                [x_list.remove(x) for x in x_list if any(match_item in x for match_item in self.safelist_match)]

            [filter_items(iocs[net_ioc_type]) for net_ioc_type in NETWORK_IOC_TYPES]

        # Check to see if IOCs are known to have a bad reputation
        for ioc_type, ioc_values in iocs.items():
            if not ioc_values:
                continue

            ioc_section = ResultKeyValueSection(f"Bad {ioc_type.upper()}s", heuristic=Heuristic(1))
            for source, bad_ioc_values in self.bad_iocs.get(ioc_type, []):
                confirmed_bad_iocs = set(ioc_values).intersection(bad_ioc_values)
                if confirmed_bad_iocs:
                    self.log.info(f"{ioc_type.upper()}s found with a bad reputation from {source}")
                    ioc_section.set_item(source, list(confirmed_bad_iocs))
                    [ioc_section.add_tag(f"network.static.{ioc_type}", i) for i in confirmed_bad_iocs]
            if ioc_section.body:
                result.add_section(ioc_section)

        # Perform typosquatting checks against top 1M (only applicable to domains)
        typo_table = ResultTableSection("Domain Typosquatting", heuristic=Heuristic(2))
        for domain in iocs["domain"] + [urlparse(uri).hostname for uri in iocs["uri"]]:
            if not isinstance(domain, str):
                if domain:
                    self.log.warning(f"Non-string {domain} found when performing typosquatting check")
                # Skip if given domain isn't a string
                continue
            elif re.match(IP_ONLY_REGEX, domain):
                # Can't perform typosquatting checks on IPs
                continue
            elif domain in self.top_1m:
                # Make sure domain doesn't exist in the top 1M
                continue

            # Generate variations of the domain and see if a variant is a legitimate domain
            legitimate_domains = set(runAll(domain, math.inf, "text", None)).intersection(self.top_1m)
            if legitimate_domains:
                # Add to table
                typo_table.add_row(
                    TableRow({"TYPOSQUATTED DOMAIN": domain, "TOP 1M DOMAIN COLLISION": list(legitimate_domains)})
                )
                typo_table.add_tag("network.static.domain", domain)

        # Phishing techniques
        phishing_table = ResultTableSection("Suspected Phishing URIs", heuristic=Heuristic(3))
        for uri in iocs["uri"]:
            parsed_url = urlparse(uri)

            if parsed_url.username or parsed_url.password:
                phishing_table.add_row(TableRow({"URI": uri, "Reason": "Basic authentication included in URI"}))
                phishing_table.add_tag("network.static.uri", uri)

        if typo_table.body:
            result.add_section(typo_table)

        if phishing_table.body:
            result.add_section(phishing_table)

        request.result = result

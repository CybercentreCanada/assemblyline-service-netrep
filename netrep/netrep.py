import csv
import json
import math
import os
import re
from collections import defaultdict
from typing import Dict, Set
from urllib.parse import urlparse

from ail_typo_squatting import runAll
from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultTableSection, TableRow

NETWORK_IOC_TYPES = ["domain", "ip", "uri"]


class NetRep(ServiceBase):
    def __init__(self, config=None):
        super(NetRep, self).__init__(config)
        self.blocklist: Dict[str, Dict] = None

        self.top_1m: Set[str] = set()
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

    def _load_rules(self) -> None:
        if os.path.exists(os.path.join(self.rules_directory, "blocklist.json")):
            with open(os.path.join(self.rules_directory, "blocklist.json")) as fp:
                self.blocklist = json.load(fp)

        if self.blocklist:
            self.log.info(f"Reputation list found for: {list(self.blocklist.keys())}")
            for ioc_type in NETWORK_IOC_TYPES:
                self.blocklist.setdefault(ioc_type, {})
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

        confirmed_ioc_section = ResultTableSection("Confirmed Bad", heuristic=Heuristic(1))

        known_bad_domains = set()
        # Check to see if IOCs are known to have a bad reputation
        for ioc_type, ioc_values in iocs.items():
            if not ioc_values:
                continue

            # Determine if any of the IOCs are within the known bad lists
            for ioc_value, doc in [
                (v, self.blocklist[ioc_type][v]) for v in ioc_values if self.blocklist[ioc_type].get(v)
            ]:
                confirmed_ioc_section.add_row(
                    TableRow(
                        {
                            "BLOCKLIST SOURCE(S)": doc["source"],
                            "IOC": ioc_value,
                            "TYPE": ioc_type.upper(),
                            "MALWARE_FAMILY": doc["malware_family"],
                        }
                    )
                )
                confirmed_ioc_section.add_tag(f"network.static.{ioc_type}", ioc_value)
                [confirmed_ioc_section.add_tag("attribution.family", f) for f in doc["malware_family"]]
                # If IOC type is a URI, extract the domain/IP and tag it as well if found in blocklist
                if ioc_type == "uri":
                    hostname = urlparse(ioc_value).hostname
                    host_type = "ip" if re.match(IP_ONLY_REGEX, hostname) else "domain"
                    if self.blocklist[host_type].get(hostname):
                        # Add this host to the list of known bad domains to avoid typo squatting checks
                        known_bad_domains.add(hostname)
                        confirmed_ioc_section.add_tag(f"network.static.{host_type}", hostname)
                elif ioc_type == "domain":
                    # Add this domain to the list of known bad domains to avoid typo squatting checks
                    known_bad_domains.add(ioc_value)

        # If there's notable content, append to parent section
        if confirmed_ioc_section.body:
            result.add_section(confirmed_ioc_section)

        if request.get_param("enable_typosquatting_check"):
            # Perform typosquatting checks against top 1M (only applicable to domains)
            self.log.info("Performing typosquat check..")
            typo_table = ResultTableSection("Domain Typosquatting", heuristic=Heuristic(3))
            for domain in set(iocs["domain"] + [urlparse(uri).hostname for uri in iocs["uri"]]) - known_bad_domains:
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
                        TableRow(
                            {
                                "TYPOSQUATTED DOMAIN": domain,
                                "TOP 1M DOMAIN COLLISION": list(legitimate_domains),
                            }
                        )
                    )
                    typo_table.add_tag("network.static.domain", domain)

        # Phishing techniques
        phishing_table = ResultTableSection("Suspected Phishing URIs", heuristic=Heuristic(4))
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

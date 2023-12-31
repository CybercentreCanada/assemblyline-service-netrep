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
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection, ResultTableSection, TableRow

from netrep.utils.network import NETWORK_IOC_TYPES, url_analysis


class NetRep(ServiceBase):
    def __init__(self, config=None):
        super(NetRep, self).__init__(config)
        self.blocklists: Dict[str, Dict] = {}

        self.top_domain: Set[str] = set()
        top_domain_file = os.environ.get("TOP_DOMAIN_CSV", "cloudflare-radar-domains-top-2000")
        if os.path.exists(top_domain_file):
            self.top_domain = set(line[0] for line in csv.reader(open(top_domain_file), delimiter=","))

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
        self.blocklists = {}
        for blocklist_name in os.listdir(self.rules_directory):
            if blocklist_name not in list(self.config["updater"].keys()):
                continue
            with open(os.path.join(self.rules_directory, blocklist_name)) as fp:
                self.blocklists[blocklist_name] = json.load(fp)
                for ioc_type in NETWORK_IOC_TYPES:
                    self.blocklists[blocklist_name].setdefault(ioc_type, {})

        if self.blocklists:
            self.log.info(f"Reputation list found for sources: {list(self.blocklists.keys())}")
        else:
            self.log.warning("Reputation list missing. Service will only perform typosquatting detection..")

    def execute(self, request: ServiceRequest):
        result = Result()

        # Gather existing network tags from AL
        iocs = defaultdict(list)

        disable_host_check = request.get_param('disable_host_check')
        for net_ioc_type in NETWORK_IOC_TYPES:
            [
                iocs[net_ioc_type].append(x)
                for k, v in request.task.tags.items()
                if net_ioc_type in k and v not in iocs[net_ioc_type]
                for x in v
            ]

        # Check to see if any of the domains tagged are email domains
        # If so, this service isn't qualified to determine the maliciousness of email domains therefore remove from set
        email_addresses = [eml.lower() for eml in request.task.tags.get("network.email.address", [])]
        email_domains = {email.split("@", 1)[-1] for email in email_addresses}
        iocs["domain"] = list(set(iocs["domain"]) - email_domains)

        if request.file_type.startswith("uri/"):
            iocs["uri"].append(request.task.fileinfo.uri_info.uri)
            if re.match(IP_ONLY_REGEX, request.task.fileinfo.uri_info.hostname):
                iocs["ip"].append(request.task.fileinfo.uri_info.hostname)
            else:
                iocs["domain"].append(request.task.fileinfo.uri_info.hostname)

        # Filter out URIs that are emails prefixed by http/s
        # (commonly tagged by OLETools but causes phishing heuristic to be raised because of '@')
        def filter_out_http_emails(x):
            parsed_url = urlparse(x.lower())
            if (
                parsed_url.scheme.startswith("http")
                and parsed_url.netloc in email_addresses
                and (parsed_url.path == "/" or not parsed_url.path)
            ):
                return False
            return True

        iocs["uri"] = list(filter(filter_out_http_emails, iocs["uri"]))

        # Pre-filter network IOCs based on AL safelist
        if self.safelist_regex or self.safelist_match:

            def filter_items(x_list: list):
                regex_matches = list(filter(self.safelist_regex.match, x_list))
                # Remove on regex and exact matches
                [x_list.remove(match_item) for match_item in regex_matches]
                [x_list.remove(x) for x in x_list if any(match_item in x for match_item in self.safelist_match)]

            [filter_items(iocs[net_ioc_type]) for net_ioc_type in NETWORK_IOC_TYPES]

        # Look for data that might be embedded in URLs
        url_analysis_section = ResultSection("URL Analysis")
        for url in set(iocs["uri"]):
            analysis_table, iocs_extracted = url_analysis(url)
            if analysis_table.body:
                url_analysis_section.add_subsection(analysis_table)
                # Merge found IOCs into list for reputation checks
                for ioc_type in NETWORK_IOC_TYPES:
                    iocs[ioc_type] = iocs[ioc_type] + iocs_extracted[ioc_type]

        confirmed_ioc_section = ResultSection("Confirmed Bad")

        known_bad_domains = set()
        for source, blocklist in self.blocklists.items():
            section = ResultTableSection(
                f"Blocklist Source: {source}",
                heuristic=Heuristic(1),
                classification=self.signatures_meta[source]["classification"],
            )

            # Check to see if IOCs are known to have a bad reputation
            for ioc_type, ioc_values in iocs.items():
                if not ioc_values:
                    continue

                if ioc_type in ['domain', 'ip'] and disable_host_check:
                    # We're not going to perform any checks against a IP/domain
                    continue

                # Determine if any of the IOCs are within the known bad lists
                for ioc_value, doc in [
                    (v, blocklist[ioc_type][v.lower()]) for v in ioc_values if blocklist[ioc_type].get(v.lower())
                ]:
                    # Add columns selectively only if they have information
                    row_data = {
                        "IOC": ioc_value,
                    }

                    for extra_info in ["malware_family", "attribution", "references"]:
                        if doc.get(extra_info):
                            row_data[extra_info.upper()] = doc[extra_info]

                    row_data = TableRow(row_data)
                    if row_data not in section.section_body._data:
                        # If we haven't seen this record before, then add it to the table
                        section.add_row(row_data)

                    section.add_tag(f"network.static.{ioc_type}", ioc_value)
                    [section.add_tag("attribution.family", f) for f in doc["malware_family"]]
                    [section.add_tag("attribution.actor", f) for f in doc.get("attribution", [])]
                    # If IOC type is a URI, extract the domain/IP and tag it as well if found in blocklist
                    if ioc_type == "uri":
                        hostname = urlparse(ioc_value).hostname
                        host_type = "ip" if re.match(IP_ONLY_REGEX, hostname) else "domain"
                        if any(b[host_type].get(hostname) for b in self.blocklists.values()):
                            # Add this host to the list of known bad domains to avoid typo squatting checks
                            known_bad_domains.add(hostname)
                            section.add_tag(f"network.static.{host_type}", hostname)
                    elif ioc_type == "domain":
                        # Add this domain to the list of known bad domains to avoid typo squatting checks
                        known_bad_domains.add(ioc_value)

            if section.body:
                section.section_body._data = sorted(section.section_body._data, key=lambda x: x["IOC"])
                confirmed_ioc_section.add_subsection(section)

        # If there's notable content, append to parent section
        if confirmed_ioc_section.subsections:
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
                elif domain in self.top_domain:
                    # Make sure domain doesn't exist in the top 1M
                    continue

                # Generate variations of the domain and see if a variant is a legitimate domain
                legitimate_domains = set(runAll(domain, math.inf, "text", None)).intersection(self.top_domain)
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

            if typo_table.body:
                result.add_section(typo_table)

        if url_analysis_section.subsections:
            # Add section to results
            result.add_section(url_analysis_section)

        request.result = result

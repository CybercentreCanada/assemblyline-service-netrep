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
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection, ResultTableSection, TableRow
from multidecoder.decoders.base64 import BASE64_RE
from multidecoder.decoders.network import DOMAIN_TYPE, EMAIL_TYPE, IP_TYPE, URL_TYPE, parse_url
from multidecoder.multidecoder import Multidecoder
from multidecoder.node import Node
from multidecoder.string_helper import make_bytes

NETWORK_IOC_TYPES = ["domain", "ip", "uri"]


class NetRep(ServiceBase):
    def __init__(self, config=None):
        super(NetRep, self).__init__(config)
        self.blocklists: Dict[str, Dict] = None

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

        # Look for data that might be embedded in URLs
        md = Multidecoder()
        url_analysis = ResultTableSection("URL Analysis")
        for url in set(iocs["uri"]):
            # Process URL and see if there's any IOCs contained within
            parsed_url = parse_url(make_bytes(url))
            query: Node = ([node for node in parsed_url if node.type == "network.url.query"] + [None])[0]
            fragment: Node = ([node for node in parsed_url if node.type == "network.url.fragment"] + [None])[0]

            # Analyze query/fragment for base64 encoded http | https URLs
            for segment in [query, fragment]:

                def add_MD_results_to_table(result: Node):
                    decoded_type = result.children[0].children[0].type
                    decoded_content = result.children[0].children[0].value.decode()
                    url_analysis.add_row(
                        TableRow(
                            {
                                "URL": url,
                                "COMPONENT": segment.type.split(".")[-1].upper(),
                                "OBFUSCATION": " → ".join(
                                    [
                                        result.value.decode(),
                                        # First layer should be obfuscation technique
                                        result.children[0].obfuscation,
                                        # Second layer should be the IOC
                                        decoded_content,
                                    ]
                                ),
                            }
                        )
                    )
                    if decoded_type == EMAIL_TYPE:
                        url_analysis.add_tag("network.email.address", decoded_content)
                    elif decoded_type == URL_TYPE:
                        url_analysis.add_tag("network.static.uri", decoded_content)
                        iocs["uri"].append(decoded_content)
                        # Extract the host and append to tagging/set to be analyzed
                        host_node = result.children[0].children[0].children[1]
                        if host_node.type == DOMAIN_TYPE:
                            url_analysis.add_tag("network.static.domain", host_node.value)
                            iocs["domain"].append(host_node.value.decode())
                        elif host_node.type == IP_TYPE:
                            url_analysis.add_tag("network.static.ip", host_node.value)
                            iocs["ip"].append(host_node.value.decode())

                    elif decoded_type == DOMAIN_TYPE:
                        url_analysis.add_tag("network.static.domain", decoded_content)
                        iocs["domain"].append(decoded_content)
                    elif decoded_type == IP_TYPE:
                        url_analysis.add_tag("network.static.ip", decoded_content)
                        iocs["ip"].append(decoded_content)

                if segment and re.search(BASE64_RE, segment.value):
                    scan_result = md.scan_node(segment)
                    if scan_result.children:
                        # Something was found while analyzing
                        add_MD_results_to_table(scan_result)
                    else:
                        # Nothing was found by MD so we'll have to perform some manual extraction
                        for b64_match in re.finditer(BASE64_RE, segment.value):
                            # htt → base64 → aHR0
                            b64_string = b64_match.group()
                            if b"aHR0" in b64_string:
                                b64_string = b64_string[b64_string.index(b"aHR0") :]
                                remaining_characters = len(b64_string) % 4

                                # Perfect base64 length
                                if not remaining_characters:
                                    pass
                                # Imperfect length, adding padding is required if there's at most 2 characters missing
                                elif remaining_characters >= 2:
                                    b64_string += b"=" * (4 - remaining_characters)
                                # Imperfect length and padding with 3 "=" doesn't make sense, start removing characters
                                else:
                                    b64_string = b64_string[:-3]

                                scan_result = md.scan(b64_string)

                                if scan_result.children:
                                    add_MD_results_to_table(scan_result)

        # Check to see if any of the domains tagged are email domains
        # If so, this service isn't qualified to determine the maliciousness of email domains therefore remove from set
        email_addresses = [eml.lower() for eml in request.task.tags.get("network.email.address", [])]
        email_domains = {email.split("@", 1)[-1] for email in email_addresses}
        iocs["domain"] = list(set(iocs["domain"]) - email_domains)

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

                    section.add_row(TableRow(row_data))

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

        # Phishing techniques
        phishing_table = ResultTableSection("Suspected Phishing URIs", heuristic=Heuristic(4))
        for uri in iocs["uri"]:
            parsed_url = urlparse(uri)

            if parsed_url.username or parsed_url.password:
                phishing_table.add_row(TableRow({"URI": uri, "Reason": "Basic authentication included in URI"}))
                phishing_table.add_tag("network.static.uri", uri)

        if phishing_table.body:
            result.add_section(phishing_table)

        if url_analysis.body:
            # Add section to results
            result.add_section(url_analysis)

        request.result = result

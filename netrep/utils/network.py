import binascii
import re
from base64 import b64decode
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline_v4_service.common.result import ResultTableSection, TableRow
from multidecoder.decoders.base64 import BASE64_RE
from multidecoder.decoders.network import DOMAIN_TYPE, EMAIL_TYPE, IP_TYPE, URL_TYPE, parse_url
from multidecoder.multidecoder import Multidecoder
from multidecoder.node import Node
from multidecoder.string_helper import make_bytes, make_str

NETWORK_IOC_TYPES = ["domain", "ip", "uri"]


def url_analysis(url: str) -> Tuple[ResultTableSection, Dict[str, List[str]]]:
    md = Multidecoder()

    analysis_table = ResultTableSection(url[:128] + "..." if len(url) > 128 else url)
    network_iocs = {"uri": [], "domain": [], "ip": []}

    def add_MD_results_to_table(result: Node):
        if result.obfuscation:
            try:
                # Attempt to decode decoded string
                result.value.decode()
            except UnicodeDecodeError:
                # Garbage string decoded
                return

            # Analysis pertains to deobfuscated content
            analysis_table.add_row(
                TableRow(
                    {
                        "COMPONENT": segment.type.split(".")[-1].upper(),
                        "ENCODED STRING": make_str(result.original),
                        "OBFUSCATION": result.obfuscation,
                        "DECODED STRING": make_str(result.value),
                    }
                )
            )

            # Overwrite result for tagging
            if result.children:
                result = result.children[0]
        elif result.type == URL_TYPE:
            # Analysis pertains to URL that was extracted from parent (assume URL encoding)
            inner_url = make_str(result.value)
            analysis_table.add_row(
                TableRow(
                    {
                        "COMPONENT": segment.type.split(".")[-1].upper(),
                        "ENCODED STRING": make_str(result.parent.value),
                        "OBFUSCATION": "encoding.url",
                        "DECODED STRING": inner_url,
                    }
                )
            )
            inner_analysis_section, inner_network_iocs = url_analysis(inner_url)
            if inner_analysis_section.body:
                # If we were able to analyze anything of interest recursively, append to result
                analysis_table.add_subsection(inner_analysis_section)
                # Merge found IOCs
                for ioc_type in NETWORK_IOC_TYPES:
                    network_iocs[ioc_type] = network_iocs[ioc_type] + inner_network_iocs[ioc_type]

        if result.parent.type == result.type:
            # This value is derived from the parent which has the "correct" component value
            result.value = result.parent.value

        tagged_type, tagged_content = result.type, make_str(result.value)
        if tagged_type == EMAIL_TYPE:
            analysis_table.add_tag("network.email.address", tagged_content)
        elif tagged_type == URL_TYPE:
            analysis_table.add_tag("network.static.uri", tagged_content)
            network_iocs["uri"].append(tagged_content)
            # Extract the host and append to tagging/set to be analyzed
            host_node = ([node for node in result.children if node.type in ["network.ip", "network.domain"]] + [None])[
                0
            ]
            if not host_node:
                pass
            elif host_node.type == DOMAIN_TYPE:
                analysis_table.add_tag("network.static.domain", host_node.value)
                network_iocs["domain"].append(host_node.value.decode())
            elif host_node.type == IP_TYPE:
                analysis_table.add_tag("network.static.ip", host_node.value)
                network_iocs["ip"].append(host_node.value.decode())

        elif tagged_type == DOMAIN_TYPE:
            analysis_table.add_tag("network.static.domain", tagged_content)
            network_iocs["domain"].append(tagged_content)
        elif tagged_type == IP_TYPE:
            analysis_table.add_tag("network.static.ip", tagged_content)
            network_iocs["ip"].append(tagged_content)

    # Process URL and see if there's any IOCs contained within
    try:
        parsed_url = parse_url(make_bytes(url))
    except UnicodeDecodeError:
        parsed_url = []
        for component, value in urlparse(url)._asdict().items():
            if component == "netloc":
                host = value
                username = password = None
                if "@" in host:
                    password = None
                    username, host = host.rsplit("@", 1)
                    if ":" in username:
                        username, password = username.split(":", 1)
                parsed_url.append(
                    Node("network.ip" if re.match(IP_ONLY_REGEX, host) else "network.domain", make_bytes(host))
                )
                if username:
                    parsed_url.append(Node("network.url.username", make_bytes(username)))
                if password:
                    parsed_url.append(Node("network.url.password", make_bytes(password)))
            else:
                parsed_url.append(Node(f"network.url.{component}", make_bytes(value)))

    scheme: Node = ([node for node in parsed_url if node.type == "network.url.scheme"] + [None])[0]
    host: Node = ([node for node in parsed_url if node.type in ["network.ip", "network.domain"]] + [None])[0]
    username: Node = ([node for node in parsed_url if node.type == "network.url.username"] + [None])[0]
    query: Node = ([node for node in parsed_url if node.type == "network.url.query"] + [None])[0]
    fragment: Node = ([node for node in parsed_url if node.type == "network.url.fragment"] + [None])[0]

    # Check to see if there's anything "phishy" about the URL
    if username and host.type == "network.domain":
        scheme = "http" if not scheme else scheme.value.decode()
        domain = host.value.decode()
        target_url = f"{scheme}://{url[url.index(domain):]}"
        if b"@" in username.value:
            # Looks like URL might be masking the actual target
            analysis_table.add_row(
                TableRow(
                    {
                        "COMPONENT": "URL",
                        "ENCODED STRING": url,
                        "OBFUSCATION": "URL masquerade",
                        "DECODED STRING": target_url,
                    }
                )
            )
            analysis_table.set_heuristic(4, signature="url_masquerade")
        else:
            # This URL has auth details embedded in the URL, weird
            analysis_table.add_row(
                TableRow(
                    {
                        "COMPONENT": "URL",
                        "ENCODED STRING": url,
                        "OBFUSCATION": "Embedded credentials",
                        "DECODED STRING": target_url,
                    }
                )
            )
            analysis_table.set_heuristic(4, signature="embedded_credentials")
        analysis_table.add_tag("network.static.uri", url)
        analysis_table.add_tag("network.static.uri", target_url)
        network_iocs["uri"].append(target_url)
        network_iocs["domain"].append(domain)

    # Analyze query/fragment
    for segment in [host, query, fragment]:
        if segment:
            if segment.type == "network.ip":
                # Check for IP obfuscation
                if segment.obfuscation:
                    # Add original URL as a parent node
                    if not segment.parent:
                        segment.parent = Node("network.url", url)
                    add_MD_results_to_table(segment)
            scan_result = md.scan_node(segment)
            if scan_result.children:
                # Something was found while analyzing
                for child in scan_result.children:
                    add_MD_results_to_table(child)
            #  Check for base64 encoded http | https URLs that MD didn't initially detect
            elif re.search(BASE64_RE, segment.value):
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
                            b64_string = b64_string[:-1]

                        scan_result = md.scan(b64_string)

                        if scan_result.children:
                            for child in scan_result.children:
                                add_MD_results_to_table(child)
                        else:
                            try:
                                # Attempt decoding manually
                                scan_result = md.scan(b64decode(b64_string))
                                # Manipulate the result to preserve the encoded → decoded process
                                scan_result = Node(
                                    "",
                                    b64_string,
                                    "",
                                    0,
                                    0,
                                    None,
                                    children=[
                                        Node(
                                            "",
                                            scan_result.value,
                                            "encoding.base64",
                                            0,
                                            0,
                                            None,
                                            children=scan_result.children,
                                        )
                                    ],
                                )
                                add_MD_results_to_table(scan_result.children[0])
                            except binascii.Error:
                                pass
    return analysis_table, {k: list(set(v)) for k, v in network_iocs.items()}

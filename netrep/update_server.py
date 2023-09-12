import csv
import json
import os
import re
from typing import List, Set
from urllib.parse import urlparse

from assemblyline.odm.base import DOMAIN_ONLY_REGEX, FULL_URI, IP_ONLY_REGEX
from assemblyline_v4_service.updater.updater import ServiceUpdater

IOC_CHECK = {
    "ip": re.compile(IP_ONLY_REGEX).match,
    "domain": re.compile(DOMAIN_ONLY_REGEX).match,
    "uri": re.compile(FULL_URI).match,
    "malware_family": lambda x: True,
}


IOC_TYPES = ["ip", "domain", "uri"]


class SetEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        return json.JSONEncoder.default(self, o)


class NetRepUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.top_domain: Set[str] = set()
        top_domain_file = os.environ.get("TOP_DOMAIN_CSV", "cloudflare-radar-domains-top-2000")
        if os.path.exists(top_domain_file):
            self.top_domain = set(line[0] for line in csv.reader(open(top_domain_file), delimiter=","))

        self.malware_families_path: str = os.path.join(self.latest_updates_dir, "malware_families.json")
        self.blocklist_path = os.path.join(self.latest_updates_dir, "blocklist.json")
        self.malware_families: Set[str] = set()

        if os.path.exists(self.malware_families_path):
            with open(self.malware_families_path, "r") as fp:
                self.malware_families = set(json.load(fp))

        self.log.info(f"{len(self.malware_families)} malware families loaded at startup")

    # A sanity check to make sure we do in fact have things to send to services
    def _inventory_check(self) -> bool:
        success = True

        def _trigger_update(source):
            self._current_source = source
            self.set_source_update_time(0)
            self.trigger_update()

        if os.path.exists(self.blocklist_path):
            with open(self.blocklist_path, "r") as blocklist_fp:
                blocklist_contents = blocklist_fp.read()
                found_sources = []
                for source in [
                    _s.name
                    for _s in self._service.update_config.sources
                    if self._service.config["updater"][_s.name]["type"] == "blocklist"
                ]:
                    if source not in blocklist_contents:
                        # If we can't find the source name in the blocklist, trigger an update
                        _trigger_update(source)
                        success = False
                    else:
                        found_sources.append(source)

                if found_sources:
                    # We have at least one blocklist source to work with for the time being
                    success = True
        else:
            for source in [_s.name for _s in self._service.update_config.sources]:
                _trigger_update(source)
            success = False

        return success

    def import_update(self, files_sha256, al_client, source_name, _):
        blocklist = {}
        if os.path.exists(self.blocklist_path):
            try:
                blocklist = json.load(open(self.blocklist_path))
            except Exception:
                pass

        if al_client.signature.sync:
            # If syncing is enabled, prune all records affiliated with source from blocklist
            tmp_blocklist = dict()
            for ioc_type, ioc_map in blocklist.items():
                tmp_blocklist[ioc_type] = {}
                for ioc_value, properties in ioc_map.items():
                    if source_name in properties["source"]:
                        # Remove source from list of sources that repute this IOC is malicious
                        properties["source"].remove(source_name)

                    if properties["source"]:
                        # Other sources still state this IOC is malicious
                        tmp_blocklist[ioc_type][ioc_value] = properties
            blocklist = tmp_blocklist

        def get_malware_families(data: str, validate=True) -> List[str]:
            if not data:
                return []

            # Normalize data (parsing based off Malpedia API output)
            malware_family = data.replace("-", "").replace("_", "").replace("#", "").lower()
            if "," in malware_family:
                malware_family = malware_family.split(",")
            else:
                malware_family = [malware_family]

            if not validate:
                return malware_family
            else:
                return [m for m in malware_family if m in self.malware_families]

        def update_blocklist(ioc_type, ioc_value, malware_family, references):
            blocklist.setdefault(ioc_type, {})

            # Check if we've seen this IOC before
            doc = blocklist[ioc_type].get(ioc_value)
            if doc:
                # Document already exists, therefore update
                doc["malware_family"] = list(set(doc["malware_family"] + malware_family))
                doc["source"] = list(set(doc["source"] + [source_name]))
                doc["references"] = list(set(doc.get("references", []) + references))
            else:
                # Document has yet to exist, therefore create
                doc = dict(malware_family=malware_family, source=[source_name], references=references)
            blocklist[ioc_type][ioc_value] = doc
            if ioc_type == "uri":
                # Is this IOC definitely malicious or questionable?
                # (ie. drive.google.com is in the top 1M but can be used for malicious purposes)
                hostname: str = urlparse(ioc_value).hostname
                for host_ioc_type, check in IOC_CHECK.items():
                    if check(hostname):
                        blocklist.setdefault(host_ioc_type, {})
                        if blocklist[host_ioc_type].get(hostname):
                            # Host is already known to be bad on another list
                            pass
                        else:
                            # Check to see if the host is a subdomain of one of the top 1M, if so don't block
                            # ie. s3.amazon.com isn't part of the top 1M but it is a subdomain of amazon.com which is
                            parent_domains: set = {hostname.split(".", x)[-1] for x in range(1, hostname.count("."))}
                            if parent_domains.intersection(self.top_domain):
                                pass
                            # Check to see if the host is known in the top 1M
                            elif hostname not in self.top_domain:
                                # If this isn't in the top 1M, assume the domain is outright malicious
                                # So properties of this maliciousness will be transferred
                                update_blocklist(
                                    host_ioc_type,
                                    hostname,
                                    doc["malware_family"],
                                    references=references,
                                )
                        break

        source_cfg = self._service.config["updater"][source_name]

        if source_cfg["type"] == "blocklist":
            # This source is meant to contribute to the blocklist
            ignore_terms = source_cfg.get("ignore_terms", [])
            if source_cfg["format"] == "csv":
                start_index = source_cfg.get("start", 0)
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        for row in list(csv.reader(fp, delimiter=","))[start_index:]:
                            joined_row = ",".join(row)
                            if any(t in joined_row for t in ignore_terms):
                                # Skip row
                                continue

                            references = [] if not source_cfg.get("reference") else [row[source_cfg["reference"]]]
                            # Get malware family
                            malware_family = (
                                get_malware_families(row[source_cfg["malware_family"]])
                                if source_cfg.get("malware_family")
                                else []
                            )

                            # Iterate over all IOC types
                            for ioc_type in IOC_TYPES:
                                if source_cfg.get(ioc_type) == None:
                                    continue
                                ioc_value = row[source_cfg[ioc_type]]

                                # If there are multiple IOC types in the same column, verify the IOC type
                                if not IOC_CHECK[ioc_type](ioc_value):
                                    continue
                                update_blocklist(ioc_type, ioc_value, malware_family, references)

            elif source_cfg["format"] == "json":
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        blocklist_data = json.load(fp)
                        if isinstance(blocklist_data, list):
                            for data in blocklist_data:
                                json_dump = json.dumps(data)
                                if any(t in json_dump for t in ignore_terms):
                                    # Skip block
                                    continue
                                references = (
                                    [] if not source_cfg.get("reference") else [data.get(source_cfg.get("reference"))]
                                )
                                malware_family = get_malware_families(data.get(source_cfg.get("malware_family")))
                                for ioc_type in IOC_TYPES:
                                    ioc_value = data.get(source_cfg.get(ioc_type))
                                    if ioc_value:
                                        update_blocklist(ioc_type, ioc_value, malware_family, references)
            # Commit list to disk
            with open(self.blocklist_path, "w") as fp:
                fp.write(json.dumps(blocklist))

        elif source_cfg["type"] == "malware_family_list":
            # This source is meant to contributes to the list of valid malware families
            if source_cfg["format"] == "list":
                # Expect a flat list containing a series to malware family names
                for file, _ in files_sha256:
                    # Add normalized family names to list
                    with open(file, "r") as fp:
                        for malware_family in json.load(fp):
                            self.malware_families = self.malware_families.union(
                                set(
                                    get_malware_families(
                                        malware_family.split(".", 1)[1],
                                        validate=False,
                                    )
                                )
                            )

            # Commit list to disk
            with open(self.malware_families_path, "w") as fp:
                fp.write(json.dumps(self.malware_families, cls=SetEncoder))


if __name__ == "__main__":
    with NetRepUpdateServer() as server:
        server.serve_forever()

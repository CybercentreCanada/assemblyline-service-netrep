import csv
import json
import os
import re
import shutil
import tempfile
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

        self.attributions_path: str = os.path.join(self.latest_updates_dir, "attribution.json")
        self.malware_families_path: str = os.path.join(self.latest_updates_dir, "malware_families.json")

        self.malware_families: Set[str] = set()
        self.attributions: Set[str] = set()

        if os.path.exists(self.malware_families_path):
            with open(self.malware_families_path, "r") as fp:
                self.malware_families = set(json.load(fp))

        if os.path.exists(self.attributions_path):
            with open(self.attributions_path, "r") as fp:
                self.attributions = set(json.load(fp))

        self.log.info(f"{len(self.malware_families)} malware families loaded at startup")
        self.log.info(f"{len(self.attributions)} attributions loaded at startup")

    # A sanity check to make sure we do in fact have things to send to services
    def _inventory_check(self) -> bool:
        success = True

        def _trigger_update(source):
            self._current_source = source
            self.set_source_update_time(0)
            self.trigger_update()

        if not os.path.exists(self.attributions_path):
            # Trigger an update for any sources that contribute to attributions list
            [
                _trigger_update(_s.name)
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"] == "attribution_list"
            ]

        if not os.path.exists(self.malware_families_path):
            # Trigger an update for any sources that contribute to the malware families list
            [
                _trigger_update(_s.name)
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"] == "malware_family_list"
            ]

        blocklist_sources = set(
            [
                _s.name
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"] == "blocklist"
            ]
        )
        missing_blocklists = blocklist_sources - set(os.listdir(self._update_dir))

        if missing_blocklists != blocklist_sources:
            # We have at least one blocklist source to work with for the time being
            success = True

        # Trigger an update for the blocklists that are missing
        [_trigger_update(source) for source in missing_blocklists]

        return success

    def import_update(self, files_sha256, al_client, source_name, _):
        blocklist = {}
        blocklist_path = os.path.join(self.latest_updates_dir, source_name)
        # If syncing is disabled and source blocklist exists, contribute to existing blocklist
        if os.path.exists(blocklist_path) and not al_client.signature.sync:
            try:
                blocklist = json.load(open(blocklist_path))
            except Exception:
                pass

        def sanitize_data(data: str, type: str, validate=True) -> List[str]:
            if not data:
                return []

            # Normalize data (parsing based off Malpedia API output)
            data = data.replace("-", "").replace("_", "").replace("#", "").lower()
            data = data.split(",") if "," in data else [data]

            if not validate:
                return data

            if type == "malware_family":
                return [d for d in data if d in self.malware_families]
            elif type == "attribution":
                return [d for d in data if d in self.attributions]

        def update_blocklist(
            ioc_type: str, ioc_value: str, malware_family: List[str], attribution: List[str], references: List[str]
        ):
            blocklist.setdefault(ioc_type, {})

            # Normalize IOC values for when performing lookups
            ioc_value = ioc_value.lower()

            # Check if we've seen this IOC before
            doc = blocklist[ioc_type].get(ioc_value)
            if doc:
                # Document already exists, therefore update
                doc["malware_family"] = list(set(doc["malware_family"] + malware_family))
                doc["references"] = list(set(doc.get("references", []) + references))
                doc["attribution"] = list(set(doc.get("attribution", []) + attribution))
            else:
                # Document has yet to exist, therefore create
                doc = dict(malware_family=malware_family, references=references, attribution=attribution)
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
                                    doc["attribution"],
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
                            references = [] if not source_cfg.get("reference") else [row[source_cfg["reference"]]]
                            # Get malware family
                            malware_family = (
                                sanitize_data(row[source_cfg["malware_family"]], type="malware_family")
                                if source_cfg.get("malware_family")
                                else []
                            )

                            # Get attribution
                            attribution = (
                                sanitize_data(row[source_cfg["attribution"]], type="attribution")
                                if source_cfg.get("attribution")
                                else []
                            )

                            # Iterate over all IOC types
                            for ioc_type in IOC_TYPES:
                                if source_cfg.get(ioc_type) is None:
                                    continue
                                ioc_value = row[source_cfg[ioc_type]]

                                # If there are multiple IOC types in the same column, verify the IOC type
                                if not IOC_CHECK[ioc_type](ioc_value):
                                    continue
                                update_blocklist(ioc_type, ioc_value, malware_family, attribution, references)

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
                                malware_family = sanitize_data(
                                    data.get(source_cfg.get("malware_family")), type="malware_family"
                                )

                                # Get attribution
                                attribution = sanitize_data(data.get(source_cfg.get("attribution")), type="attribution")

                                for ioc_type in IOC_TYPES:
                                    ioc_value = data.get(source_cfg.get(ioc_type))
                                    if ioc_value:
                                        update_blocklist(ioc_type, ioc_value, malware_family, attribution, references)
            # Commit list to disk
            with open(blocklist_path, "w") as fp:
                fp.write(json.dumps(blocklist))

        elif source_cfg["type"] == "malware_family_list":
            # This source is meant to contributes to the list of valid malware families
            if source_cfg["format"] == "list":
                # Expect a flat list containing a series of malware family names
                for file, _ in files_sha256:
                    # Add normalized family names to list
                    with open(file, "r") as fp:
                        for malware_family in json.load(fp):
                            self.malware_families = self.malware_families.union(
                                set(
                                    sanitize_data(
                                        malware_family.split(".", 1)[-1],
                                        type="malware_family",
                                        validate=False,
                                    )
                                )
                            )
        elif source_cfg["type"] == "attribution_list":
            # This source is meant to contributes to the list of valid attribution names
            if source_cfg["format"] == "list":
                # Expect a flat list containing a series of attribution names
                for file, _ in files_sha256:
                    # Add normalized family names to list
                    with open(file, "r") as fp:
                        # Let's assume no sanitization is required and just merge the set of names
                        self.attributions = self.attributions.union(
                            set(
                                sanitize_data(
                                    ",".join(json.load(fp)),
                                    type="attribution",
                                    validate=False,
                                )
                            )
                        )

            # Commit list to disk
            with open(self.malware_families_path, "w") as fp:
                fp.write(json.dumps(self.malware_families, cls=SetEncoder))

    # Define how to prepare the output directory before being served, must return the path of the directory to serve.
    def prepare_output_directory(self) -> str:
        output_directory = tempfile.mkdtemp()
        # Ignore the files that contribute to blocklist construction that the service doesn't need to have
        shutil.copytree(
            self.latest_updates_dir,
            output_directory,
            dirs_exist_ok=True,
            ignore=lambda _, y: [i for i in y if i.endswith(".json")],
        )

        return output_directory


if __name__ == "__main__":
    with NetRepUpdateServer() as server:
        server.serve_forever()

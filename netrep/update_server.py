import csv
import json
import os
import re
from typing import List, Set
from urllib.parse import urlparse

from assemblyline.odm.base import DOMAIN_ONLY_REGEX, FULL_URI, IP_ONLY_REGEX
from assemblyline_v4_service.updater.updater import ServiceUpdater
from tinydb import TinyDB
from tinydb.database import Document

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
        self.top_1m: Set[str] = set()
        top_1m_file = os.environ.get("TOP_1M_CSV", "top-1m.csv")
        if os.path.exists(top_1m_file):
            self.top_1m = set(
                line[1] for line in csv.reader(open(top_1m_file), delimiter=",")
            )

        self.malware_families_path: str = os.path.join(
            self.latest_updates_dir, "malware_families.json"
        )
        self.blocklist = TinyDB(os.path.join(self.latest_updates_dir, "blocklist.json"))
        # We're going to use the IOC value as the doc_ids
        self.blocklist.table_class.document_id_class = str

        self.malware_families: Set[str] = set()

        if os.path.exists(self.malware_families_path):
            with open(self.malware_families_path, "r") as fp:
                self.malware_families = set(json.load(fp))

        self.log.info(
            f"{len(self.malware_families)} malware families loaded at startup"
        )

    # A sanity check to make sure we do in fact have things to send to services
    def _inventory_check(self) -> bool:
        return len(self.blocklist)

    def import_update(self, files_sha256, _, source_name, __):
        def get_malware_families(data: str, validate=True) -> List[str]:
            if not data:
                return []

            # Normalize data (parsing based off Malpedia API output)
            malware_family = (
                data.replace("-", "").replace("_", "").replace("#", "").lower()
            )
            if "," in malware_family:
                malware_family = malware_family.split(",")
            else:
                malware_family = [malware_family]

            if not validate:
                return malware_family
            else:
                return [m for m in malware_family if m in self.malware_families]

        def ioc_type_check(data: str) -> str:
            for type, func in IOC_CHECK.items():
                if func(data):
                    return type

        def update_blocklist(ioc_type, ioc_value, malware_family):
            table = self.blocklist.table(ioc_type)

            # Check if we've seen this IOC before
            doc = table.get(doc_id=ioc_value)
            if doc:
                # Document already exists, therefore update
                doc["malware_family"] = list(
                    set(doc["malware_family"] + malware_family)
                )
                doc["source"] = list(set(doc["source"] + [source_name]))
            else:
                # Document has yet to exist, therefore create
                doc = Document(
                    dict(
                        malware_family=malware_family,
                        source=[source_name],
                    ),
                    doc_id=ioc_value,
                )
            table.upsert(doc)

        source_cfg = self._service.config["updater"][source_name]

        if source_cfg["type"] == "blocklist":
            # This source is meant to contribute to the blocklist
            if source_cfg["format"] == "csv":
                data_map = dict()
                [
                    data_map.setdefault(source_cfg[data], []).append(data)
                    for data in ["uri", "ip", "domain", "malware_family"]
                    if source_cfg.get(data) is not None
                ]

                start_index = source_cfg.get("start", 0)
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        for row in [r.strip() for r in fp.readlines()][start_index:]:
                            if '","' in row:
                                row_data = [r.strip('"') for r in row.split('","')]
                            else:
                                row_data = row.split(",")
                            ioc_type, ioc_value, malware_family = None, None, []
                            for data_index, data_fields in data_map.items():
                                # Get data from index
                                data = row_data[data_index]
                                field_type = data_fields[0]
                                if len(data_fields) > 1:
                                    # Multiple types are selected for this column
                                    # Perform validation to see which one it likely belongs to
                                    field_type = ioc_type_check(data)

                                if field_type in IOC_TYPES:
                                    # Set IOC values
                                    ioc_type = field_type
                                    ioc_value = data
                                elif field_type == "malware_family":
                                    # Try to extract the malware family name if we can
                                    malware_family = get_malware_families(data)

                            if ioc_value:
                                update_blocklist(ioc_type, ioc_value, malware_family)

            elif source_cfg["format"] == "json":
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        blocklist_data = json.load(fp)
                        if isinstance(blocklist_data, list):
                            for data in blocklist_data:
                                malware_family = get_malware_families(
                                    data.get(source_cfg.get("malware_family"))
                                )
                                for ioc_type in IOC_TYPES:
                                    ioc_value = data.get(source_cfg.get(ioc_type))
                                    if ioc_value:
                                        update_blocklist(
                                            ioc_type, ioc_value, malware_family
                                        )

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
                                        malware_family.split(".", 1)[1], validate=False
                                    )
                                )
                            )

            # Commit list to disk
            with open(self.malware_families_path, "w") as fp:
                fp.write(json.dumps(self.malware_families, cls=SetEncoder))

        # Page through the URI table and flag hosts that aren't in the top 1M
        for record in self.blocklist.table("uri").all():
            # Is this IOC definitely malicious or questionable?
            # (ie. drive.google.com is in the top 1M but can be used for malicious purposes)
            hostname = urlparse(record.doc_id).hostname
            for ioc_type, check in IOC_CHECK.items():
                if check(hostname):
                    if self.blocklist.table(ioc_type).get(doc_id=hostname):
                        # Host is already known to be bad on another list
                        pass
                    else:
                        # Check to see if the host is known in the top 1M
                        if hostname not in self.top_1m:
                            # If this isn't in the top 1M, assume the domain is outright malicious
                            # So properties of this maliciousness will be transferred
                            update_blocklist(
                                ioc_type, hostname, record["malware_family"]
                            )
                    break


if __name__ == "__main__":
    with NetRepUpdateServer() as server:
        server.serve_forever()

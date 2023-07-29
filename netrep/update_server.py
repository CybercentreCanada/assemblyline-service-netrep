import json
import os
import re

from assemblyline.odm.base import DOMAIN_ONLY_REGEX, FULL_URI, IP_ONLY_REGEX
from assemblyline_v4_service.updater.updater import ServiceUpdater

IOC_CHECK = {
    "ip": re.compile(IP_ONLY_REGEX).match,
    "domain": re.compile(DOMAIN_ONLY_REGEX).match,
    "uri": re.compile(FULL_URI).match,
    "malware_family": lambda x: True,
}


IOC_TYPES = ["ip", "domain", "uri"]


class NetRepUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.malware_families_path = os.path.join(self.latest_updates_dir, "malware_families.json")
        self.blocklist_path = os.path.join(self.latest_updates_dir, "blocklist.json")
        self.malware_families = list()
        self.blocklist = dict()

        if os.path.exists(self.malware_families_path):
            with open(self.malware_families_path, "r") as fp:
                self.malware_families = json.load(fp)
        if os.path.exists(self.blocklist_path):
            with open(self.blocklist_path, "r") as fp:
                self.blocklist = json.load(fp)

        self.log.info(f"{len(self.malware_families)} malware families loaded at startup")

    # A sanity check to make sure we do in fact have things to send to services
    def _inventory_check(self) -> bool:
        self.log.info(self.blocklist_path)
        return os.path.exists(self.blocklist_path)

    def import_update(self, files_sha256, _, source_name, __):
        def normalize_malware_family(data: str) -> str:
            # Normalize data (parsing based off Malpedia API output)
            return data.replace("-", "").replace("_", "").replace("#", "").lower()

        def ioc_type_check(data: str) -> str:
            for type, func in IOC_CHECK.items():
                if func(data):
                    return type

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
                                    norm_mf = normalize_malware_family(data)
                                    if "," not in norm_mf:
                                        norm_mf = [norm_mf]
                                    else:
                                        norm_mf = norm_mf.split(",")

                                    for term in norm_mf:
                                        if term in self.malware_families:
                                            malware_family.append(term)
                            self.blocklist.setdefault(ioc_type, {}).setdefault(ioc_value, {})
                            self.blocklist[ioc_type][ioc_value].setdefault("malware_family", [])
                            self.blocklist[ioc_type][ioc_value].setdefault("source", [])

                            if source_name not in self.blocklist[ioc_type][ioc_value]["source"]:
                                self.blocklist[ioc_type][ioc_value]["source"].append(source_name)

                            if (
                                malware_family
                                and malware_family not in self.blocklist[ioc_type][ioc_value]["malware_family"]
                            ):
                                self.blocklist[ioc_type][ioc_value]["malware_family"] = list(
                                    set(self.blocklist[ioc_type][ioc_value]["malware_family"] + malware_family)
                                )

                # Commit blocklist to disk to send to service
                open(self.blocklist_path, "w").write(json.dumps(self.blocklist))

        elif source_cfg["type"] == "malware_family_list":
            # This source is meant to contributes to the list of valid malware families
            if source_cfg["format"] == "list":
                # Expect a flat list containing a series to malware family names
                for file, _ in files_sha256:
                    # Add normalized family names to list
                    [
                        self.malware_families.append(normalize_malware_family(malware_family.split(".", 1)[1]))
                        for malware_family in json.load(open(file, "r"))
                    ]

            # Eliminate duplicates
            self.malware_families = list(set(self.malware_families))

            # Commit list to disk
            open(self.malware_families_path, "w").write(json.dumps(self.malware_families))

        # for file, _ in files_sha256:
        #     # Parse file containing URIs, extract domains and IPs
        #     iocs = dict()

        #     # Collect any previous collected IOCs so we don't lose any between updates
        #     for ioc in ["ip", "domain", "uri"]:
        #         if os.path.exists(os.path.join(self.latest_updates_dir, source_name, ioc)):
        #             iocs[ioc] = set(open(os.path.join(self.latest_updates_dir, source_name, ioc), "r").readlines())

        #     for line in open(file, "r"):
        #         if line.startswith("#"):
        #             # Presumably some commenting from source (ie. urlhaus)
        #             continue
        #         line = line.strip()
        #         try:
        #             host = urlparse(line).hostname
        #             if re.match(IP_ONLY_REGEX, host):
        #                 # Bad IP
        #                 iocs.setdefault("ip", set()).add(host)
        #             else:
        #                 # Bad Domain?
        #                 iocs.setdefault("domain", set()).add(host)

        #             iocs.setdefault("uri", set()).add(line)
        #         except Exception as e:
        #             self.log.error(f'Problem parsing "{line}" in file from {source_name}: {e}')

        #     for ioc_type, ioc_values in iocs.items():
        #         # Store the IOCs in their respective source to make it easier to track
        #         if ioc_values:
        #             if not os.path.exists(os.path.join(self.latest_updates_dir, source_name)):
        #                 os.makedirs(os.path.join(self.latest_updates_dir, source_name))

        #             with open(os.path.join(self.latest_updates_dir, source_name, ioc_type), "w") as bl_writer:
        #                 bl_writer.write("\n".join(ioc_values))


if __name__ == "__main__":
    with NetRepUpdateServer() as server:
        server.serve_forever()

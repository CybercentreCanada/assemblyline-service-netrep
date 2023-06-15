import csv
import os
import re
from urllib.parse import urlparse

from assemblyline.odm.base import IP_ONLY_REGEX
from assemblyline_v4_service.updater.updater import ServiceUpdater


class NetRepUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Load top 1M to reduce FPs when performing source collection
        top_1m_file = os.environ.get("TOP_1M_CSV", "top-1m.csv")
        if os.path.exists(top_1m_file):
            self.top_1m = set(line[1] for line in csv.reader(open(top_1m_file), delimiter=","))

    def import_update(self, files_sha256, _, source_name, __):
        for file, _ in files_sha256:
            # Parse file containing URIs, extract domains and IPs
            iocs = dict()

            # Collect any previous collected IOCs so we don't lose any between updates
            for ioc in ["ip", "domain", "uri"]:
                if os.path.exists(os.path.join(self.latest_updates_dir, source_name, ioc)):
                    iocs[ioc] = set(open(os.path.join(self.latest_updates_dir, source_name, ioc), "r").readlines())

            for line in open(file, "r"):
                if line.startswith("#"):
                    # Presumably some commenting from source (ie. urlhaus)
                    continue
                line = line.strip()
                try:
                    host = urlparse(line).hostname
                    if re.match(IP_ONLY_REGEX, host):
                        # Bad IP
                        iocs.setdefault("ip", set()).add(host)
                    else:
                        # Bad Domain? Consult top 1M
                        if host not in self.top_1m:
                            iocs.setdefault("domain", set()).add(host)

                    iocs.setdefault("uri", set()).add(line)
                except Exception as e:
                    self.log.error(f'Problem parsing "{line}" in file from {source_name}: {e}')

            for ioc_type, ioc_values in iocs.items():
                # Store the IOCs in their respective source to make it easier to track
                if ioc_values:
                    if not os.path.exists(os.path.join(self.latest_updates_dir, source_name)):
                        os.makedirs(os.path.join(self.latest_updates_dir, source_name))

                    with open(os.path.join(self.latest_updates_dir, source_name, ioc_type), "w") as bl_writer:
                        bl_writer.write("\n".join(ioc_values))


if __name__ == "__main__":
    with NetRepUpdateServer() as server:
        server.serve_forever()

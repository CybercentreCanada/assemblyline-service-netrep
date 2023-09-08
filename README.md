# Network Reputation (NetRep) Service

Assemblyline service that flags network IOCs for belonging to known bad lists or believed to be phishing related

## Typosquatting Checks

This service employs the use of:

- [ail-typo-squatting](https://github.com/typosquatter/ail-typo-squatting) - Licensed under [BSD 2-Clause License](https://raw.githubusercontent.com/typosquatter/ail-typo-squatting/main/LICENSE)

Performing this check requires the `enable_typosquatting_check` parameter to be `True` in your submission.

**Note**: Depending how much traffic your Assemblyline instance receives and how many IOCs are extracted from services
like Frankenstrings, it might be better suited to disable typosquatting checks.

## Sources

When adding sources to the service, there are two types of expected data formats

- csv
- json

There are also two types of sources for this service:

- blocklist
- malware_family_list

### Blocklist Data Formats

In order for the service to pull the right IOCs and categorize them per source, you'll have to instruct it on how to using the `config.updater.<source>` key.

Within each `source` map, you'll specify the type of source this is (`blocklist`) as well as set the format (`json` | `csv`).

You'll also have to specify the different IOC types (`domain`, `ip`, `uri`) you expect to find in the data and where.

For example if dealing with a CSV file and you expect to find `uri`s in the 3rd column per row:

ie. "`<date>,<name>,https://google.com,...`"

Then your source configuration will look like:

```yaml
config:
  updater:
    my_source:
      type: blocklist
      format: csv
      uri: 2
```

Similarly, if you're dealing with a JSON list (`[{}, {}, ...]`) and you know to find `uri`s under the key `bad_uri` in each record:

ie. `{"bad_uri": "https://google.com", "family": "bad_stuff", ...}`

```yaml
config:
  updater:
    my_source:
      type: blocklist
      format: json
      uri: "bad_uri"
```

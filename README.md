# Network Reputation (NetRep) Service

Assemblyline service that flags network IOCs for belonging to known bad lists or believed to be phishing related

## Typosquatting Checks

This service employs the use of:

- [ail-typo-squatting](https://github.com/typosquatter/ail-typo-squatting) - Licensed under [BSD 2-Clause License](https://raw.githubusercontent.com/typosquatter/ail-typo-squatting/main/LICENSE)

## Sources

When adding sources to the service, the expectation is that the response if a file containing a list of URIs separated by newlines.

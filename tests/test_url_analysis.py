from netrep.utils.network import url_analysis


def test_unicode_characters():
    # Shouldn't crash due to non-ASCII characters being in the URL
    url = "https://hello:world@écoute.com/"
    res_section, network_iocs = url_analysis(url)
    assert network_iocs == {"uri": ["https://écoute.com/"], "domain": ["écoute.com"], "ip": []}
    assert '"OBFUSCATION": "Embedded credentials"' in res_section.body


def test_embedded_base64():
    url = "https://somedomain.com/some/path?u=a1aHR0cHM6Ly9iYWQuY29t#dGVzdEBleGFtcGxlLmNvbQ=="
    res_section, network_iocs = url_analysis(url)
    assert network_iocs == {"uri": ["https://bad.com"], "domain": ["bad.com"], "ip": []}
    assert res_section.tags == {
        # Encoded URL in query
        "network.static.uri": ["https://bad.com"],
        # Domain from encoded URL
        "network.static.domain": ["bad.com"],
        # Encoded email in fragment
        "network.email.address": ["test@example.com"],
    }

    # Handle garbage base64 strings, this shouldn't generate any results
    url = "https://somedomain.com/some/path?u=2F4wOWl6vSIfij9tBVr7MyOThiV1"
    res_section, network_iocs = url_analysis(url)
    assert network_iocs == {"uri": [], "domain": [], "ip": []}
    assert not res_section.body


def test_safelinks():
    # Ref: https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about?view=o365-worldwide
    url = "https://safelinks.com/?url=https%3A%2F%2Fhelloworld%2Ecom%2Fbad%7C01%7Ctest%40example%2Ecom"
    res_section, network_iocs = url_analysis(url)
    assert network_iocs == {
        # URL to be redirected to
        "uri": ["https://helloworld.com/bad"],
        "domain": ["helloworld.com"],
        "ip": [],
    }
    assert res_section.tags == {
        # URL to be redirected to
        "network.static.uri": ["https://helloworld.com/bad"],
        "network.static.domain": ["helloworld.com"],
        # Recipient email address
        "network.email.address": ["test@example.com"],
    }


def test_hexed_ip():
    # Ref: https://www.darkreading.com/cloud/shellbot-cracks-linux-ssh-servers-debuts-new-evasion-tactic
    url = "http://0x7f000001"
    res_section, network_iocs = url_analysis(url)
    assert network_iocs["ip"] == ["127.0.0.1"]
    assert res_section.tags == {"network.static.ip": ["127.0.0.1"]}


def test_phishing():
    # Ref: https://www.vmray.com/cyber-security-blog/detection-signature-updates-2/#elementor-toc__heading-anchor-9
    url = "https://google.com@wellsfargo.com@micrsoft.com@adobe.com@bad.com/malicious.zip?evil=true"
    res_section, network_iocs = url_analysis(url)
    # Should reveal the true target URL for reputation checking
    assert network_iocs["uri"] == ["https://bad.com/malicious.zip?evil=true"]
    assert network_iocs["domain"] == ["bad.com"]
    assert '"OBFUSCATION": "URL masquerade"' in res_section.body

    url = "https://username@bad.com/"
    res_section, network_iocs = url_analysis(url)
    assert network_iocs["uri"] == ["https://bad.com/"]
    assert network_iocs["domain"] == ["bad.com"]
    assert '"OBFUSCATION": "Embedded credentials"' in res_section.body

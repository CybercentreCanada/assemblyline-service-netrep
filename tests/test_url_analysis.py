from netrep.netrep import url_analysis


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

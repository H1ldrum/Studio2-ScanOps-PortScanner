from operator import contains

import pytest

from reporters.banner import extract_banner


@pytest.mark.unit
@pytest.mark.banner
async def test_nping_echo_banner():
    results = extract_banner(
        "scanme.nmap.org", 9929, "h5RrJuID_;w,jbɡ[V#NS؄/KZ5\\-nW͟a!:S"
    )
    print("results", results)
    assert results is not None
    assert "nping echo" in results


@pytest.mark.unit
@pytest.mark.external
@pytest.mark.banner
async def test_nping_echo_banner_integration():
    results = extract_banner("scanme.nmap.org", 9929, "")
    print("results", results)
    assert results is not None
    assert "nping echo" in results

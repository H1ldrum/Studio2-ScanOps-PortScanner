import pytest

from app_args import to_ip
from reporters.banner import extract_banner


@pytest.mark.unit
@pytest.mark.banner
async def test_nping_echo_banner():
    results = extract_banner(
        "scanme.nmap.org", 9929, "h5RrJuID_;w,jbɡ[V#NS؄/KZ5\\-nW͟a!:S", timeout=500
    )
    assert results is not None
    assert "nping echo" in results


@pytest.mark.external
@pytest.mark.banner
async def test_nping_echo_banner_integration():
    results = extract_banner(to_ip("scanme.nmap.org"), 9929, "", timeout=1)
    assert results is not None
    assert "nping echo" in results


@pytest.mark.external
@pytest.mark.banner
async def test_nrk_https_follow_redirect():
    results = extract_banner(to_ip("nrk.no"), 443, "", timeout=0.3)
    assert results is not None
    assert results == "AkamaiGHost"

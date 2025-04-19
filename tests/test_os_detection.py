import pytest

from osdetection.osdetect import OSDetector


@pytest.mark.unit
@pytest.mark.osdetect
@pytest.mark.parametrize(
    "ttl, expected_os",
    [
        (128, "Windows"),
        (64, "Linux"),
        (255, "Cisco"),
        (32, "Windows"),
        (254, "Solaris"),
        # Add more test cases as needed
    ],
)
def test_os_detection_from_ttl(ttl, expected_os):
    results = OSDetector.lookup_os_from_ttl("example.com", ttl)
    assert results is not None
    assert (
        expected_os in results.possible_oses
    ), f"Expected os '{expected_os}' for ttl {ttl}, but got {results.possible_oses}"


@pytest.mark.unit
@pytest.mark.osdetect
@pytest.mark.parametrize(
    "ports, expected_os",
    [
        ({22: "ssh"}, []),
        ({135: "", 139: "", 445: ""}, ["Windows"]),
        ({135: "", 139: ""}, []),
    ],
)
def test_os_detection_from_ports(ports, expected_os):
    results = OSDetector.lookup_os_from_port_list("example.com", ports)
    all_oses = set([os for r in results for os in r.possible_oses])
    assert results is not None
    assert all_oses == set(expected_os)

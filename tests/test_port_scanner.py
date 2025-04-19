import os
import re
import sys
from dataclasses import dataclass
from re import Pattern
from typing import Dict, Optional

import pytest

from app_args import parse_int_list, parse_target_list
from main import createScanner
from network_mapping.ping import CmdPinger
from reporters import cli_reporter
from reporters.reporter import Ports

# Add project root to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app_args import Args
from port_scanner import PortScanner

default_concurrent=7000



@dataclass
class PortScannerTestCase:
    args: Args
    expected_open: Optional[Dict[str, list[int]]] = None
    expected_banners: Optional[Dict[str, Dict[int, str | Pattern]]] = None
    expected_filtered: Optional[Dict[str, list[int]]] = None
    expected_closed: Optional[Dict[str, list[int]]] = None
    expected_oses: Optional[Dict[str, list[str]]] = None
    expoected_ports_scanned: Optional[int] = None


@pytest.mark.external
@pytest.mark.privileged
@pytest.mark.banner
async def test_scanme_syn():
    """Syn-scan should detect all port-statuses on scanme.nmap.org, as well as return correct banners"""
    target = "scanme.nmap.org"
    x = PortScannerTestCase(
        args=Args(
            command="syn_scan",
            concurrent=default_concurrent,
            target=[target],
            ports=[22, 25, 80, 9929, 31337, 6000, 6080],
        ),
        expected_banners={
            target: {
                22: "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
                80: "Apache/2.4.7 (Ubuntu)",
                # nping echo has garbled output. We have not implemented the specific handling of this.
                # I do not htink any other service uses this protocol
                9929: re.compile("nping echo"),
            }
        },
        expoected_ports_scanned=7,
        expected_open={target: [22, 80, 9929, 31337]},
        expected_filtered={target: [25]},
        expected_closed={target: [6000, 6080]},
    )
    await run_port_scanner_basic(x)

@pytest.mark.home
@pytest.mark.privileged
@pytest.mark.mapper
async def test_home_network_mapper():
    """Should find all hosts on network"""
    x = PortScannerTestCase(
        args=Args(
            command="syn_scan",
            concurrent=default_concurrent,
            target=parse_target_list("192.168.38.0/24"),
            ports=[],
        ),
        expoected_ports_scanned=0,
    )
    reporter = await run_port_scanner_basic(x)
    # Ignoring some hosts on the network that seems to be very flaky, same with nmap
    missing = set([
        "192.168.38.1",
        "192.168.38.120",
        "192.168.38.122",
        "192.168.38.145",
        "192.168.38.148",
        "192.168.38.157",
        "192.168.38.163",
        "192.168.38.178",
            ]) -set(reporter.up_targets)  
    assert not missing, f"Missing expected hosts: {missing}"

@pytest.mark.external
@pytest.mark.banner
async def test_scanme_connect():
    """Connect-scan should detect all port-statuses on scanme.nmap.org, as well as return correct banners"""
    target = "scanme.nmap.org"
    x = PortScannerTestCase(
        args=Args(
            command="connect_scan",
            concurrent=default_concurrent,
            target=[target],
            ports=[22, 25, 80, 9929, 31337, 6000, 6080],
        ),
        expected_banners={
            target: {
                22: "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
                80: "Apache/2.4.7 (Ubuntu)",
                # nping echo has garbled output. We have not implemented the specific handling of this.
                # I do not htink any other service uses this protocol
                9929: re.compile("nping echo"),
            }
        },
        expoected_ports_scanned=7,
        expected_open={target: [22, 80, 9929, 31337]},
        expected_filtered={target: [25]},
        expected_closed={target: [6000, 6080]},
    )
    await run_port_scanner_basic(x)


@pytest.mark.osdetect
@pytest.mark.privileged
async def test_osdetect_windows():
    """Detect a windows-machine as windows"""
    target = "192.168.38.122"
    x = PortScannerTestCase(
        args=Args(
            command="syn_scan",
            concurrent=default_concurrent,
            target=[target],
            ports=[22, 80, 443, 8080, 135, 139, 445, 7680, 49668],
            timeout_ms=200
        ),
        # Not implemented for these ports
        # expected_banners={ },
        expected_oses={target:["Windows"]},
        expoected_ports_scanned=9,
        expected_open={target: [135, 139, 445, 7680, 49668]},
        expected_filtered={target: [22, 80, 443, 8080]},
        expected_closed={target: []},
    )
    await run_port_scanner_basic(x)
@pytest.mark.osdetect
@pytest.mark.privileged
async def test_osdetect_linux():
    """Detect a linux-machine as linux"""
    target = "127.0.0.1"
    x = PortScannerTestCase(
        args=Args(
            command="syn_scan",
            concurrent=default_concurrent,
            target=[target],
            ports=[22],
            timeout_ms=200
        ),
        expected_banners={target: {22: "SSH-2.0-OpenSSH_9.9"} },
        expected_oses={target:["Linux", "Unix", "FreeBSD", "macOS"]},
        expected_open={target: [22]},
    )
    await run_port_scanner_basic(x)


@pytest.mark.home
@pytest.mark.privileged
@pytest.mark.slow
async def test_home_media_syn():
    """Syn-scan should detect all port-statuses on a known host"""
    ports_to_scan = parse_int_list("1-10000,32400,51413")
    target = "192.168.38.163"
    expoected_open = [
        22,
        80,
        443,
        1115,
        1617,
        7878,
        8040,
        8080,
        8686,
        8989,
        9091,
        9696,
        32400,
        51413,
    ]
    x = PortScannerTestCase(
        args=Args(
            command="syn_scan",
            concurrent=default_concurrent,
            target=[target],
            timeout_ms=200,
            ports=ports_to_scan,
        ),
        # expoected_ports_scanned=65535,
        expoected_ports_scanned=10002,
        expected_open={target: expoected_open},
        expected_filtered={target: []},
        expected_closed={target: list(set(ports_to_scan) - set(expoected_open))},
    )
    await run_port_scanner_basic(x)


@pytest.mark.home
@pytest.mark.fast
async def test_home_media_connect_fast():
    """Connect-scan should detect all port-statuses on a known host"""
    ports_to_scan = parse_int_list("1-10000,32400,51413")
    expoected_open = [
        22,
        80,
        443,
        1115,
        1617,
        7878,
        8040,
        8080,
        8686,
        8989,
        9091,
        9696,
        32400,
        51413,
    ]
    target = "192.168.38.163"
    x = PortScannerTestCase(
        args=Args(
            command="connect_scan",
            concurrent=default_concurrent,
            target=[target],
            timeout_ms=200,
            ports=ports_to_scan,
        ),
        # expoected_ports_scanned=65535,
        expoected_ports_scanned=len(ports_to_scan),
        expected_open={target: expoected_open},
        expected_filtered={target: []},
        expected_closed={target: list(set(ports_to_scan) - set(expoected_open))},
    )
    await run_port_scanner_basic(x)

async def run_port_scanner_basic(test_case: PortScannerTestCase):
    # Arrange
    reporter = cli_reporter.ConsoleReporter(
        with_progress=False, with_closed_ports=False, with_debug=True
    )
    pinger = CmdPinger()

    def scanner_factory(target: str):
        return createScanner(test_case.args, target)

    # Act
    await PortScanner(test_case.args, reporter, pinger, scanner_factory)

    # Assert
    if test_case.expected_filtered is not None:
        assert reporter.scanned_ports == test_case.expoected_ports_scanned
    if test_case.expected_open is not None:
        assert len(reporter.open_ports.keys()) == len(test_case.args.target)
    if test_case.expected_oses:
        for target, expected in test_case.expected_oses.items():
            results = reporter.osdetect(target)
            all_oses = set([os for r in results for os in r.possible_oses])
            assert set(expected) == all_oses
    if test_case.expected_banners:
        for target, d in test_case.expected_banners.items():
            assert target in reporter.open_ports
            for port, banner in d.items():
                assert port in reporter.open_ports[target]
                if isinstance(banner, str):
                    assert banner == reporter.open_ports[target][port], (
                        f"expected {banner} on port {port} in reporter.open_ports[{target}], but got {reporter.open_ports[target][port]}. All port-banners for this target: {reporter.open_ports[target]}"
                    )
                else:
                    assert (
                        banner.match(reporter.open_ports[target][port]) is not None
                    ), (
                        f"expected regex-match for {banner} on port {port} in reporter.open_ports[{target}], but got {reporter.open_ports[target][port]}. All port-banners for this target: {reporter.open_ports[target]}"
                    )

    if test_case.expected_open:
        for target, d in test_case.expected_open.items():
            assert target in reporter.open_ports
            if d is None:
                continue
            assert_port_list(list(reporter.open_ports[target].keys()), d, "Open")

    if test_case.expected_closed:
        for target, d in test_case.expected_closed.items():
            assert target in reporter.closed_ports
            if d is None:
                continue
            assert_port_list(reporter.closed_ports[target], d, "Closed")

    if test_case.expected_filtered:
        for target, d in test_case.expected_filtered.items():
            assert target in reporter.filtered_ports
            if d is None:
                continue
            assert_port_list(reporter.filtered_ports[target], d, "Filtered")

    return reporter


def flatten_ports(dict: Dict[str, Ports]):
    return [port for sublist in dict.values() for port in sublist]


def assert_port_list(got: list[int] | Dict[str, Ports], want: list[int] | None, kind):
    if want is None:
        return
    if isinstance(got, dict):
        got = flatten_ports(got)

    if set(got) == set(want):
        return
    missing = cli_reporter.stringify_compact_list_of_ints(list(set(want) - set(got)))
    extra = cli_reporter.stringify_compact_list_of_ints(list(set(got) - set(want)))
    assert False, (
        f"{kind} Port lists don't match: Missing: {missing}, Extra: {extra}. Got {cli_reporter.stringify_compact_list_of_ints(got)}, wanted {cli_reporter.stringify_compact_list_of_ints(want)}"
    )

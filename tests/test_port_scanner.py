import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Optional

import pytest

from app_args import parse_int_list
from main import createScanner
from network_mapping.ping import CmdPinger
from reporters import cli_reporter
from reporters.reporter import Ports

# Add project root to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app_args import Args
from port_scanner import PortScanner

# from tests.mocks import MockPinger, MockScanner, MockReporter


@dataclass
class PortScannerTestCase:
    args: Args
    expected_open: Dict[str, list[int]]
    expected_filtered: Dict[str, list[int]]
    expected_closed: Dict[str, list[int]]
    expoected_ports_scanned: Optional[int]
    test_id: str
    markers: list[str] = field(default_factory=list)


@pytest.mark.external
@pytest.mark.privileged
async def test_scanme_syn():
    x = PortScannerTestCase(
        args=Args(
            command="syn_scan",
            target=["scanme.nmap.org"],
            ports=[22, 25, 80, 9929, 31337, 6000, 6080],
        ),
        expoected_ports_scanned=7,
        expected_open={"scanme.nmap.org": [22, 80, 9929, 31337]},
        expected_filtered={"scanme.nmap.org": [25]},
        expected_closed={"scanme.nmap.org": [6000, 6080]},
        test_id="scanme.nmap.org reports correct ports as open/filtered/closed",
    )
    await run_port_scanner_basic(x)


@pytest.mark.home
@pytest.mark.privileged
@pytest.mark.slow
async def test_home_media_syn():
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
            target=[target],
            timeout_ms=200,
            ports=ports_to_scan,
        ),
        # expoected_ports_scanned=65535,
        expoected_ports_scanned=10002,
        expected_open={target: expoected_open},
        expected_filtered={target: []},
        expected_closed={target: list(set(ports_to_scan) - set(expoected_open))},
        test_id="home media server reports correct ports as open/filtered/closed",
    )
    await run_port_scanner_basic(x)


async def run_port_scanner_basic(test_case: PortScannerTestCase):
    # Arrange
    reporter = cli_reporter.ConsoleReporter()
    pinger = CmdPinger()

    def scanner_factory(target: str):
        return createScanner(test_case.args, target)

    # Act
    await PortScanner(test_case.args, reporter, pinger, scanner_factory)

    # Assert
    if test_case.expected_filtered is not None:
        assert reporter.scanned_ports == test_case.expoected_ports_scanned
    assert len(reporter.open_ports.keys()) == len(test_case.args.target)
    for target, d in test_case.expected_open.items():
        assert target in reporter.open_ports
        if d is None:
            continue
        assert_port_list(reporter.open_ports[target], d, "Open")

    for target, d in test_case.expected_closed.items():
        assert target in reporter.closed_ports
        if d is None:
            continue
        assert_port_list(reporter.closed_ports[target], d, "Closed")

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

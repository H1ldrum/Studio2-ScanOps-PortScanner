import json
import sys

from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import JsonLexer

from osdetection.osdetect import OSDetector
from reporters.reporter import Ports, ScanReporter


class JsonReporter(ScanReporter):
    def _update_progress_abstract(
        self, target: str, current_port: int, is_open: bool | Exception
    ) -> None:
        pass

    def _report_start_abstract(
        self, target: str, ports: Ports, prefix="", suffix: str = ""
    ) -> None:
        pass

    def _report_final_abstract(self, time_taken_ms) -> None:
        result = {
            "total_ports": self.total_ports,
            "scanned_ports_count": self.scanned_ports,
            "open_ports": self.open_ports,
            "filtered_ports": self.filtered_ports,
            "closed_ports": self.closed_ports,
            "errors": self.errors,
            "last_error": self.last_error,
            "time_ms": time_taken_ms,
            "os_detection": {
                target: (
                    f"{OSDetector.lookup_os_from_ttl(ttl_list[0])} ({ttl_list[0]})"
                    if ttl_list
                    else "Unknown (No TTL)"
                )
                for target, ttl_list in self.ttls.items()
            },
        }
        json_str = json.dumps(result)
        if not sys.stdout.isatty():
            print(json_str)
            return

        colored_json = highlight(json_str, JsonLexer(), TerminalFormatter())
        print(colored_json)

    def debug(self, string) -> None:
        print("DEBUG", string, file=sys.stderr)

    def info(self, string) -> None:
        print("info", string, file=sys.stderr)

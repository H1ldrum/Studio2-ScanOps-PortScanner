import json
import sys

from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import JsonLexer

from reporters.reporter import Ports, ScanReporter


class JsonReporter(ScanReporter):
    def update_progress(self, current_port: int, is_open: bool | Exception) -> None:
        super().update_progress(current_port, is_open)

    def report_start(
        self, target: str, ports: Ports, prefix="", suffix: str = ""
    ) -> None:
        super().report_start(target, ports, prefix, suffix)
        self.target = target

    def report_final(self, time_taken_ms) -> None:
        result = {
            "target": self.target,
            "total_ports": self.total_ports,
            "scanned_ports": self.scanned_ports,
            "open_ports": self.open_ports,
            "errors": self.errors,
            "last_error": self.last_error,
            "time_ms": time_taken_ms,
        }
        json_str = json.dumps(result, indent=2)
        if not sys.stdout.isatty():
            print(json_str)
            return

        colored_json = highlight(json_str, JsonLexer(), TerminalFormatter())
        print(colored_json)

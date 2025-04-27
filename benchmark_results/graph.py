#!/usr/bin/env python3
import argparse
import json
import re
import sys


def extract_concurrent(regex, cmd):
    if regex is None:
        return cmd
    match = re.search(regex, cmd)
    return match.group(1) if match else None


def main():
    parser = argparse.ArgumentParser(
        prog="graph-helper", description="plots latex graphs from hyperfine-results"
    )
    parser.add_argument(
        "--x-regex",  # Possible shortname if needed
        default=r"--concurrent=(\d+)",
        help="regex to use for x-axis (command)",
    )
    parser.add_argument(
        "--mode",  # Possible shortname if needed
        default="graph",
        help="graph or table",
    )
    args = parser.parse_args()
    mode = getattr(args, "mode", False)
    data = json.load(sys.stdin)
    points = []
    for entry in data["results"]:
        concurrent = extract_concurrent(getattr(args, "x_regex"), entry["command"])
        if concurrent is None:
            continue
        mean = entry["mean"]
        # if mean < 1:
        #     continue
        min_val = entry["min"]
        max_val = entry["max"]
        stddev = entry["stddev"]
        points.append(
            (
                int(concurrent) if concurrent.isdecimal() else concurrent,
                mean,
                min_val,
                max_val,
                stddev,
            )
        )
    points.sort(key=lambda x: x[0])
    if mode == "table":
        print(
            r"""
\begin{table}[h!]
  % \small
  \centering
\setlength{\tabcolsep}{6pt}
\sisetup{detect-weight=true, mode=text}
\begin{tabular}{l 
                S[table-format=2.2] 
                S[table-format=2.2] 
                S[table-format=2.2] 
                S[table-format=1.3]}
  \textbf{Shortcommand} & \textbf{Mean} & \textbf{Min} & \textbf{Max} & \textbf{Std. Dev.} \\ 
  \toprule
"""
        )
        for x, mean, min_val, max_val, stddev in points:
            lower = mean - min_val
            upper = max_val - mean
            print(
                f"{str(x).replace('_', '\\_')} & {mean:.2f} & {min_val:.2f} & {max_val:.2f} & {stddev:.2f} \\\\"
            )
            # print(
            #     remove_non_ascii_and_newlines(x),
            #     end="banan",
            # )
            # print(mean, end="&")
            # print(min_val, end="&")
            # print(max_val, end=" \\\\\n")

        print(
            r"""
\end{tabular}
\caption{Listing of the versions of this document}
\label{tab:versioncontrol}
%
\end{table}
        """
        )

        return
    # print(points[0])
    # print(points[1])
    assert len(points) > 0
    standalone = False
    standalone_header = r"""
\documentclass{standalone}
\usepackage{pgfplots}
\begin{document}
"""
    standalone_footer = r"""
\end{document}
"""
    if standalone:
        print(standalone_header)

    print(
        r"""
\begin{tikzpicture}
\begin{axis}[
    title={Execution Time vs Concurrent Requests},
    xlabel={Concurrent Requests},
    ylabel={Mean Execution Time (seconds)},
    grid=minor,
    scaled ticks=false,
    % xmode=log,
    % ymode=log,
    width=14cm,
    height=9cm,
    % xmin=1,
    % ymin=0,
    enlarge x limits=0.1,
    yticklabel style={/pgf/number format/fixed},
]
\addplot[
    only marks,
    mark=*,
    color=blue,
    % error bars/y dir=both,
    % error bars/y explicit,
    % error bars/error bar style={thick},
    error bars/.cd,  
    y dir=both, y explicit,  
    error bar style={blue!50},
] coordinates {
    % Data points:
    """
    )

    for x, mean, min_val, max_val, stddev in points:
        lower = mean - min_val
        upper = max_val - mean
        # print(f"({x}, {mean}) +- ({lower}, {upper})")
        print(f"({x}, {mean}) +- (0, {stddev or 0})")

    print(
        r"""
};
\end{axis}
\end{tikzpicture}
"""
    )
    if standalone:
        print(standalone_footer)


def remove_non_ascii(s: str) -> str:
    return "".join(c for c in s if ord(c) < 128)


def remove_non_ascii_and_newlines(s: str) -> str:
    return "".join(c for c in s if ord(c) < 128 and c not in {"\n", "\r"})


if __name__ == "__main__":
    main()

# Studio2-ScanOps-PortScanner
Artifact for our project in Studio 2

![Example of cli running http_scan](./docs/samplescan.gif)

## Getting started.

You probably want to create a virtual environment first, and source it, for instance like:

```shell
virtualenv -p /usr/bin/python3 .venv-python
source ./.venv-python/bin/activate
```

then install the dependencies with pip

```shell
pip install -r requirements.txt
```

You should now be ready to run the application:

## Usage

Run it with 

```
python main.py scan

```

```bash
usage: main.py scan [-h] -t TARGET [-p PORTS] [-c CONCURRENT] [-m METHOD]
                    [--proxy PROXY]

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target IP/hostname to scan
  -p, --ports PORTS     Ports to scan (e.g. "80,443,8080" or "20-1000")
  -c, --concurrent CONCURRENT
                        Number of concurrent scans
  -m, --method METHOD   HTTP-verb to use for scanning
  --proxy PROXY         Proxy URL (e.g. "http://proxy:8080")
  ```


### Project structure

The project is structured in a modular way. This keeps each module simple, but does require each module to adhere to fixed interfaces.

`main.py` is the entrypoint of the program. It handles parsing of input from the user, 
instantiates specific implementations of modules.

Scanners are implementation of a certain type of scanner. Currently, only the HTTP-scanner is implemented.
These are responsible for handling the specifics of performing an actual scan on a single port.

Reporters are responsible for reporting on the progress during a scan, when it starts, as well as when it is complete. 

# Studio2-ScanOps-PortScanner
Artifact for our project in Studio 2

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
python portscanner.py

```

```bash
usage: Portscanner by ScanOps [-h] [-t TARGET] [--concurrent CONCURRENT]
                              [--proxy PROXY]

Multipurpose portscanner to discover open ports and detect running services |
Arguments prepended with * is mandatory

options:
  -h, --help                show this help message and exit
  -t TARGET                 *Define ip to scan
  --concurrent CONCURRENT   Concurrent limit in the event loop, default = 4
  --proxy PROXY             Define proxy address/port url(http://xxx:xxx)
  ```



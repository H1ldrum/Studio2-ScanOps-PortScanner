scanme := "scanme.nmap.org"
local_ip := "192.168.38.163"
lan := "192.168.38.0/24"
portRange := "22,25,80,9929,31337"
allPorts := "1-65535"
thousandPorts := "1-1000"
resultsDir := benchmark_results
bin := ./.venv-python/bin
python := $(bin)/python
pytest := $(bin)/pytest
scanops_raw := $(python) main.py -Pn --no-extract-banner
scanops := $(python) main.py --concurrent=800 -Pn --no-extract-banner 
hyperfine := sudo hyperfine --warmup 1 --runs 10

# Create results directory
setup:
	mkdir -p $(resultsDir)
concurrent_localhost:
	sudo hyperfine --runs 10 \
	--show-output \
	--export-json $(resultsDir)/concurrent_localhost_syn.json \
	--export-csv $(resultsDir)/concurrent_localhost_syn.csv \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=50 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=100 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=200 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=300 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=400 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=500 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=600 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=700 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=800 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=900 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1000 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1100 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1200 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1300 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1300 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1400 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1500 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1600 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1700 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1800 syn_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=2400 syn_scan" \


concurrent_localhost_connect:
	sudo hyperfine --runs 10 \
	--show-output \
	--export-json $(resultsDir)/concurrent_localhost_connect.json \
	--export-csv $(resultsDir)/concurrent_localhost_connect.csv \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=50 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=100 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=200 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=300 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=400 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=500 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=600 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=700 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=800 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=900 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1000 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1100 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1200 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1300 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1300 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1400 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1500 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1600 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1700 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=1800 connect_scan" \
	"$(scanops_raw) -t 127.0.0.1 -p- --timeout_ms=50 --concurrent=2400 connect_scan" \

concurrent_media:
	sudo hyperfine --runs 10 \
	--show-output \
	--export-json $(resultsDir)/concurrent_mediaserver_syn.json \
	--export-csv $(resultsDir)/concurrent_mediaserver_syn.csv \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=50 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=100 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=200 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=300 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=400 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=500 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=600 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=700 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=800 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=900 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1000 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1100 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1200 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1300 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1300 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1400 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1500 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1600 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1700 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1800 syn_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=2400 syn_scan" \


concurrent_media_connect:
	sudo hyperfine --runs 10 \
	--show-output \
	--export-json $(resultsDir)/concurrent_mediaserver_connect.json \
	--export-csv $(resultsDir)/concurrent_mediaserver_connect.csv \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=50 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=100 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=200 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=300 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=400 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=500 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=600 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=700 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=800 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=900 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1000 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1100 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1200 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1300 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1300 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1400 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1500 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1600 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1700 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=1800 connect_scan" \
	"$(scanops_raw) -t 192.168.38.163 -p- --timeout_ms=50 --concurrent=2400 connect_scan" \

plot:
	 cat benchmark_results/concurrent_mediaserver_syn.json | python benchmark_results/graph.py > ../Group-report/Figures/concurrent_mediaserver_syn.tex
	 cat benchmark_results/concurrent_localhost_syn.json | python benchmark_results/graph.py > ../Group-report/Figures/concurrent_localhost_syn.tex
	 cat benchmark_results/concurrent_mediaserver_connect.json | python benchmark_results/graph.py > ../Group-report/Figures/concurrent_mediaserver_connect.tex
	 cat benchmark_results/concurrent_localhost_connect.json | python benchmark_results/graph.py > ../Group-report/Figures/concurrent_localhost_connect.tex
	 
	 cat ./benchmark_results/full_ports_connect.json | python benchmark_results/graph.py --x-regex='(.*)' | sed \
	 	 	-e 's/nmap [^)]* -sS[^)]*/nmap SYN/' \
	 	 	-e 's/nmap [^)]* -sT[^)]*/nmap CONNECT/' \
	 	 	-e 's/^\(.*tcp_scan[^)]*\)/(scanops tcp/' \
	 	 	-e 's/^\(.*syn_scan[^)]*\)/(scanops syn/' \
	 	 	-e 's/^\(.*connect_scan[^)]*\)/(scanops connect/' \
	 	 	-e 's/^\(.*http_scan[^)]*\)/(scanops http/' > ../Group-report/Figures/all-port-connect.tex

	 cat ./benchmark_results/full_ports_syn.json | python benchmark_results/graph.py --x-regex='(.*)' | sed \
	 	 	-e 's/nmap [^)]* -sS[^)]*/nmap SYN/' \
	 	 	-e 's/nmap [^)]* -sT[^)]*/nmap CONNECT/' \
	 	 	-e 's/^\(.*tcp_scan[^)]*\)/(scanops tcp/' \
	 	 	-e 's/^\(.*syn_scan[^)]*\)/(scanops syn/' \
	 	 	-e 's/^\(.*connect_scan[^)]*\)/(scanops connect/' \
	 	 	-e 's/^\(.*http_scan[^)]*\)/(scanops http/' > ../Group-report/Figures/all-port-syn.tex


	 cat ./benchmark_results/localhost.json | python benchmark_results/graph.py --x-regex='(.*)' | sed \
	 	 	-e 's/nmap [^)]* -sS[^)]*/nmap SYN/' \
	 	 	-e 's/nmap [^)]* -sT[^)]*/nmap CONNECT/' \
	 	 	-e 's/^\(.*tcp_scan[^)]*\)/(scanops tcp/' \
	 	 	-e 's/^\(.*syn_scan[^)]*\)/(scanops syn/' \
	 	 	-e 's/^\(.*connect_scan[^)]*\)/(scanops connect/' \
	 	 	-e 's/^\(.*http_scan[^)]*\)/(scanops http/' > ../Group-report/Figures/localhost.tex

test: unit_test
	sudo python -x -m pytest tests/ -m 'not unit'  --html=./tests/test_results.html --self-contained-html
unit_test:
	$(pytest) -x tests/ -m unit  -vv
# Test specific ports on scanme.nmap.org
benchmark-specific-ports: setup
	$(hyperfine) \
	--show-output \
	--export-json $(resultsDir)/specific_ports.json \
	--export-csv $(resultsDir)/specific_ports.csv \
	"$(scanops) -t $(scanme) -p $(portRange) syn_scan" \
	"$(scanops) -t $(scanme) -p $(portRange) connect_scan" \
	"$(scanops) -t $(scanme) -p $(portRange) tcp_scan" \
	"$(scanops) -t $(scanme) -p $(portRange) http_scan" \
	"nmap -p $(portRange) -sT $(scanme)" \
	"nmap -p $(portRange) -sS $(scanme)" 

# Full port scan test on local machine
benchmark-full-ports: setup
	$(hyperfine) \
	--show-output \
		--export-json $(resultsDir)/full_ports_syn.json \
		--export-csv $(resultsDir)/full_ports_syn.csv \
		"$(scanops) -t $(local_ip) -p $(thousandPorts) syn_scan" \
		"nmap -p $(thousandPorts) -T4 --max-retries 1 -sS $(local_ip)" 
benchmark-full-ports_connect: setup
	$(hyperfine) \
	--show-output \
		--export-json $(resultsDir)/full_ports_connect.json \
		--export-csv $(resultsDir)/full_ports_connect.csv \
		"$(scanops) -t $(local_ip) -p $(thousandPorts) connect_scan" \
		"nmap -p $(thousandPorts) -T4 --max-retries 1 -sT $(local_ip)" 

# Full port scan on localhost
benchmark-localhost: setup
	$(hyperfine) \
	--show-output \
		--export-json $(resultsDir)/localhost.json \
		--export-csv $(resultsDir)/localhost.csv \
		"$(scanops) -t 127.0.0.1 -p $(thousandPorts) syn_scan" \
		"$(scanops) -t 127.0.0.1 -p $(thousandPorts) connect_scan" \
		"$(scanops) -t 127.0.0.1 -p $(thousandPorts) tcp_scan" \
		"nmap -p $(thousandPorts) -T4 --max-retries 1 -sS 127.0.0.1" 

# OS detection test on all LAN devices
benchmark-os-detection: setup
	$(hyperfine) \
	--show-output \
		--export-json $(resultsDir)/os_detection.json \
		--export-csv $(resultsDir)/os_detection.csv \
		"$(python) main.py --concurrent=800 --no-extract-banner -t $(lan) os_detection" \
		"nmap -O $(lan)" 

# Full port scan on LAN
benchmark-lan: setup
	$(hyperfine) \
	--show-output \
		--export-json $(resultsDir)/lan_scan.json \
		--export-csv $(resultsDir)/lan_scan.csv \
		"$(python) main.py --concurrent=800 --no-extract-banner -t $(lan) -p $(thousandPorts) syn_scan" \
		"nmap -p $(thousandPorts) -sS $(lan) --min-rate=1000 -T4" 

# Run all benchmarks
benchmark-all: concurrent_localhost concurrent_media concurrent_localhost_connect concurrent_media_connect benchmark-specific-ports benchmark-lan benchmark-full-ports benchmark-localhost 
benchmark-resr: benchmark-full-ports benchmark-full-ports_connect benchmark-localhost 

.PHONY: setup benchmark-specific-ports benchmark-full-ports_connect benchmark-full-ports benchmark-localhost benchmark-os-detection benchmark-lan benchmark-all test unit_test

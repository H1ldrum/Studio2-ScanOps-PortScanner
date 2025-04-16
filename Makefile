ip := "scanme.nmap.org"
local_ip := "192.168.38.125"
lan := "192.168.38.0/24"
portRange := "22,25,80,9929,31337"
allPorts := "1-65535"
resultsDir := "benchmark_results"

# Create results directory
setup:
	mkdir -p $(resultsDir)

# Test specific ports on scanme.nmap.org
benchmark-specific-ports: setup
	sudo hyperfine --warmup 1 \
	--export-json $(resultsDir)/specific_ports.json \
	--export-csv $(resultsDir)/specific_ports.csv \
	"nmap -p $(portRange) -sT $(ip)" \
	"nmap -p $(portRange) -sS $(ip)" \
	"python main.py -t $(ip) --reporter None -p $(portRange) syn_scan" \
	"python main.py -t $(ip) --reporter None -p $(portRange) connect_scan" \
	"python main.py -t $(ip) --reporter None -p $(portRange) tcp_scan" \
	"python main.py -t $(ip) --reporter None -p $(portRange) http_scan"

# Full port scan test on local machine
benchmark-full-ports: setup
	sudo hyperfine --warmup 1 --runs 3 \
		--export-json $(resultsDir)/full_ports.json \
		--export-csv $(resultsDir)/full_ports.csv \
		"nmap -p $(allPorts) -T4 --max-retries 1 -sS $(local_ip)" \
		"python main.py -t $(local_ip) --reporter None -p $(allPorts) syn_scan"

# Full port scan on localhost
benchmark-localhost: setup
	sudo hyperfine --warmup 1 --runs 3 \
		--export-json $(resultsDir)/localhost.json \
		--export-csv $(resultsDir)/localhost.csv \
		"nmap -p $(allPorts) -T4 --max-retries 1 -sS 127.0.0.1" \
		"python main.py -t 127.0.0.1 --reporter None -p $(allPorts) syn_scan" \
		"python main.py -t 127.0.0.1 --reporter None -p $(allPorts) connect_scan" \
		"python main.py -t 127.0.0.1 --reporter None -p $(allPorts) tcp_scan"

# OS detection test on all LAN devices
benchmark-os-detection: setup
	sudo hyperfine --warmup 1 \
		--export-json $(resultsDir)/os_detection.json \
		--export-csv $(resultsDir)/os_detection.csv \
		"nmap -O $(lan)" \
		"python main.py -t $(lan) --reporter None os_detection"

# Full port scan on LAN
benchmark-lan: setup
	sudo hyperfine --warmup 1 \
		--export-json $(resultsDir)/lan_scan.json \
		--export-csv $(resultsDir)/lan_scan.csv \
		"nmap -p $(allPorts) -sS $(lan) --min-rate=1000 -T4" \
		"python main.py -t $(lan) --reporter None -p $(allPorts) syn_scan"

# Run all benchmarks
benchmark-all: benchmark-specific-ports benchmark-os-detection benchmark-lan benchmark-full-ports benchmark-localhost

.PHONY: setup benchmark-specific-ports benchmark-full-ports benchmark-localhost benchmark-os-detection benchmark-lan benchmark-all

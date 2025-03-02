ip := "192.168.38.163"
portRange := "8000-9000"
openPort := "8080"
closedPort := "30238"


benchmark:
	hyperfine \
		"python main.py -t $(ip) --reporter None -p $(portRange) socket_scan" \
		"python main.py -t $(ip) --reporter None -p $(portRange) tcp_scan" \
		"python main.py -t $(ip) --reporter None -p $(portRange) http_scan" 


.PHONY: benchmark

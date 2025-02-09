benchmark:
	hyperfine \
		'python main.py -t 127.1 --reporter None -p "1-10000" tcp_scan' \
		'python main.py -t 127.1 --reporter None -p "1-10000" socket_scan' \
		'python main.py -t 127.1 --reporter None -p "1-10000" http_scan'


.PHONY: benchmark

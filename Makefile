SERVER_IP ?=
SERVER_PORT ?= 1080
BPF_TARGET ?= bpfeb
OUT ?= build/s0cks5.o

.PHONY: all bpf check clean

all: bpf

bpf:
	@test -n "$(SERVER_IP)" || (echo "SERVER_IP is required (make SERVER_IP=203.0.113.10)" >&2; exit 1)
	SERVER_IP=$(SERVER_IP) SERVER_PORT=$(SERVER_PORT) \
		BPF_TARGET=$(BPF_TARGET) OUT=$(OUT) ./scripts/build.sh

check:
	python3 -m py_compile server/mutated_socks5.py tests/mutated_client.py

clean:
	rm -rf build server/__pycache__ tests/__pycache__

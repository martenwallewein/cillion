.PHONY: install bpf bpf/tc_egress.o bpf/xdp_ingress.o generate

BPF_CFLAGS := -O2 -target bpf -Wall -I bpf -I pkg/bpf/headers

bpf/tc_egress.o: bpf/tc_egress.c
	clang $(BPF_CFLAGS) -c $< -o $@

bpf/xdp_ingress.o: bpf/xdp_ingress.c
	clang $(BPF_CFLAGS) -c $< -o $@

generate:
	go generate ./pkg/bpf/

bpf: generate bpf/tc_egress.o bpf/xdp_ingress.o

install:

	apt-get install -y clang llvm libbpf-dev linux-tools-$(shell uname -r)
	# Docker
	if ! command -v docker >/dev/null 2>&1; then \
		curl -fsSL https://get.docker.com | sh; \
	else \
		echo "Docker already installed."; \
	fi
	# kind
	curl -Lo /usr/local/bin/kind \
		"https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64"
	chmod +x /usr/local/bin/kind
	# kubectl
	curl -Lo /usr/local/bin/kubectl \
		"https://dl.k8s.io/release/$$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
	chmod +x /usr/local/bin/kubectl
	bash install-cilium.sh
	


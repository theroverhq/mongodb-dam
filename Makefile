.PHONY: check test test-container test-http-push test-ebpf test-demo-api build-images lint-chart render-chart

check:
	cargo check --workspace --locked

test:
	cargo test --workspace --locked

test-container:
	docker build --file Dockerfile.observer --target test .

test-http-push:
	./scripts/test-http-push.sh

test-ebpf:
	./scripts/test-ebpf-mongodb.sh

test-demo-api:
	./scripts/test-demo-api.sh

build-images:
	./scripts/build-images.sh

lint-chart:
	helm lint deploy/helm/mongodb-dam

render-chart:
	helm template mongodb-dam deploy/helm/mongodb-dam --namespace mongodb-dam

.PHONY: test-native test-integration test-integration-up test-integration-run \
        test-integration-down test-integration-quick flash-test

PIO ?= pio
DOCKER_COMPOSE = docker compose -f test/integration/docker/docker-compose.yml

test-native:
	$(PIO) test -e native -v

test-integration: test-integration-up test-integration-run test-integration-down

test-integration-up:
	$(DOCKER_COMPOSE) up -d --build
	@sleep 3

test-integration-run:
	cd test/integration/harness && pytest -v --tb=short

test-integration-down:
	$(DOCKER_COMPOSE) down

test-integration-quick:
	cd test/integration/harness && pytest -v --tb=short

flash-test:
	$(PIO) run -e test_integration -t upload

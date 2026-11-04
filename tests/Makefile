TEST_SERVICE = test_seabee.service
TEST_SERVICE_SRC = $(TEST_SERVICE)
TEST_SERVICE_PATH = /etc/systemd/system/$(TEST_SERVICE)

.PHONY: all test test-release test-policy test-policy-release example-kmod test-kmod

# if missing or outdated, install a new daemon test service into systemd
$(TEST_SERVICE_PATH): $(TEST_SERVICE_SRC)
	sudo cp $(TEST_SERVICE_SRC) $(TEST_SERVICE_PATH)
	sudo systemctl daemon-reload

generate-test-sigs:
	@./crypto/gen_sigs.sh

# run tests with debug binaries
test: integration-test policy-test

# run tests with release binaries
test-release: integration-test-release policy-test-release

# set SKIP_KMOD=1 to run without building or inserting the test kernel modules
# and to skip the kernel module tests that need them
KMOD_TARGETS = $(if $(SKIP_KMOD),,example-kmod test-kmod)
KMOD_SKIP = $(if $(SKIP_KMOD),--skip security_kmod,)

integration-test: $(KMOD_TARGETS)
	sudo ../target/debug/integration_test $(KMOD_SKIP)

integration-test-release: $(KMOD_TARGETS)
	sudo ../target/release/integration_test $(KMOD_SKIP)

# launch and test seabee policy with debug binaries
policy-test: $(TEST_SERVICE_PATH) generate-test-sigs
	sudo ../target/debug/policy_test --test-threads=1

# launch and test seabee policy with release binaries
policy-test-release: $(TEST_SERVICE_PATH) generate-test-sigs
	sudo ../target/release/policy_test --test-threads=1

# compile and compress 'example_kmod/hello_world_kmod.c'
example-kmod:
	@make -C kmod_example test

# remove, compile, and reinstall 'test_kmod/test_kmod.c'
# also compile 'test_kmod/test_kmod_user.c'
test-kmod:
	@make -C kmod_test test

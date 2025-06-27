# Makefile for cGO ECDSA Proof Verifier

# Variables
GO_SRC = ecdsa_verifier.go
C_HEADER = ecdsa_verifier.h
C_TEST = test_c_interface.c
LIB_NAME = libecdsa_verifier
GO_TEST = test_go

# Default target
all: shared static test

# Build shared library (.so)
shared:
	@echo "Building shared library..."
	go build -buildmode=c-shared -o $(LIB_NAME).so $(GO_SRC)
	@echo "Shared library $(LIB_NAME).so created"

# Build static library (.a)
static:
	@echo "Building static library..."
	go build -buildmode=c-archive -o $(LIB_NAME).a $(GO_SRC)
	@echo "Static library $(LIB_NAME).a created"

# Test Go functionality
test-go:
	@echo "Testing Go functionality..."
	go run $(GO_SRC)

# Build C test program (using shared library)
test-c-shared: shared
	@echo "Building C test program with shared library..."
	gcc -o test_c_shared $(C_TEST) -L. -lecdsa_verifier -Wl,-rpath,.
	@echo "C test program 'test_c_shared' created"

# Build C test program (using static library)
test-c-static: static
	@echo "Building C test program with static library..."
	gcc -o test_c_static $(C_TEST) $(LIB_NAME).a -lpthread
	@echo "C test program 'test_c_static' created"

# Run C test with shared library
run-test-shared: test-c-shared
	@echo "Running C test with shared library..."
	./test_c_shared

# Run C test with static library
run-test-static: test-c-static
	@echo "Running C test with static library..."
	./test_c_static

# Build and test everything
test: test-go test-c-shared test-c-static
	@echo "All tests built successfully"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(LIB_NAME).so $(LIB_NAME).a $(LIB_NAME).h
	rm -f test_c_shared test_c_static
	@echo "Clean complete"

# Install dependencies (if needed)
deps:
	@echo "Installing Go dependencies..."
	go mod tidy
	go mod download

# Help
help:
	@echo "Available targets:"
	@echo "  all           - Build shared and static libraries"
	@echo "  shared        - Build shared library (.so)"
	@echo "  static        - Build static library (.a)"
	@echo "  test-go       - Test Go functionality"
	@echo "  test-c-shared - Build C test with shared library"
	@echo "  test-c-static - Build C test with static library"
	@echo "  run-test-shared - Run C test with shared library"
	@echo "  run-test-static - Run C test with static library"
	@echo "  test          - Build all tests"
	@echo "  clean         - Remove build artifacts"
	@echo "  deps          - Install Go dependencies"
	@echo "  help          - Show this help"

.PHONY: all shared static test-go test-c-shared test-c-static run-test-shared run-test-static test clean deps help
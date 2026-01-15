# Makefile for cvc5 verification of rangecheck
#
# This supports two modes:
# 1. Manual tests: verify_recomposition.cpp, verify_constraints.cpp (handwritten)
# 2. Generated tests: verify_rangecheck_*.cpp (generated from gnark compiler output)
#
# To generate tests from gnark:
#   go run generate_test.go
#
# Then build with:
#   make generated

CVC5_DIR = /tmp/cvc5-Linux-x86_64-static-gpl
CXX = g++
CXXFLAGS = -std=c++17 -I$(CVC5_DIR)/include -I../../../internal/smt/templates -O2
LDFLAGS = -L$(CVC5_DIR)/lib -lcvc5 -lcvc5parser -lgmp -lgmpxx -lpthread -ldl

# Static linking for portability
STATIC_LDFLAGS = $(CVC5_DIR)/lib/libcvc5.a \
                 $(CVC5_DIR)/lib/libcvc5parser.a \
                 $(CVC5_DIR)/lib/libcadical.a \
                 $(CVC5_DIR)/lib/libpicpoly.a \
                 $(CVC5_DIR)/lib/libpicpolyxx.a \
                 $(CVC5_DIR)/lib/libcocoa.a \
                 $(CVC5_DIR)/lib/libgmp.a \
                 $(CVC5_DIR)/lib/libgmpxx.a \
                 $(CVC5_DIR)/lib/libcln.a \
                 $(CVC5_DIR)/lib/libglpk.a \
                 -lpthread -ldl

# Manual (handwritten) tests
MANUAL_TARGETS = verify_recomposition verify_constraints

# Generated tests (from gnark compiler output)
GENERATED_SRCS = $(wildcard verify_rangecheck_*.cpp verify_decomposition*.cpp)
GENERATED_TARGETS = $(GENERATED_SRCS:.cpp=)

all: manual

manual: $(MANUAL_TARGETS)

generated: $(GENERATED_TARGETS)

# Generate constraint exports from gnark
generate:
	go run generate_test.go

verify_recomposition: verify_recomposition.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(STATIC_LDFLAGS)

verify_constraints: verify_constraints.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(STATIC_LDFLAGS)

# Pattern rule for generated tests
verify_%: verify_%.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(STATIC_LDFLAGS)

run-manual: $(MANUAL_TARGETS)
	@for t in $(MANUAL_TARGETS); do \
		echo "=== Running $$t ===" ; \
		./$$t ; \
		echo "" ; \
	done

run-generated: $(GENERATED_TARGETS)
	@for t in $(GENERATED_TARGETS); do \
		echo "=== Running $$t ===" ; \
		./$$t ; \
		echo "" ; \
	done

run: run-manual

clean:
	rm -f $(MANUAL_TARGETS) $(GENERATED_TARGETS) verify_rangecheck_*.cpp verify_rangecheck_*.smt2 verify_decomposition*.cpp verify_decomposition*.smt2

.PHONY: all manual generated generate run run-manual run-generated clean

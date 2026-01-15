# Makefile for cvc5 verification of std/math/emulated

CVC5_DIR = /tmp/cvc5-Linux-x86_64-static-gpl
CXX = g++
CXXFLAGS = -std=c++17 -I$(CVC5_DIR)/include -O2

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

TARGETS = verify_emulated verify_edge_cases verify_constraints

all: $(TARGETS)

verify_emulated: verify_emulated.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(STATIC_LDFLAGS)

verify_edge_cases: verify_edge_cases.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(STATIC_LDFLAGS)

verify_constraints: verify_constraints.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(STATIC_LDFLAGS)

run: $(TARGETS)
	./verify_emulated
	@echo ""
	./verify_edge_cases
	@echo ""
	./verify_constraints

clean:
	rm -f $(TARGETS)

.PHONY: all run clean

CXX ?= g++
VERSION_FILE := VERSION
VERSION ?= $(shell cat $(VERSION_FILE) 2>/dev/null)
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo "dev")
VERSION := $(patsubst v%,%,$(VERSION))
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++11
CXXFLAGS += -DPROGRAM_VERSION=\"$(VERSION)\"
BIN_DIR := build
BIN := $(BIN_DIR)/voip_port_edit
SRC := src/voip_port_edit.cpp

.PHONY: build clean

build: $(BIN)

$(BIN): $(SRC)
	mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(BIN)

clean:
	rm -rf $(BIN_DIR)

CC = g++
CFLAGS = -Wall -g -std=c++11 -lpthread -lcrypto
SERVER_SRC_DIR = src
SERVER_EXE = server
BUILD_DIR = build

SERVER_SRC = $(SERVER_SRC_DIR)/server.cpp

all: $(BUILD_DIR)/$(SERVER_EXE)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(SERVER_EXE): $(SERVER_SRC) $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o $@

run: $(BUILD_DIR)/$(SERVER_EXE)
	@echo "Running server..."
	./$(BUILD_DIR)/$(SERVER_EXE)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all run clean

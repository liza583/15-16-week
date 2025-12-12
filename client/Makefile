CC = g++
CFLAGS = -Wall -g -std=c++11 -lcrypto -lpthread

# Source directories
CLIENT_SRC_DIR = src
CLIENT_EXE = client
BUILD_DIR = build

# Source files - обратите внимание на src/
CLIENT_SRC = $(CLIENT_SRC_DIR)/client.cpp

all: $(BUILD_DIR)/$(CLIENT_EXE)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(CLIENT_EXE): $(CLIENT_SRC) $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

run: $(BUILD_DIR)/$(CLIENT_EXE)
	@echo "Running client..."
	./$(BUILD_DIR)/$(CLIENT_EXE)

run_workers_3: $(BUILD_DIR)/$(CLIENT_EXE)
	@echo "Running 3 clients..."
	./$(BUILD_DIR)/$(CLIENT_EXE) & \
	./$(BUILD_DIR)/$(CLIENT_EXE) & \
	./$(BUILD_DIR)/$(CLIENT_EXE) &

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all run clean run_workers_3

CC = gcc
CFLAGS = -O3 -Wall -pedantic -Wextra -Wc++-compat
LDFLAGS = -lmicrohttpd -lpthread -lmpg123 -lao -ljson-c
#SANITIZER = -fsanitize=address -g
SANITIZER = -fsanitize=undefined -g
#SANITIZER = -fsanitize=leak -g
LDFLAGS += $(SANITIZER)

SRC_DIR = ./src
BUILD_DIR = ./build
SOURCES = $(wildcard $(SRC_DIR)/*.c)
HEADERS = $(wildcard $(SRC_DIR)/*.h)
EXECUTABLE = $(BUILD_DIR)/pac
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))



all: prebuild $(EXECUTABLE)

prebuild:
	@echo ===== Variables =====
	@echo SOURCES: $(SOURCES)
	@echo HEADERS: $(HEADERS)
	@echo OBJS: $(OBJS)
	@echo CFLAGS: $(CFLAGS)
	@echo LDFLAGS: $(LDFLAGS)
	@echo SANITIZER: $(SANITIZER)
	@echo ===== Variables =====
	@echo 
	@mkdir -p $(BUILD_DIR)

$(EXECUTABLE): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@ $(SANITIZER)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all prebuild clean

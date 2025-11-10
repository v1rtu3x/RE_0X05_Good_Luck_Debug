# Makefile for good_luck_debug

CC := gcc
CFLAGS := -O2 -Wall -Wextra -fno-stack-protector -no-pie
TARGET := good_luck_debug
BUILD_DIR := ../build
TARGET := $(BUILD_DIR)/good_luck_debug

SRC := good_luck_debug.c

all: $(BUILD_DIR) $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^


$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean


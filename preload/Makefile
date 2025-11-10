#Makefile for preload.c

CC := gcc
CFLAGS := -O2 -Wall -Wextra -fPIC
LDFLAGS := -shared -ldl
BUILD_DIR = ../build
TARGET := $(BUILD_DIR)/preload.so

SRC := preload.c

all: $(BUILD_DIR) $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean: 
	rm -rf $(TARGET)

.PHONY: all clean
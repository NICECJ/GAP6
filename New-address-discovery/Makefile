CC = gcc

CFLAGS = -O3 -march=native -mcmodel=medium -fPIC \
         -Iinclude -Iprotocols

LDFLAGS = -lm -lpthread

SRC = $(wildcard src/*.c) \
      $(wildcard protocols/*/*.c)

OBJ = $(patsubst %.c,build/%.o,$(SRC))

TARGET = bin/main

all: $(TARGET)

$(TARGET): $(OBJ)
	mkdir -p bin
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

build/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build bin

.PHONY: all clean
CC     ?= gcc
CFLAGS ?= -O3 -msha -msse4.1 -Wall
SRC     = src/miner.c src/sha256ni.S
TARGET  = btc-miner-c

ifeq ($(OS),Windows_NT)
  TARGET := btc-miner-c.exe
  LDLIBS := -lws2_32 -lm
else
  LDLIBS := -lpthread -lm
endif

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

clean:
	-rm -f btc-miner-c btc-miner-c.exe

.PHONY: all clean
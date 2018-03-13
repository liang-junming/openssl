ifeq ($(TARGET_ARM), 1)
CC = arm-none-linux-gnueabi-gcc
LIBDIR = ../../ssl_out_arm
else
CC = gcc
LIBDIR = ../../ssl_out_host
endif

INCLUDE = -I$(LIBDIR)/include
LIBS = -L$(LIBDIR)/lib


all: verify.c sign.c
	$(CC) $(INCLUDE) $(LIBS) -Wall -static sign.c -o sign -lssl -lcrypto -ldl
	$(CC) $(INCLUDE) $(LIBS) -Wall -static verify.c -o verify -lssl -lcrypto -ldl

clean:
	rm -rf sign verify

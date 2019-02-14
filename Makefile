CC = gcc
CFLAGS = -g
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  mitm-$(EXEC_SUFFIX)

mitm-$(EXEC_SUFFIX): main.c parse.c checksum.c
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ main.c parse.c packetutil.c packetsend.c  checksum.c -lpcap

clean:
	-rm -rf mitm-* mitm-*.dSYM


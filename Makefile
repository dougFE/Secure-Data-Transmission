CC=gcc
CPPFLAGS=-Wall -Wextra
LDFLAGS=
LDLIBS=-ltransport -lsecurity -lcrypto

DEPS=io.o security.o

all: server client

server: server.o $(DEPS)
client: client.o $(DEPS)

security.o: util.h tlv_utils.h crypto_utils.h

clean:
	@find . -type f \
		! -name "*.c" \
		! -name "*.h" \
		! -name "*.cpp" \
		! -name "*.hpp" \
		! -name "Makefile" \
		! -name "README.md" -delete
	@find . -type d \( ! -name "." \) -exec rm -rf {} +

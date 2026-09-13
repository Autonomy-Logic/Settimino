# Host-side tests for the S7 server.
#
# The server owns no socket, so all of this runs on a PC with no board and no
# network. Run it before you flash anything.
#
#   make          unit tests, under AddressSanitizer and UBSan
#   make harness  a POSIX TCP server wrapping the engine, for real clients
#   make interop  the above, driven by python-snap7

CXX      ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -Werror -O1 -g
SAN      ?= -fsanitize=address,undefined -fno-omit-frame-pointer
PORT     ?= 1102

.PHONY: test harness interop clean

test:
	$(CXX) $(CXXFLAGS) $(SAN) -I.. ../S7Server.cpp test_s7server.cpp -o /tmp/s7server_test
	/tmp/s7server_test

harness:
	$(CXX) $(CXXFLAGS) -I.. ../S7Server.cpp harness.cpp -o /tmp/s7server_harness

interop: harness
	@/tmp/s7server_harness $(PORT) & echo $$! > /tmp/s7h.pid; \
	python3 -c 'import time; time.sleep(1)'; \
	python3 test_interop.py 127.0.0.1 $(PORT); status=$$?; \
	kill `cat /tmp/s7h.pid` 2>/dev/null; rm -f /tmp/s7h.pid; \
	exit $$status

clean:
	rm -f /tmp/s7server_test /tmp/s7server_harness

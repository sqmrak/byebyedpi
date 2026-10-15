# host tests, plain clang or gcc
CC      ?= cc
CORE    = ../core
CFLAGS  ?= -std=c99 -Wall -Wextra -O2
CFLAGS  += -I$(CORE) -I. $(SAN)
TLS_CFLAGS  := $(shell pkg-config --cflags openssl 2>/dev/null)
TLS_LDFLAGS := $(shell pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)

TUN        = ../daemon/tun
TUN_CFLAGS = -I$(TUN) -I$(TUN)/core -Itun
LWIP       = $(TUN)/third_party/lwip/src
LWIP_PORT  = $(TUN)/lwip_port
LWIP_CFLAGS = -I$(LWIP_PORT) -I$(LWIP)/include
LWIP_SRC   = $(wildcard $(LWIP)/core/*.c) $(wildcard $(LWIP)/core/ipv4/*.c) \
             $(wildcard $(LWIP)/core/ipv6/*.c) $(LWIP_PORT)/lwip_sys.c
# the vendored stack builds quiet and apart, its warnings are not ours to fix
# a sanitizer build keeps its own objects, so the two never mix
BUILD      = build$(if $(SAN),-san,)
LWIP_OBJ   = $(patsubst $(TUN)/%.c,$(BUILD)/lwip/%.o,$(LWIP_SRC))
LWIP_LIB   = $(BUILD)/liblwip.a
THREAD_CFLAGS  = -pthread
THREAD_LDFLAGS = -pthread

TUN_TESTS = test_tun_plan test_utun_framing test_route_message test_route_socket \
            test_lwip_smoke test_tun_throughput test_tun_nat test_tun_stack test_tun_loop test_legacy_ios test_proc_detach

HOST_TESTS = test_sniff test_fake test_desync test_mtp test_ws test_tg test_config test_config_file test_hosts test_status test_reply test_client test_hostsfile test_altaddr test_probe test_probe_dns test_fuzz test_wsconn test_tgproxy test_flows test_gateway_resolve test_tcp_first test_external_interface test_start_error test_physical_path test_tls_hooks test_ctl_owner test_tls_owner

.PHONY: all test clean sanitize test_ctl probe benchmark
all: test

test: $(HOST_TESTS) $(TUN_TESTS)
	@for t in $(HOST_TESTS) $(TUN_TESTS); do ./$$t || exit 1; done
	python3 test_launchd_install.py
	$(MAKE) test_ctl

test_ctl_owner: test_ctl_owner.c ../daemon/bye_ctl.c ../daemon/bye_ctl.h check.h
	$(CC) $(CFLAGS) -I../daemon test_ctl_owner.c ../daemon/bye_ctl.c -o $@

test_tls_owner: test_tls_owner.c ../daemon/bye_tls_owner.c ../daemon/bye_tls_owner.h ../daemon/bye_paths.h check.h
	$(CC) $(CFLAGS) -I../daemon test_tls_owner.c -o $@

test_tls_hooks: test_tls_hooks.c ../byebyetlsfix/stl_hooks.c ../byebyetlsfix/stl_hooks.h ../byebyetlsfix/stl_log.h ../byebyetlsfix/stl_init.c ../byebyetlsfix/stl_gate.h ../byebyetlsfix/stl_shadow.h check.h
	$(CC) $(CFLAGS) test_tls_hooks.c -o $@

test_fake: test_fake.c $(CORE)/bye_fake.c $(CORE)/bye_desync.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c check.h hello_openssl.inc
	$(CC) $(CFLAGS) test_fake.c $(CORE)/bye_fake.c $(CORE)/bye_desync.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c -o $@

test_sniff: test_sniff.c $(CORE)/bye_sniff.c check.h hello_openssl.inc
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_sniff.c $(CORE)/bye_sniff.c -o $@ $(TLS_LDFLAGS)

test_desync: test_desync.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(CORE)/bye_ciadpi.h check.h hello_openssl.inc
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_desync.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c -o $@ $(TLS_LDFLAGS)

test_mtp: test_mtp.c $(CORE)/bye_mtp.c $(CORE)/bye_mtp.h check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_mtp.c $(CORE)/bye_mtp.c -o $@ $(TLS_LDFLAGS)

test_ws: test_ws.c $(CORE)/bye_ws.c $(CORE)/bye_ws.h check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_ws.c $(CORE)/bye_ws.c -o $@ $(TLS_LDFLAGS)

test_tg: test_tg.c $(CORE)/bye_tg.c $(CORE)/bye_route.c check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_tg.c $(CORE)/bye_tg.c $(CORE)/bye_route.c -o $@ $(TLS_LDFLAGS)

test_start_error: test_start_error.c $(CORE)/bye_error.c $(CORE)/bye_error.h check.h
	$(CC) $(CFLAGS) test_start_error.c $(CORE)/bye_error.c -o $@

test_physical_path: test_physical_path.c ../daemon/bye_backend.c ../daemon/bye_fakesend.c $(CORE)/bye_route.c $(CORE)/bye_tg.c $(TUN)/core/tun_plan.c check.h
	$(CC) $(CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) -ffunction-sections -fdata-sections \
	      test_physical_path.c $(CORE)/bye_route.c $(CORE)/bye_tg.c $(TUN)/core/tun_plan.c \
	      -Wl,--gc-sections -o $@ $(THREAD_LDFLAGS)

# discard the platform backend sections so only the bounded resolver runs on the host
test_gateway_resolve: test_gateway_resolve.c ../daemon/bye_backend.c ../daemon/bye_fakesend.c $(CORE)/bye_tg.c
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) \
	      -ffunction-sections -fdata-sections test_gateway_resolve.c ../daemon/bye_backend.c ../daemon/bye_fakesend.c \
	      $(CORE)/bye_tg.c -Wl,--gc-sections -o $@ $(THREAD_LDFLAGS)

test_config: test_config.c $(CORE)/bye_config.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(CORE)/bye_hosts.c check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_config.c $(CORE)/bye_config.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(CORE)/bye_hosts.c -o $@ $(TLS_LDFLAGS)

test_config_file: test_config_file.c ../daemon/main.c $(wildcard ../daemon/*.h) $(CORE)/bye_config.c $(CORE)/bye_config.h $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(CORE)/bye_hosts.c check.h
	$(CC) $(CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) -ffunction-sections -fdata-sections \
	      test_config_file.c $(CORE)/bye_config.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(CORE)/bye_hosts.c \
	      -Wl,--gc-sections -o $@ $(THREAD_LDFLAGS)

test_hosts: test_hosts.c $(CORE)/bye_hosts.c $(CORE)/bye_hosts.h check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_hosts.c $(CORE)/bye_hosts.c -o $@ $(TLS_LDFLAGS)

test_altaddr: test_altaddr.c ../daemon/bye_altaddr.c ../daemon/bye_altaddr.h $(CORE)/bye_route.c $(CORE)/bye_tg.c check.h
	$(CC) $(CFLAGS) -I../daemon $(THREAD_CFLAGS) test_altaddr.c ../daemon/bye_altaddr.c $(CORE)/bye_route.c $(CORE)/bye_tg.c -o $@ $(THREAD_LDFLAGS)

test_probe: test_probe.c ../daemon/bye_probe.c ../daemon/bye_probe.h $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(TUN)/core/senko_time.c $(TUN)/direct_socket.c $(TUN)/route_socket.c $(TUN)/core/route_message.c check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) test_probe.c ../daemon/bye_probe.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(TUN)/core/senko_time.c $(TUN)/direct_socket.c $(TUN)/route_socket.c $(TUN)/core/route_message.c -o $@ $(TLS_LDFLAGS) $(THREAD_LDFLAGS)

test_probe_dns: test_probe_dns.c ../daemon/bye_probe.c ../daemon/bye_probe.h $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(TUN)/core/senko_time.c $(TUN)/direct_socket.c $(TUN)/route_socket.c $(TUN)/core/route_message.c check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) test_probe_dns.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(TUN)/core/senko_time.c $(TUN)/direct_socket.c $(TUN)/route_socket.c $(TUN)/core/route_message.c -o $@ $(TLS_LDFLAGS) $(THREAD_LDFLAGS)

test_reply: test_reply.c $(CORE)/bye_reply.c $(CORE)/bye_reply.h check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_reply.c $(CORE)/bye_reply.c -o $@ $(TLS_LDFLAGS)

test_client: test_client.c $(CORE)/bye_client.c $(CORE)/bye_client.h check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(THREAD_CFLAGS) test_client.c $(CORE)/bye_client.c -o $@ $(TLS_LDFLAGS) $(THREAD_LDFLAGS)

test_hostsfile: test_hostsfile.c ../daemon/bye_hostsfile.c ../daemon/bye_hostsfile.h $(CORE)/bye_hosts.c check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) -I../daemon test_hostsfile.c ../daemon/bye_hostsfile.c $(CORE)/bye_hosts.c -o $@ $(TLS_LDFLAGS)

test_status: test_status.c $(CORE)/bye_status.c $(CORE)/bye_status.h check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_status.c $(CORE)/bye_status.c -o $@ $(TLS_LDFLAGS)

sanitize:
	$(MAKE) clean
	$(MAKE) test SAN='-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined'

test_fuzz: test_fuzz.c $(CORE)/bye_sniff.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_mtp.c $(CORE)/bye_ws.c $(CORE)/bye_config.c $(CORE)/bye_hosts.c check.h hello_openssl.inc
	$(CC) $(CFLAGS) $(TLS_CFLAGS) test_fuzz.c $(CORE)/bye_sniff.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_mtp.c $(CORE)/bye_ws.c $(CORE)/bye_config.c $(CORE)/bye_hosts.c -o $@ $(TLS_LDFLAGS)

$(BUILD)/lwip/%.o: $(TUN)/%.c $(LWIP_PORT)/lwipopts.h
	@mkdir -p $(dir $@)
	$(CC) -std=c99 -O2 -w $(SAN) $(LWIP_CFLAGS) -I$(TUN) -I$(TUN)/core -c $< -o $@

$(LWIP_LIB): $(LWIP_OBJ)
	rm -f $@
	ar rcs $@ $(LWIP_OBJ)

test_tun_plan: tun/test_tun_plan.c $(TUN)/core/tun_plan.c
	$(CC) $(CFLAGS) $(TUN_CFLAGS) tun/test_tun_plan.c $(TUN)/core/tun_plan.c -o $@

test_utun_framing: tun/test_utun_framing.c $(TUN)/core/utun_frame.c
	$(CC) $(CFLAGS) $(TUN_CFLAGS) tun/test_utun_framing.c $(TUN)/core/utun_frame.c -o $@

test_route_message: tun/test_route_message.c $(TUN)/core/route_message.c
	$(CC) $(CFLAGS) $(TUN_CFLAGS) tun/test_route_message.c $(TUN)/core/route_message.c -o $@

test_route_socket: tun/test_route_socket.c $(TUN)/route_socket.c $(TUN)/core/route_message.c
	$(CC) $(CFLAGS) $(TUN_CFLAGS) tun/test_route_socket.c $(TUN)/route_socket.c $(TUN)/core/route_message.c -o $@

test_legacy_ios: tun/test_legacy_ios.c $(TUN)/legacy_ios.c
	$(CC) $(CFLAGS) $(TUN_CFLAGS) tun/test_legacy_ios.c $(TUN)/legacy_ios.c -o $@

test_proc_detach: tun/test_proc_detach.c $(TUN)/proc_detach.c
	$(CC) $(CFLAGS) $(TUN_CFLAGS) tun/test_proc_detach.c $(TUN)/proc_detach.c -o $@ -rdynamic -ldl

test_lwip_smoke: tun/test_lwip_smoke.c $(LWIP_LIB)
	$(CC) $(CFLAGS) $(TUN_CFLAGS) $(LWIP_CFLAGS) tun/test_lwip_smoke.c $(LWIP_LIB) $(TUN)/core/senko_time.c -o $@

test_tun_nat: tun/test_tun_nat.c tun/packet_fixture.h $(TUN)/core/tun_nat.c
	$(CC) $(CFLAGS) $(TUN_CFLAGS) tun/test_tun_nat.c $(TUN)/core/tun_nat.c -o $@

test_tun_stack: tun/test_tun_stack.c tun/packet_fixture.h $(TUN)/tun_stack.c $(TUN)/core/tun_nat.c \
                $(TUN)/core/utun_frame.c $(LWIP_LIB)
	$(CC) $(CFLAGS) $(TUN_CFLAGS) $(LWIP_CFLAGS) $(THREAD_CFLAGS) tun/test_tun_stack.c $(TUN)/tun_stack.c \
	      $(TUN)/core/tun_nat.c $(TUN)/core/utun_frame.c $(LWIP_LIB) $(TUN)/core/senko_time.c \
	      -o $@ $(THREAD_LDFLAGS)

test_tun_loop: tun/test_tun_loop.c tun/packet_fixture.h $(TUN)/tun_loop.c $(TUN)/utun_device.c \
               $(TUN)/tun_stack.c $(TUN)/core/tun_nat.c $(TUN)/core/utun_frame.c $(LWIP_LIB)
	$(CC) $(CFLAGS) $(TUN_CFLAGS) $(LWIP_CFLAGS) $(THREAD_CFLAGS) tun/test_tun_loop.c $(TUN)/tun_loop.c \
	      $(TUN)/utun_device.c $(TUN)/tun_stack.c $(TUN)/core/tun_nat.c $(TUN)/core/utun_frame.c \
	      $(LWIP_LIB) $(TUN)/core/senko_time.c -o $@ $(THREAD_LDFLAGS)

test_wsconn: test_wsconn.c ws_server.py ../daemon/bye_wsconn.c ../daemon/bye_wsconn.h $(CORE)/bye_ws.c check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) -D_DEFAULT_SOURCE -I../daemon test_wsconn.c ../daemon/bye_wsconn.c $(CORE)/bye_ws.c -o $@ $(TLS_LDFLAGS)

test_tgproxy: test_tgproxy.c ../daemon/bye_tgproxy.c ../daemon/bye_tgproxy.h ../daemon/bye_wsconn.c $(CORE)/bye_mtp.c \
              $(CORE)/bye_ws.c $(CORE)/bye_tg.c $(CORE)/bye_route.c $(TUN)/core/senko_time.c check.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) test_tgproxy.c \
	      ../daemon/bye_tgproxy.c ../daemon/bye_wsconn.c $(CORE)/bye_mtp.c $(CORE)/bye_ws.c $(CORE)/bye_tg.c \
	      $(CORE)/bye_route.c $(TUN)/core/senko_time.c -o $@ $(TLS_LDFLAGS) $(THREAD_LDFLAGS)

BYE_SRC = ../daemon/bye_tcp.c ../daemon/bye_altaddr.c ../daemon/bye_udp.c ../daemon/bye_wsconn.c $(CORE)/bye_mtp.c \
          $(CORE)/bye_ws.c $(CORE)/bye_tg.c $(CORE)/bye_route.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c \
          $(CORE)/bye_sniff.c $(CORE)/bye_hosts.c $(TUN)/direct_socket.c $(TUN)/route_socket.c $(TUN)/core/route_message.c \
          $(TUN)/tun_loop.c $(TUN)/utun_device.c $(TUN)/tun_stack.c $(TUN)/core/tun_nat.c \
          $(TUN)/core/utun_frame.c $(TUN)/core/senko_time.c

test_flows: test_flows.c tun/packet_fixture.h hello_openssl.inc hello_fixture.h $(BYE_SRC) $(LWIP_LIB)
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) $(LWIP_CFLAGS) -I../daemon $(THREAD_CFLAGS) test_flows.c \
	      $(BYE_SRC) $(LWIP_LIB) -o $@ $(TLS_LDFLAGS) $(THREAD_LDFLAGS)

DAEMON_SRC = $(TUN)/proc_detach.c ../daemon/main.c ../daemon/bye_tgproxy.c ../daemon/bye_backend.c ../daemon/bye_fakesend.c ../daemon/bye_badge.c ../daemon/bye_hostsfile.c ../daemon/bye_ctl.c ../daemon/bye_tls_owner.c ../daemon/bye_iface.c ../daemon/bye_probe.c ../daemon/bye_resolver.c \
             $(BYE_SRC) $(CORE)/bye_config.c $(CORE)/bye_status.c $(TUN)/utun_route.c $(TUN)/utun_dns.c \
             $(TUN)/legacy_ios.c $(TUN)/core/tun_plan.c

byedpid-host: $(DAEMON_SRC) $(LWIP_LIB)
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) $(LWIP_CFLAGS) -I../daemon $(THREAD_CFLAGS) $(DAEMON_SRC) \
	      $(LWIP_LIB) -o $@ $(TLS_LDFLAGS) $(THREAD_LDFLAGS)

byebyectl-host: ../daemon/byebyectl.c $(CORE)/bye_client.c $(CORE)/bye_client.h
	$(CC) $(CFLAGS) -I../daemon ../daemon/byebyectl.c $(CORE)/bye_client.c -o $@

test_ctl: ctl_smoke.sh byedpid-host byebyectl-host
	./ctl_smoke.sh

probe_gateway: probe_gateway.c ../daemon/bye_backend.c ../daemon/bye_fakesend.c ../daemon/bye_wsconn.c $(CORE)/bye_mtp.c $(CORE)/bye_ws.c $(CORE)/bye_tg.c
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) -ffunction-sections -fdata-sections \
	      probe_gateway.c ../daemon/bye_backend.c ../daemon/bye_fakesend.c ../daemon/bye_wsconn.c $(CORE)/bye_mtp.c $(CORE)/bye_ws.c \
	      $(CORE)/bye_tg.c -Wl,--gc-sections -o $@ $(TLS_LDFLAGS) $(THREAD_LDFLAGS)

# the live gateway of datacenter 2; needs the public network
probe: probe_gateway
	./probe_gateway $(PROBE_ROOTS)

clean:
	rm -rf $(HOST_TESTS) $(TUN_TESTS) build build-san byedpid-host byebyectl-host probe_gateway

# exercise first-payload collection without a public service or a host listener
test_tcp_first: test_tcp_first.c hello_openssl.inc hello_fixture.h ../daemon/bye_tcp.c ../daemon/bye_altaddr.c ../daemon/bye_wsconn.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c $(CORE)/bye_sniff.c $(CORE)/bye_hosts.c
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) -ffunction-sections -fdata-sections \
	      test_tcp_first.c ../daemon/bye_altaddr.c ../daemon/bye_wsconn.c $(CORE)/bye_desync.c $(CORE)/bye_fake.c $(CORE)/bye_ciadpi.c \
	      $(CORE)/bye_sniff.c $(CORE)/bye_hosts.c $(CORE)/bye_mtp.c $(CORE)/bye_ws.c $(CORE)/bye_route.c $(CORE)/bye_tg.c \
	      $(TUN)/core/senko_time.c $(TUN)/route_socket.c $(TUN)/core/route_message.c -Wl,--gc-sections \
	      -o $@ $(TLS_LDFLAGS) $(THREAD_LDFLAGS)

test_external_interface: test_external_interface.c ../daemon/bye_backend.c ../daemon/bye_fakesend.c ../daemon/bye_backend.h
	$(CC) $(CFLAGS) $(TLS_CFLAGS) $(TUN_CFLAGS) -I../daemon $(THREAD_CFLAGS) -ffunction-sections -fdata-sections \
	      test_external_interface.c ../daemon/bye_backend.c ../daemon/bye_fakesend.c -Wl,--gc-sections -o $@ $(THREAD_LDFLAGS)

test_tun_throughput: tun/test_tun_throughput.c tun/packet_fixture.h $(TUN)/tun_stack.c $(TUN)/core/tun_nat.c $(TUN)/core/utun_frame.c $(LWIP_LIB)
	$(CC) $(CFLAGS) $(TUN_CFLAGS) $(LWIP_CFLAGS) $(THREAD_CFLAGS) tun/test_tun_throughput.c $(TUN)/tun_stack.c \
	      $(TUN)/core/tun_nat.c $(TUN)/core/utun_frame.c $(LWIP_LIB) $(TUN)/core/senko_time.c -o $@ $(THREAD_LDFLAGS)

benchmark: test_flows
	./test_flows --benchmark

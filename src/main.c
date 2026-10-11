#define _DEFAULT_SOURCE
#include <time.h>
#include <stdio.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "attach.h"
#include "shared.h"
#include "hmac.h"
#include "xdp-knock.skel.h"

static config_t conf = {};
struct xdp_knock *skel;

__u64 get_timestamp(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	packet_t *event = data;


	__u64 curr_ts = get_timestamp();

	if (hmac_is_valid_knock(event->payload_data, conf.shared_secret)) {
		printf("NEW IP Authorized\n");
		bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_map), &event->src_address, &curr_ts, 0);
	}

	return 0;
}

int main(void)
{
	skel = NULL;

	if (parse_config(&conf) != 0)
		return 1;

	if (xdp_attach(&conf, &skel) != 0) {
		fprintf(stderr, "Failed to attach XDP program\n");
		return 1;
	}

	printf("Starting XDP-Knock on port: %d...\n", conf.knock_port);
	printf("Press Ctrl+C to stop\n");

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events_rb), handle_event, NULL, NULL);

	while (1) {
		int err = ring_buffer__poll(rb, 100);
		if (err < 0) {
			fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
			break;
		}
	}

	xdp_detach(&skel);
	return 0;
}

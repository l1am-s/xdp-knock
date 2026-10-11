#include <stdio.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "attach.h"
#include "xdp-knock.skel.h"



int xdp_attach(config_t *conf, struct xdp_knock **skel)
{
	*skel = xdp_knock__open_and_load();
	if (!(*skel)) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	(*skel)->bss->knock_port = conf->knock_port;
	(*skel)->bss->access_window_s = conf->access_window_s;

	int ifindex = if_nametoindex(conf->interface);
	if (ifindex < 0) {
		perror("if_nametoindex");
		xdp_knock__destroy((*skel));
		(*skel) = NULL;
		return 1;
	}

	if (!bpf_program__attach_xdp((*skel)->progs.xdp_check_prog, ifindex)) {
		fprintf(stderr, "Failed to attach XDP program\n");
		xdp_knock__destroy(*skel);
		*skel = NULL;
		return 1;
	}

	return 0;
}

int xdp_detach(struct xdp_knock **skel)
{
	xdp_knock__detach(*skel);
	xdp_knock__destroy(*skel);
	*skel = NULL;
	return 0;
}

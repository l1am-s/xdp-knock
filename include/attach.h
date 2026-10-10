#ifndef ATTACH_H
#define ATTACH_H

#include "config.h"

struct xdp_knock;

int xdp_attach(config_t *conf, struct xdp_knock **skel);
int xdp_detach(struct xdp_knock **skel);

#endif

#ifndef SHARED_H
#define SHARED_H

#ifndef __VMLINUX_H__
#include <stdint.h>
typedef uint32_t __u32;
#endif

typedef struct {
	__u32 ip_parts[4];
} member_t;

typedef struct {
	member_t src_address;
	uint8_t payload_data[48];
} packet_t;

#endif

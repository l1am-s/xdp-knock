#ifndef CONFIG_H
#define CONFIG_H

#define CONFIG_SIZE_LIMIT 1024

#include <stdint.h>

typedef struct {
	char interface[250];
	uint16_t knock_port;
	char shared_secret[250];
	uint32_t access_window_s;
} config_t;

char *trim_whitespaces(char *str);

int parse_config(config_t *conf);

#endif

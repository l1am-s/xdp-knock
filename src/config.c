#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#define CHECK(a,b) (strcmp((a), (b)) == 0)

// int get_attach_mode(char *str) {
//     if (CHECK(str, "XDP_FLAGS_SKB_MODE")) {
//         return XDP_FLAGS_SKB_MODE;
//     } else if (CHECK(str, "XDP_FLAGS_DRV_MODE")) {
//         return XDP_FLAGS_DRV_MODE;
//     } else if (CHECK(str, "XDP_FLAGS_HW_MODE")) {
//         return XDP_FLAGS_HW_MODE;
//     }
//
//     return 0;
// }

char *trim_whitespaces(char *str)
{
	while (isspace(*str))
		str++;
	if (*str == 0)
		return str;

	char *end = str + strlen(str) - 1;
	while (end > str && isspace(*end))
		end--;
	end[1] = '\0';

	return str;
}

int parse_config(config_t *conf)
{
	char buff[CONFIG_SIZE_LIMIT];

	FILE *fptr = fopen("config.cfg", "r");
	if (!fptr) {
		perror("Error opening config.cfg file");
		return -1;
	}

	while (fgets(buff, CONFIG_SIZE_LIMIT, fptr)) {
		char *equal_mark_loc = strchr(buff, '=');

		if (!equal_mark_loc)
			continue;

		*equal_mark_loc = '\0';

		char *key = trim_whitespaces(buff);
		char *value = trim_whitespaces(equal_mark_loc + 1);

		if (strcmp(key, "interface") == 0) {
			snprintf(conf->interface, sizeof(conf->interface), "%s", value);
		} else if (strcmp(key, "knock_port") == 0) {
			conf->knock_port = (uint16_t)atoi(value);
		} else if (strcmp(key, "shared_secret") == 0) {
			snprintf(conf->shared_secret, sizeof(conf->shared_secret), "%s", value);
		} else if (strcmp(key, "access_window_s") == 0) {
			conf->access_window_s = (uint32_t)atoi(value);
		} // else if (strcmp(key, "attach_mode") == 0) {
		//     conf->attach_mode = get_attach_mode(value);
		// }
	}

	fclose(fptr);

	return 0;
}

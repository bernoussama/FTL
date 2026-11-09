/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL rust-compare <module> [args]: C vs Rust comparison driver
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Each module has its own ftl_rs_compare_<module>() in ftl_rs_compare_<module>.c.
// They run the C and the Rust implementation of the module in this process on
// the same inputs, print every difference and a summary line, and return
// EXIT_SUCCESS only if both agree on everything.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ftl_rs.h"

int ftl_rs_compare(int argc, char *argv[])
{
	static const struct {
		const char *name;
		int (*run)(int argc, char *argv[]);
	} modules[] = {
		{ "sha256", ftl_rs_compare_sha256 },
		{ "idn2", ftl_rs_compare_idn2 },
		{ "complete", ftl_rs_compare_complete },
	};

	if(argc >= 1)
		for(size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); i++)
			if(strcmp(argv[0], modules[i].name) == 0)
				return modules[i].run(argc - 1, argv + 1);

	printf("Usage: pihole-FTL rust-compare <module> [args]\nModules:");
	for(size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); i++)
		printf(" %s", modules[i].name);
	printf("\n");
	return EXIT_FAILURE;
}

/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL rust-compare sha256: C vs Rust comparison
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <stdio.h>
#include <stdlib.h>
#include "ftl_rs.h"

int ftl_rs_compare_sha256(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	printf("rust-compare sha256: not implemented yet\n");
	return EXIT_FAILURE;
}

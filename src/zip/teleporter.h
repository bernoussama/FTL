/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Compression routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef TELEPORTER_H
#define TELEPORTER_H

#include "zip/miniz/miniz.h"
#include "webserver/cJSON/cJSON.h"
#ifdef HAVE_FTL_RS
#include "ftl_rs.h"
#endif

// A finished Teleporter ZIP archive: data points at size bytes. Release it with
// free_teleporter_zip(), not with free().
struct teleporter_zip {
	uint8_t *data;
	size_t size;
#ifdef HAVE_FTL_RS
	ftl_rs_buf buf; // the Rust buffer that data points into
#endif
};

const char *generate_teleporter_zip(char filename[128], struct teleporter_zip *zip);
void free_teleporter_zip(struct teleporter_zip *zip);
bool valid_dhcp_leases(const char *data, const size_t size);
const char *read_teleporter_zip(uint8_t *buffer, const size_t buflen, char *hint, cJSON *import, cJSON *json_files);

bool write_teleporter_zip_to_disk(void);
bool read_teleporter_zip_from_disk(const char *filename);

#endif // TELEPORTER_H

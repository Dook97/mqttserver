#include <stdio.h>
#include <unistd.h>

#include "mqtt.h"
#include "magic.h"

/* Verify whether a string is valid w.r.t. the MQTT specification
 *
 * Conditions:
 *	- strlen(str) <= UINT16_MAX
 *	- mustn't include codepoints U+D800..U+DFFF
 *	- mustn't include U+0000
 *	- shouldn't include U+0001..U+001F or U+007F..U+009F
 *	- shouldn't include non-character codepoints (like U+0FFFF)
 *
 * This function doesn't check all of these.
 *
 * @retval true If valid.
 * @retval false If invalid.
 */
static bool validate_str(size_t len, char str[static len]) {
	return true;
}

/* Read and decode between 1 and 4 bytes of data present in the 'Remaining Length' field in the
 * fixed header of a MQTT packet.
 *
 * @param The connection file descriptor.
 * @retval -1 on invalid input
 */
static int32_t decode_remaining_length(int conn) {
	int32_t output = 0;
	int32_t buf = 0;
	int nread = 0;
	for (; nread < 4; ++nread) {
		ssize_t readret = 0;
		if ((readret = read(conn, &buf, 1)) == 0)
			break;
		else if (readret == -1)
			return -1;

		output |= (buf & 0x7f) << (nread * 7);

		if (!(buf & 0x80))
			break;
	}
	if (buf & 0x80)
		return -1;

	return output;
}

/* Decode between 1 and 4 bytes of data present in the 'Remaining Length' field in the fixed header.
 *
 * @retval UINT32_MAX on invalid input
 */
static char *encode_remaining_length(char bytes[4]);

bool process_packet(int conn, user_data *u) {
	char buf[1024] = {0};
	int i = read(conn, buf, 1);

	if (i == 0)
		return false;

	int32_t remaining = decode_remaining_length(conn);
	printf("%d\n", remaining);
	fflush(stdout);

	return true;
}

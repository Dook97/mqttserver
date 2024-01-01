#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mqtt.h"
#include "magic.h"

static uint16_t read_uint16(const unsigned char buf[static 2]) {
	return ((uint16_t)buf[0] << 8) + (uint16_t)buf[1];
}

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
// static bool validate_str(size_t len, char str[static len]) {
// 	return true;
// }

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
		if (read(conn, &buf, 1) < 1)
			break;

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

static bool connect_handler(const fixed_header *hdr, user_data *usr, const char *packet) {
	DPRINTF("User sent a " MAGENTA("CONNECT") " packet\n");

	assert(!usr->CONNECT_recieved);
	usr->CONNECT_recieved = true;

	unsigned char *read_head = (unsigned char *)packet;

	/* Figure 3.2 - Protocol Name bytes
	 * this is safe - a CONNECT packet must have at least 13B of storage
	 */
	if (memcmp("\x00\x04MQTT", read_head, 6)) {
		DPRINTF("CONNECT protocol name header " RED("incorrect\n"));
		return false;
	}
	read_head += 6;

	/* Figure 3.3 - Protocol Level byte */
	if (*read_head != PROTOCOL_LEVEL) {
		DPRINTF("CONNECT protocol level header " RED("incorrect\n"));
		// TODO: send CONNACK with code UNACCEPTABLE_PROTOCOL_LEVEL
		return false;
	}

	/* Figure 3.4 - Connect Flag bits */
	if (*++read_head != CONNECT_FLAGS) {
		DPRINTF("CONNECT flags " RED("incorrect") ", expected: %d got: %d\n", CONNECT_FLAGS,
			*read_head);
		return false;
	}

	/* Figure 3.5 Keep Alive bytes */
	usr->keep_alive = read_uint16(++read_head);
	read_head += 2;

	// TODO: setup a keep alive timer somehow

	uint16_t identifier_len = read_uint16(read_head);
	read_head += 2;

	// 12 bytes read so far - only 1 "safe" byte remains
	if (hdr->remaining_length - 12 != identifier_len) {
		DPRINTF("client id has unexpected length; expected: %d, got: %d\n",
			hdr->remaining_length - 12, identifier_len);
		return false;
	}

	// now they're all safe :)

	/* [MQTT-3.1.3-5] */
	if (identifier_len > CLIENT_ID_MAXLEN) {
		DPRINTF("CONNECT: supplied client id " RED("too long\n"));
		// TODO: send CONNACK with code IDENTIFIER_REJECTED
		return false;
	}

	memcpy(usr->client_id, read_head, identifier_len);
	usr->client_id[identifier_len] = '\0';

	DPRINTF("CONNECT packet parsed " GREEN("successfully") " client id is " MAGENTA("%s\n"),
		usr->client_id);

	// TODO: send CONNACK with code CONNECTION_ACCEPTED
	return true;
}

static bool publish_handler(const fixed_header *hdr, user_data *usr, const char *packet){return 0;}
static bool subscribe_handler(const fixed_header *hdr, user_data *usr, const char *packet){return 0;}
static bool unsubscribe_handler(const fixed_header *hdr, user_data *usr, const char *packet){return 0;}
static bool pingreq_handler(const fixed_header *hdr, user_data *usr, const char *packet){return 0;}
static bool disconnect_handler(const fixed_header *hdr, user_data *usr, const char *packet){return 0;}

static packet_handler verify_fixed_header(const fixed_header *hdr, const user_data *usr) {
	if (hdr->remaining_length > MAX_MESSAGE_LEN) {
		dwarnx("Message too large (max: %d, message is: %d)", MAX_MESSAGE_LEN,
		       hdr->remaining_length);
		return NULL;
	}

	switch (hdr->packet_type) {
	case CONNECT:
		/* 10B variable header - Figure 3.6 - Variable header
		 * + client id which has 2B length prefix and contains at least one character [MQTT-3.1.3-5]
		 */
		if (hdr->flags == 0 && hdr->remaining_length >= 13 && !usr->CONNECT_recieved)
			return connect_handler;
		break;
	case PUBLISH:
		/* DUP (bit 3) is always zero in this implementation [MQTT-3.3.1-2]
		 * QoS (bits 2-1) is always zero in this implementation
		 * RETAIN (bit 0) can be compliantly ignored [MQTT-3.3.1-7]
		 *
		 * A PUBLISH packet has to contain at least 2B in the variable header for the length
		 * of the topic string which is at least 1B [MQTT-4.7.3-1]. No payload has to be
		 * present.
		 */
		if (!(hdr->flags & 0x0e) && hdr->remaining_length >= 3 && usr->CONNECT_recieved)
			return publish_handler;
		break;
	case SUBSCRIBE:
		/* flags: see Figure 3.20 - SUBSCRIBE Packet fixed header
		 *
		 * length: variable header contains a packet identifier (2B) and the payload
		 * contains at least one topic filter [MQTT-3.8.3-3] which is a utf8 string, at
		 * least one character long [MQTT-4.7.3-1] + a QoS byte; in total 6B or more
		 */
		if (hdr->flags == 2 && hdr->remaining_length >= 6 && usr->CONNECT_recieved)
			return subscribe_handler;
		break;
	case UNSUBSCRIBE:
		/* flags: see Figure 3.28 - UNSUBSCRIBE Packet Fixed header
		 *
		 * length: packet identifier (2B), at least one topic filter (3B)
		 */
		if (hdr->flags == 2 && hdr->remaining_length >= 5 && usr->CONNECT_recieved)
			return unsubscribe_handler;
		break;
	case PINGREQ:
		/* see Figure 3.33 - PINGREQ Packet fixed header */
		if (hdr->flags == 0 && hdr->remaining_length == 0 && usr->CONNECT_recieved)
			return pingreq_handler;
		break;
	case DISCONNECT:
		/* see Figure 3.35 - DISCONNECT Packet fixed header */
		if (hdr->flags == 0 && hdr->remaining_length == 0 && usr->CONNECT_recieved)
			return disconnect_handler;
		break;
	default:
		return NULL;
	}

	return NULL;
}

bool process_packet(int conn, user_data *usr) {
	char initial;
	if (read(conn, &initial, 1) != 1) {
		DPRINTF("client closed connection\n");
		return false;
	}

	fixed_header hdr = {
		.packet_type = (initial & 0xf0) >> 4,
		.flags = initial & 0x0f,
		.remaining_length = decode_remaining_length(conn),
	};

	packet_handler handler;
	if ((handler = verify_fixed_header(&hdr, usr)) == NULL) {
		dwarnx("invalid fixed header");
		return false;
	}

	DPRINTF("packet info: type: %d, flags: %d, length: %u\n", hdr.packet_type, hdr.flags,
		hdr.remaining_length);

	char message_buf[MAX_MESSAGE_LEN];
	ssize_t nread = read(conn, message_buf, hdr.remaining_length);
	if (nread != hdr.remaining_length) {
		dwarnx("client didn't send enough data; expected: %d, got: %zd\n", hdr.remaining_length, nread);
		return false;
	}

	handler(&hdr, usr, message_buf);

	return true;
}

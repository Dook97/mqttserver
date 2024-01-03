#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
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
static ssize_t validate_str(const size_t maxlen, const unsigned char str[static maxlen]) {
	uint16_t len = read_uint16(str);

	for (const unsigned char *head = str + 2; head < str + 2 + len; ++head)
		if (*head < ' ' || *head == 0x7f)
			return -1;

	return len;
}

static ssize_t validate_topic(const size_t maxlen, const unsigned char str[static maxlen]) {
	ssize_t len = validate_str(maxlen, str);
	if (len < 1)
		return -1;

	/* [MQTT-4.7.2-1] */
	if (*(str + 2) == '$')
		return -1;

	for (const unsigned char *head = str + 2; head < str + 2 + len; ++head) {
		switch (*head) {
		case '/':
		case '#':
		case '+':
			return -1;
		default:
			break;
		}
	}

	return len;
}

static ssize_t validate_clientid(const size_t maxlen, const unsigned char str[static maxlen]) {
	ssize_t len = validate_str(maxlen, str);
	if (len < 1)
		return -1;

	/* [MQTT-3.1.3-5] */
	for (const unsigned char *head = str + 2; head < str + 2 + len; ++head)
		if (!isalnum(*head))
			return -1;

	return len;
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

static int send_connack(const int conn, const char code) {
	/* see Figure 3.8 - CONNACK Packet fixed header
	 *
	 * 1. the fixed header (2B)
	 * 	1. packet type = 0b0010
	 * 	2. flags = 0b0000
	 * 	3. remaining length (1B) = 0x02
	 *
	 * see Figure 3.9 - CONNACK Packet variable header
	 *
	 * 2. variable header (2B)
	 * 	1. Connect Acknowledge Flags (1B)
	 * 		- [0] = Session Present; always 0 in this implementation
	 * 		- rest = RESERVED 0s
	 * 	2. Connect return code (1B)
	 *
	 * 3. payload
	 * 	- NONE
	 */
	char buf[4] = {'\x20', '\x02', '\x00', code};
	return write(conn, buf, 4) == 4;
}

static bool connect_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	DPRINTF("User sent a " MAGENTA("CONNECT") " packet\n");

	assert(!usr->CONNECT_recieved);
	usr->CONNECT_recieved = true;

	int connack_ret = CONNECTION_ACCEPTED;
	unsigned char *read_head = (unsigned char *)packet;

	/* Figure 3.2 - Protocol Name bytes
	 * this is safe - a CONNECT packet must have at least 13B of storage
	 */
	if (memcmp("\x00\x04MQTT", read_head, 6)) {
		dwarnx(MAGENTA("CONNECT") " protocol name header " RED("incorrect"));
		connack_ret = -1;
		goto finish;
	}
	read_head += 6;

	/* Figure 3.3 - Protocol Level byte */
	if (*read_head != PROTOCOL_LEVEL) {
		dwarnx(MAGENTA("CONNECT") " protocol level header " RED("incorrect"));
		connack_ret = UNACCEPTABLE_PROTOCOL_LEVEL;
		goto finish;
	}

	/* Figure 3.4 - Connect Flag bits */
	if (*++read_head != CONNECT_FLAGS) {
		dwarnx(MAGENTA("CONNECT") " flags " RED("incorrect") ", expected: %d got: %d",
		       CONNECT_FLAGS, *read_head);
		connack_ret = -1;
		goto finish;
	}

	/* Figure 3.5 Keep Alive bytes */
	usr->keep_alive = read_uint16(++read_head);
	read_head += 2;


	// 10B read so far + 2B for the utf8 string header
	ssize_t identifier_len = validate_clientid(hdr->remaining_length - 12, read_head);

	if (identifier_len != hdr->remaining_length - 12) {
		dwarnx("invalid client id %zd", identifier_len);
		connack_ret = IDENTIFIER_REJECTED;
		goto finish;
	}

	/* [MQTT-3.1.3-5] */
	if (identifier_len > CLIENT_ID_MAXLEN) {
		dwarnx(MAGENTA("CONNECT") " supplied client id " RED("too long"));
		connack_ret = IDENTIFIER_REJECTED;
		goto finish;
	}

	/* skip the 2B storing utf8 string length */
	read_head += 2;

	/* disconnect any existing client with the same id [MQTT-3.1.4-2] */
	if (remove_usr_by_id((char *)read_head))
		DPRINTF("a user with matching id found - will be disconnected\n");

	/* store the userid string into the new client */
	memcpy(usr->client_id, read_head, identifier_len);
	usr->client_id[identifier_len] = '\0';

	DPRINTF(MAGENTA("CONNECT") " packet parsed " GREEN("SUCCESSFULLY") " client id is " MAGENTA(
			"%s\n"), usr->client_id);

finish:
	if (connack_ret == -1) {
		dwarnx(MAGENTA("CONNECT") " packet parsing " RED("FAILED"));
		return false;
	}
	int retval = send_connack(conn, connack_ret) && connack_ret == CONNECTION_ACCEPTED;
	return retval;
}

static bool publish_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	return 0;
}

static bool subscribe_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	return 0;
}

static bool unsubscribe_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	return 0;
}

static bool pingreq_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	DPRINTF("User " MAGENTA("%s") " sent a " MAGENTA("PING") " packet; PONG!\n",
		usr->client_id);

	const char response[2] = {'\xd0', '\x00'};
	return write(conn, response, 2) == 2;

	(void)hdr;
	(void)usr;
	(void)packet;
}

static bool disconnect_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	DPRINTF("User " MAGENTA("%s") " sent a " MAGENTA("DISCONNECT") " packet\n",
		usr->client_id);

	return remove_usr_by_ptr(usr);

	(void)hdr;
	(void)conn;
	(void)packet;
}

static packet_handler verify_fixed_header(const fixed_header *hdr, const user_data *usr) {
	if (hdr->remaining_length > MAX_MESSAGE_LEN) {
		dwarnx("Message too large (max: %d, message is: %d)", MAX_MESSAGE_LEN,
		       hdr->remaining_length);
		return NULL;
	}

	switch (hdr->packet_type) {
	case CONNECT:
		/* 10B variable header - Figure 3.6 - Variable header
		 * + client id which has 2B length prefix and contains at least one character
		 * [MQTT-3.1.3-5]
		 */
		if (hdr->flags == CONNECT_DEF_FLAGS && hdr->remaining_length >= 13
		    && !usr->CONNECT_recieved)
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
		if (hdr->flags == SUBSCRIBE_DEF_FLAGS && hdr->remaining_length >= 6
		    && usr->CONNECT_recieved)
			return subscribe_handler;
		break;
	case UNSUBSCRIBE:
		/* flags: see Figure 3.28 - UNSUBSCRIBE Packet Fixed header
		 *
		 * length: packet identifier (2B), at least one topic filter (3B)
		 */
		if (hdr->flags == UNSUBSCRIBE_DEF_FLAGS && hdr->remaining_length >= 5
		    && usr->CONNECT_recieved)
			return unsubscribe_handler;
		break;
	case PINGREQ:
		/* see Figure 3.33 - PINGREQ Packet fixed header */
		if (hdr->flags == PINGREQ_DEF_FLAGS && hdr->remaining_length == 0
		    && usr->CONNECT_recieved)
			return pingreq_handler;
		break;
	case DISCONNECT:
		/* see Figure 3.35 - DISCONNECT Packet fixed header */
		if (hdr->flags == DISCONNECT_DEF_FLAGS && hdr->remaining_length == 0
		    && usr->CONNECT_recieved)
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
		dwarnx("client didn't send enough data; expected: %u, got: %zd\n", hdr.remaining_length, nread);
		return false;
	}

	if (!handler(&hdr, usr, message_buf, conn)) {
		dwarnx(RED("CLOSING") " connection %d due to a malformed packet", conn);
		remove_usr_by_ptr(usr);
	}

	time(&usr->keepalive_timestamp);

	return true;
}

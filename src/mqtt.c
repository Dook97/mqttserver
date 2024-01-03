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
	if (len > maxlen)
		return -1;

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

/* Encode a 4B unsigned integer to the MQTT remaining length format
 */
static int encode_remaining_length(uint32_t toencode, char dest[static 4]) {
	if (toencode & 0x80)
		return -1;

	for (int i = 0; i < 4; ++i) {
		dest[i] = toencode & 0x7f;
		toencode >>= 7;
		if (toencode)
			dest[i] |= 1 << 7; // continuation bit
		else
			return i + 1;
	}

	return 4;
}

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
		dwarnx("invalid client id of length %zd (expected %u)", identifier_len,
		       hdr->remaining_length - 12);
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
	if (remove_usr_by_id((char *)read_head, true))
		DPRINTF("a user with matching id found - will be disconnected\n");

	/* store the userid string into the new client */
	memcpy(usr->client_id, read_head, identifier_len);
	usr->client_id[identifier_len] = '\0';

	DPRINTF(MAGENTA("CONNECT") " packet parsed " GREEN("SUCCESSFULLY") " client id is "
			MAGENTA("'%s'\n"), usr->client_id);

finish:
	if (connack_ret == -1) {
		dwarnx(MAGENTA("CONNECT") " packet parsing " RED("FAILED"));
		return false;
	}
	return send_connack(conn, connack_ret) && connack_ret == CONNECTION_ACCEPTED;
}

static bool publish_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	return false;
}

static bool send_suback(size_t nsubs, uint16_t packet_identifier, int conn) {
	char remaining_length[4];
	int encode_ret = encode_remaining_length(2 + nsubs, remaining_length);
	if (encode_ret == -1)
		derrx(SERVER_ERR,
		      "failed to encode remaining length of server packet - this should never happen");

	/* +1B initial part of the fixed header (=MQTT packet type and flags)
	 * +encode_ret length of the "remaining length" field
	 * +2B packet identifier
	 * +nsubs one byte for each subscription status code
	 */
	const size_t packet_size = 3 + encode_ret + nsubs;
	char *packet = malloc(packet_size);
	if (packet == NULL)
		derr(NO_MEMORY, "couldn't allocate %zuB for SUBACK packet buffer", packet_size);

	/* packet type and flags; Figure 3.24 - SUBACK Packet fixed header */
	unsigned char *write_head = (unsigned char *)packet;
	*write_head = 0x90;

	/* remaining_length */
	memcpy(++write_head, remaining_length, encode_ret);
	write_head += encode_ret;

	/* packet identifier */
	*write_head = packet_identifier >> 8;
	*++write_head = packet_identifier & 0xff;

	/* suback return codes */
	memset(++write_head, SUCCESS_QOS_0, nsubs);

	ssize_t nwritten = write(conn, packet, packet_size);
	free(packet);
	return nwritten == (ssize_t)packet_size;
}

static ssize_t read_topic(const unsigned char *read_head, str_vec *topics[static 1], size_t maxlen) {
	ssize_t string_len = validate_topic(maxlen, read_head);
	/* +2 for utf8 string length bytes +1 for QoS byte */
	const size_t topic_len = string_len + 3;
	if (string_len == -1 || topic_len > maxlen)
		return -1;

	char *new_topic = malloc((string_len + 1) * sizeof(char));
	if (new_topic == NULL)
		derr(NO_MEMORY, "malloc: couldn't allocate %zuB", (string_len + 1) * sizeof(char));

	new_topic[string_len] = '\0';
	memcpy(new_topic, read_head + 2, string_len + 1);

	bool vec_err = false;
	vec_append(topics, new_topic, &vec_err);
	if (vec_err)
		derr(NO_MEMORY, "vec_append: couldn't allocate %luB", sizeof(char *));

	unsigned char QoS = *(read_head + string_len);
	switch (QoS) {
	case 0:
	case 1:
	case 2:
		break;
	default:
		return -1;
	}

	return topic_len;
}

static bool subscribe_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	DPRINTF("User " MAGENTA("%s") " sent a " MAGENTA("SUBSCRIBE") " packet\n", usr->client_id);

	unsigned char *read_head = (unsigned char *)packet;

	uint16_t packet_identifier = read_uint16(read_head);
	read_head += 2;
	if (packet_identifier == 0) {
		dwarnx("zero packet identifier in SUBSCRIBE packet");
		return false;
	}

	str_vec *topics;
	vec_init(&topics, 8);
	if (topics == NULL)
		derr(NO_MEMORY, "malloc");

	while ((char *)read_head < packet + hdr->remaining_length) {
		ssize_t nread = read_topic(read_head, &topics,
					   (packet + hdr->remaining_length) - (char *)read_head);

		/* the MQTT spec actually requires us to gracefully reject the subscription if it is
		 * a valid topic string containing a wildcard character, but we're too lazy to
		 * check, so just kill em ;p
		 */
		if (nread == -1) {
			dwarnx("bad topic string in SUBSCRIBE packet");
			for (size_t i = 0; i < topics->nmemb; ++i)
				free(topics->arr[i]);
			return false;
		}
		read_head += nread;
	}
	assert((char *)read_head == packet + hdr->remaining_length);

	for (size_t i = 0; i < topics->nmemb; ++i) {
		bool present = false;
		for (size_t j = 0; j < usr->subscriptions->nmemb; ++j) {
			if (!strcmp(topics->arr[i], usr->subscriptions->arr[j])) {
				present = true;
				break;
			}
		}
		if (present)
			continue;
		bool vec_err = false;
		vec_append(&usr->subscriptions, topics->arr[i], &vec_err);
		if (vec_err)
			derr(NO_MEMORY, "realloc");
	}

	size_t nsubs = topics->nmemb;
	free(topics);

	DPRINTF("SUBSCRIBE packet parsed " GREEN("SUCCESSFULLY\n"));
	DPRINTF("subscriptions for user " MAGENTA("'%s':\n"), usr->client_id);
	for (size_t i = 0; i < usr->subscriptions->nmemb; ++i)
		DPRINTF("\ttopic: " MAGENTA("'%s'\n"), usr->subscriptions->arr[i]);

	return send_suback(nsubs, packet_identifier, conn);
}

static bool unsubscribe_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	return false;
}

static bool pingreq_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	DPRINTF("User " MAGENTA("%s") " sent a " MAGENTA("PING") " packet; PONG!\n", usr->client_id);

	/* send PINGRESP */
	const char response[2] = {'\xd0', '\x00'};
	return write(conn, response, 2) == 2;

	(void)hdr;
	(void)usr;
	(void)packet;
}

static bool disconnect_handler(const fixed_header *hdr, user_data *usr, const char *packet, int conn) {
	DPRINTF("User " MAGENTA("%s") " sent a " MAGENTA("DISCONNECT") " packet\n", usr->client_id);

	return remove_usr_by_ptr(usr, true);

	(void)hdr;
	(void)conn;
	(void)packet;
}

static packet_handler verify_fixed_header(const fixed_header *hdr, const user_data *usr) {
	if (hdr->remaining_length == -1) {
		dwarnx("invalid remaining length field");
		return NULL;
	}

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
	ssize_t nread = read(conn, &initial, 1);
	if (nread == 0) {
		DPRINTF("client closed connection\n");
		remove_usr_by_ptr(usr, true);
		return true;
	} else if (nread == -1) {
		dwarnx("connection error");
		return false;
	}
	assert(nread == 1);

	fixed_header hdr = {
		.packet_type = (initial & 0xf0) >> 4,
		.flags = initial & 0x0f,
		.remaining_length = decode_remaining_length(conn),
	};

	DPRINTF("packet info: type: %d, flags: %d, length: %u\n", hdr.packet_type, hdr.flags,
		hdr.remaining_length);

	packet_handler handler;
	if ((handler = verify_fixed_header(&hdr, usr)) == NULL) {
		dwarnx("invalid fixed header");
		return false;
	}

	char message_buf[MAX_MESSAGE_LEN];
	nread = read(conn, message_buf, hdr.remaining_length);
	if (nread != hdr.remaining_length) {
		dwarnx("client didn't send enough data; expected: %u, got: %zd", hdr.remaining_length, nread);
		return false;
	}

	if (!handler(&hdr, usr, message_buf, conn)) {
		dwarnx(RED("CLOSING") " connection %d due to a malformed packet", conn);
		return false;
	}

	time(&usr->keepalive_timestamp);

	return true;
}

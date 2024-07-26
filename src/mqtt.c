#include <assert.h>
#include <ctype.h>
#include <unistd.h>

#include "mqtt.h"
#include "magic.h"

/*!
 * Read a 2B big-endian unsigned integer from buffer buf.
 *
 * @param buf Read buffer.
 * @return The read integer.
 */
static uint16_t read_BE_16b(const uint8_t buf[static 2]) {
	return ((uint16_t)buf[0] << 8) + (uint16_t)buf[1];
}

/*!
 * Verify whether a string is valid w.r.t. the MQTT specification
 *
 * Conditions:
 *	- strlen(buf) <= UINT16_MAX
 *	- mustn't include U+0000
 *	- shouldn't include U+0001..U+001F
 *
 * This function doesn't check all the conditions required by the MQTT spec.
 *
 * @param buflen Size of the buffer.
 * @param buf The buffer from which to read the string.
 * @return The size of the string, not including the initial 2B which encode its stated length.
 * @retval -1 if invalid
 */
static ssize_t validate_str(const size_t bufsize, const uint8_t *buf) {
	uint16_t len = read_BE_16b(buf);
	if (len > bufsize)
		return -1;

	for (const uint8_t *head = buf + 2; head < buf + 2 + len; ++head)
		if (*head < ' ')
			return -1;

	return len;
}

/*!
 * Verify that given utf8 string is a valid topic string.
 *
 * @param buflen Length of the buffer.
 * @param buf Buffer holding the topic string.
 * @retval length of the topic string, not counting the 2B of metadata at the beggining
 */
static ssize_t validate_topic(const size_t buflen, const uint8_t *buf) {
	ssize_t len = validate_str(buflen, buf);
	if (len < 1)
		return -1;

	buf += 2;
	for (const uint8_t *head = buf; head < buf + len; ++head) {
		switch (*head) {
		case '#':
		case '+':
			return -1;
		default:
			break;
		}
	}

	return len;
}

/*!
 * Verify that given utf8 string is a valid client id.
 *
 * @param buflen Length of the buffer.
 * @param buf Buffer holding the client id.
 * @retval length of the client id, not counting the 2B of metadata at the beggining
 */
static ssize_t validate_clientid(const size_t buflen, const uint8_t *buf) {
	ssize_t len = validate_str(buflen, buf);
	if (len < 1)
		return -1;

	/* [MQTT-3.1.3-5] */
	for (const uint8_t *head = buf + 2; head < buf + 2 + len; ++head)
		if (!isgraph(*head)) /* be lenient here, because why not - the spec allows it */
			return -1;

	return len;
}

/*!
 * Read and decode between 1 and 4 bytes of data present in the 'Remaining Length' field in the
 * fixed header of a MQTT packet.
 *
 * @param src Memory buffer containing at least one byte of encoded length information
 * @param bufsize Size of the src buffer (ie. how many bytes may be accessed without wandering into
 * potentially unallocated memory)
 * @param len Output parameter storing the numer of bytes actually occupied by the packet length
 * information.
 * @retval The decoded number.
 * @returns -1 on invalid input
 * @returns -2 if more bytes in the buffer are required
 */
static int32_t decode_remaining_length(uint8_t *src, size_t bufsize, size_t *len) {
	bufsize = MIN(4, bufsize);

	int32_t output = 0;
	size_t i = 0;
	for (; i < bufsize; ++i) {
		output |= (src[i] & 0x7f) << (i * 7);
		if (!(src[i] & 0x80)) {
			++i;
			break;
		}
	}
	if (src[i - 1] & 0x80)
		return i == 4 ? -1 : -2;

	*len = i;
	return output;
}

/*!
 * Encode a 4B unsigned integer to the MQTT remaining length format
 *
 * @param toencode The 4B unsigned integer to encode
 * @param dest A buffer of at least 4B to store the encoded number
 * @retval length of the encoded number.
 * @returns -1 if toencode is a value which cannot be represented
 */
static int encode_remaining_length(uint32_t toencode, uint8_t dest[static 4]) {
	assert(toencode <= MQTT_MSG_MAX_LEN);

	for (int i = 0; i < 4; ++i) {
		dest[i] = toencode & 0x7f;
		toencode >>= 7;
		if (toencode)
			dest[i] |= 0x80; /* continuation bit */
		else
			return i + 1;
	}

	return 4;
}

static packet_action connect_handler(const fixed_header *hdr, user_data *usr, const uint8_t *packet, int conn) {
	DPRINTF("User (conn %d) sent a " MAGENTA("CONNECT") " packet\n", conn);

	assert(!usr->connect_recieved);
	assert(hdr->remaining_length >= 13);

	usr->connect_recieved = true;

	int connack_ret = CONNECTION_ACCEPTED;
	const uint8_t *read_head = packet;

	/* Figure 3.2 - Protocol Name bytes */
	if (memcmp(MQTT_PROTO_NAME, read_head, sizeof(MQTT_PROTO_NAME))) {
		dwarnx(MAGENTA("CONNECT") " protocol name header " RED("incorrect"));
		connack_ret = -1;
		goto finish;
	}
	read_head += sizeof(MQTT_PROTO_NAME);

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
	usr->keep_alive = read_BE_16b(++read_head);
	read_head += 2;

	/* 10B read so far + 2B for the utf8 string header */
	ssize_t identifier_len = validate_clientid(hdr->remaining_length - 12, read_head);

	/* skip the 2B storing utf8 string length */
	read_head += 2;

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

	/* disconnect any existing client with the same id [MQTT-3.1.4-2] */
	if (remove_usr_by_id((char *)read_head, true, identifier_len))
		DPRINTF("a user with matching id found - will be disconnected\n");

	/* store the userid string into the new client */
	memcpy(usr->client_id, read_head, identifier_len);
	usr->client_id[identifier_len] = '\0';

	DPRINTF(MAGENTA("CONNECT") " packet parsed " GREEN("SUCCESSFULLY") " client id is " MAGENTA("'%s'\n"),
		usr->client_id);

finish:
	if (connack_ret == -1)
		return CLOSE_ERR;

	/* see Figure 3.8 - CONNACK Packet fixed header
	 * see Figure 3.9 - CONNACK Packet variable header */
	uint8_t buf[] = {'\x20', '\x02', '\x00', connack_ret};
	if (write(conn, buf, sizeof(buf)) != sizeof(buf)) {
		dwarnx("Unable to send CONNACK");
		return CLOSE_ERR;
	}

	if (connack_ret != CONNECTION_ACCEPTED)
		return CLOSE_ERR;

	return KEEP;
}

/* check whether a user is subscribed to given topic */
static bool is_subscribed(user_data *u, size_t topic_len, const uint8_t *topic) {
	str_vec *subs = u->subscriptions;
	for (size_t i = 0; i < subs->nmemb; ++i) {
		if (strlen(subs->arr[i]) != topic_len)
			continue;
		if (!memcmp(topic, subs->arr[i], topic_len))
			return true;
	}
	return false;
}

static packet_action publish_handler(const fixed_header *hdr, user_data *usr, const uint8_t *packet, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("PUBLISH") " packet\n", usr->client_id);

	ssize_t len = validate_topic(hdr->remaining_length, packet);
	if (len == -1) {
		dwarnx("invalid topic string");
		return CLOSE_ERR;
	}

	uint8_t fixed_header[5] = {'\x30'};
	int encode_ret = encode_remaining_length(hdr->remaining_length, fixed_header + 1);
	assert(encode_ret != -1);

	const int hdr_len = encode_ret + 1;

	for (size_t i = 0; i < users.data->nmemb; ++i) {
		user_data *u = &users.data->arr[i];
		int uconn = users.conns->arr[i].fd;
		if (is_subscribed(u, len, packet + 2)) {
			DPRINTF("sending a " MAGENTA("PUBLISH") " packet to user " MAGENTA("'%s'\n"), u->client_id);

			bool fail;
			fail  = write(uconn, fixed_header, hdr_len) != hdr_len;
			fail |= write(uconn, packet, hdr->remaining_length) != hdr->remaining_length;

			if (fail) {
				dwarnx(RED("FAILED") " to properly send " MAGENTA("PUBLISH")
				       "packet to subscriber (connection %d)", uconn);
			}
		}
	}


	return KEEP;

	(void)usr;
	(void)conn;
}

static bool send_suback(size_t nsubs, uint16_t packet_identifier, int conn) {
	uint8_t remaining_length[4];
	int encode_ret = encode_remaining_length(2 + nsubs, remaining_length); /* +2 for packet identifier */
	assert(encode_ret != -1);

	/* +1B initial part of the fixed header (=MQTT packet type and flags)
	 * +encode_ret length of the "remaining length" field
	 * +2B packet identifier
	 * +nsubs one byte for each subscription status code
	 */
	const size_t packet_size = 3 + encode_ret + nsubs;
	uint8_t *packet = memalloc(packet_size);

	/* packet type and flags; Figure 3.24 - SUBACK Packet fixed header */
	uint8_t *write_head = packet;
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

/*!
 * Given a buffer of length buflen read the topic string which begins at the buffer address and
 * return its length, including the 2 length bytes and a QoS byte. If successful store a copy of it
 * in the topics vector.
 *
 * @param buf Read buffer.
 * @param buflen Length of the buffer.
 * @param topics A vector to which to append the topic.
 * @param QoS Whether a QoS byte follows the string data.
 * @retval Length of the topic string, including the 2B of length and possibly a QoS byte.
 */
static ssize_t read_topic(size_t buflen, const uint8_t *buf, str_vec *topics[static 1], bool QoS) {
	ssize_t string_len = validate_topic(buflen, buf);
	/* +2 for utf8 string length bytes +1 for QoS byte */
	const size_t topic_len = string_len + 2 + (QoS ? 1 : 0);
	if (string_len == -1 || topic_len > buflen)
		return -1;

	if (QoS) {
		uint8_t QoS = *(buf + string_len + 2);
		switch (QoS) {
		case 0:
		case 1:
		case 2:
			break;
		default:
			dwarnx("invalid QoS byte in topic string");
			return -1;
		}
	}

	char *new_topic = memalloc((string_len + 1) * sizeof(char));

	new_topic[string_len] = '\0';
	memcpy(new_topic, buf + 2, string_len);
	vec_append(topics, new_topic, NULL);

	return topic_len;
}

/*!
 * Given a buffer of len buflen and assuming this buffer contains only topic strings, extract these
 * and return a vector filled with them
 *
 * @param buflen Length of the buffer.
 * @param buf The buffer.
 * @param QoS Whether a QoS byte follows the string data.
 * @retval vector of topics as null terminated strings
 * @returns NULL on failure
 */
static str_vec *extract_topics(size_t buflen, const uint8_t *buf, bool QoS) {
	str_vec *topics;
	vec_init(&topics, 8);

	const uint8_t *read_head = buf;

	while (read_head < buf + buflen) {
		ssize_t nread = read_topic(buflen - (read_head - buf), read_head, &topics, QoS);
		/* the MQTT spec actually requires us to gracefully reject the subscription if it is
		 * a valid topic string containing a wildcard character, but we're too lazy to
		 * check, so just kill em ;p */
		if (nread == -1) {
			dwarnx("bad topic string");
			goto fail;
		}
		read_head += nread;
	}
	/* we should've read the entire buffer and nothing more at this point */
	if (read_head != buf + buflen) {
		dwarnx("malformed data when reading topics");
		goto fail;
	}

	return topics;

fail:
	for (size_t i = 0; i < topics->nmemb; ++i)
		free(topics->arr[i]);
	free(topics);
	return NULL;
}

static packet_action subscribe_handler(const fixed_header *hdr, user_data *usr, const uint8_t *packet, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("SUBSCRIBE") " packet\n", usr->client_id);

	const uint8_t *read_head = packet;

	uint16_t packet_identifier = read_BE_16b(read_head);
	read_head += 2;

	/* must be non-zero [MQTT-2.3.1-1] */
	if (packet_identifier == 0) {
		dwarnx("zero packet identifier in SUBSCRIBE packet");
		return CLOSE_ERR;
	}

	str_vec *topics = extract_topics(hdr->remaining_length - 2, read_head, true);
	if (topics == NULL) {
		dwarnx("couldn't read topics");
		return CLOSE_ERR;
	}

	/* at least one topic must be present [MQTT-3.8.3-3] */
	if (topics->nmemb == 0) {
		dwarnx(MAGENTA("SUBSCRIBE") " packet contains no topics");
		free(topics);
		return CLOSE_ERR;
	}

	/* copy the subscription topics over to the user's list */
	for (size_t i = 0; i < topics->nmemb; ++i) {
		for (size_t j = 0; j < usr->subscriptions->nmemb; ++j) {
			if (!strcmp(topics->arr[i], usr->subscriptions->arr[j])) {
				dwarnx("User " MAGENTA("'%s'") " trying to subscribe to an already subscribed-to topic (%s)",
				       usr->client_id, topics->arr[i]);
				free(topics->arr[i]);
				goto next_topic;
			}
		}
		vec_append(&usr->subscriptions, topics->arr[i], NULL);
next_topic:;
	}

	size_t nsubs = topics->nmemb;
	free(topics);

	DPRINTF(MAGENTA("SUBSCRIBE") " packet parsed " GREEN("SUCCESSFULLY\n"));
	DPRINTF("subscriptions for user " MAGENTA("'%s':\n"), usr->client_id);
	for (size_t i = 0; i < usr->subscriptions->nmemb; ++i)
		DPRINTF("    topic: " MAGENTA("'%s'\n"), usr->subscriptions->arr[i]);

	return send_suback(nsubs, packet_identifier, conn) ? KEEP : CLOSE_ERR;
}

static packet_action unsubscribe_handler(const fixed_header *hdr, user_data *usr, const uint8_t *packet, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("UNSUBSCRIBE") " packet\n", usr->client_id);

	uint16_t packet_identifier = read_BE_16b(packet);

	str_vec *unsubs = extract_topics(hdr->remaining_length - 2, packet + 2, false);
	if (unsubs == NULL) {
		dwarnx("couldn't read topics");
		return CLOSE_ERR;
	}

	/* must contain at least one topic [MQTT-3.10.3-2] */
	if (unsubs->nmemb == 0) {
		dwarnx(MAGENTA("UNSUBSCRIBE") " packet contains no topics");
		free(unsubs);
		return CLOSE_ERR;
	}

	/* remove matching subscriptions */
	str_vec *subs = usr->subscriptions;
	for (ssize_t i = usr->subscriptions->nmemb - 1; i >= 0; --i) {
		for (size_t j = 0; j < unsubs->nmemb; ++j) {
			if (!strcmp(subs->arr[i], unsubs->arr[j])) {
				DPRINTF("removing subscription " MAGENTA("'%s'") " for user " MAGENTA("'%s'\n"),
					subs->arr[i], usr->client_id);
				free(subs->arr[i]);
				vec_remove_at(subs, i);
				break;
			}
		}
	}

	for (size_t i = 0; i < unsubs->nmemb; ++i)
		free(unsubs->arr[i]);
	free(unsubs);

	DPRINTF("UNSUBSCRIBE packet parsed " GREEN("SUCCESSFULLY\n"));
	DPRINTF("subscriptions for user " MAGENTA("'%s':\n"), usr->client_id);
	for (size_t i = 0; i < usr->subscriptions->nmemb; ++i)
		DPRINTF("    topic: " MAGENTA("'%s'\n"), usr->subscriptions->arr[i]);

	/* Figure 3.31 - UNSUBACK Packet fixed header
	 * Figure 3.32 - UNSUBACK Packet variable header
	 */
	const uint8_t response[] = {'\xb0', '\x02', packet_identifier >> 8, packet_identifier & 0xff};
	write(conn, response, sizeof(response));

	return KEEP;
}

static packet_action pingreq_handler(const fixed_header *hdr, user_data *usr, const uint8_t *packet, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("PING") " packet; PONG!\n", usr->client_id);

	/* send PINGRESP */
	const uint8_t response[] = {'\xd0', '\x00'};
	write(conn, response, sizeof(response));

	return KEEP;

	(void)hdr;
	(void)usr;
	(void)packet;
}

static packet_action disconnect_handler(const fixed_header *hdr, user_data *usr, const uint8_t *packet, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("DISCONNECT") " packet\n", usr->client_id);

	return CLOSE_OK;

	(void)hdr;
	(void)usr;
	(void)conn;
	(void)packet;
}

/*!
 * Verifies correctness of the fixed header.
 *
 * @retval handler function applicable to given packet type
 * @returns NULL if the fixed header has an invalid format
 */
static packet_handler verify_fixed_header(const fixed_header *hdr, const user_data *usr) {
	if (hdr->remaining_length < 0) {
		dwarnx("invalid remaining length field");
		return NULL;
	}

	if (hdr->remaining_length > MESSAGE_MAX_LEN) {
		dwarnx("Message too large (max: %d, message is: %d)", MESSAGE_MAX_LEN,
		       hdr->remaining_length);
		return NULL;
	}

	switch (hdr->packet_type) {
	case CONNECT:
		/* 10B variable header - Figure 3.6 - Variable header
		 * + client id which has 2B length prefix and contains at least one character
		 * [MQTT-3.1.3-5]
		 */
		if (hdr->flags == CONNECT_DEF_FLAGS && hdr->remaining_length >= 13 && !usr->connect_recieved)
			return connect_handler;
		if (usr->connect_recieved)
			dwarnx("User " MAGENTA("%s") " sent a second " MAGENTA("CONNECT") " packet",
			       usr->client_id);
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
		if (!(hdr->flags & 0x0e) && hdr->remaining_length >= 3 && usr->connect_recieved)
			return publish_handler;

		dwarnx(MAGENTA("PUBLISH") " requested QoS: %d", (hdr->flags >> 1) & 0x03);
		break;
	case SUBSCRIBE:
		/* flags: see Figure 3.20 - SUBSCRIBE Packet fixed header
		 *
		 * length: variable header contains a packet identifier (2B) and the payload
		 * contains at least one topic filter [MQTT-3.8.3-3] which is a utf8 string, at
		 * least one character long [MQTT-4.7.3-1] + a QoS byte; in total 6B or more
		 */
		if (hdr->flags == SUBSCRIBE_DEF_FLAGS && hdr->remaining_length >= 6 && usr->connect_recieved)
			return subscribe_handler;
		break;
	case UNSUBSCRIBE:
		/* flags: see Figure 3.28 - UNSUBSCRIBE Packet Fixed header
		 *
		 * length: packet identifier (2B), at least one topic filter (3B)
		 */
		if (hdr->flags == UNSUBSCRIBE_DEF_FLAGS && hdr->remaining_length >= 5 && usr->connect_recieved)
			return unsubscribe_handler;
		break;
	case PINGREQ:
		/* see Figure 3.33 - PINGREQ Packet fixed header */
		if (hdr->flags == PINGREQ_DEF_FLAGS && hdr->remaining_length == 0 && usr->connect_recieved)
			return pingreq_handler;
		break;
	case DISCONNECT:
		/* see Figure 3.35 - DISCONNECT Packet fixed header */
		if (hdr->flags == DISCONNECT_DEF_FLAGS && hdr->remaining_length == 0
		    && usr->connect_recieved)
			return disconnect_handler;
		break;
	}

	return NULL;
}

packet_action process_packet(int conn, user_data *usr) {
	static const size_t MIN_LOAD = 1024;

	/* attempt to avoid unnecessary reallocation of the streambuf */
	size_t to_load = MAX(SB_FREE(usr->sbuf), MIN_LOAD);
	switch (sbuf_load(&usr->sbuf, conn, to_load)) {
	case SBUF_ENOMEM:
		derr(NO_MEMORY, "failed allocating storage for packet buffer");
	case -1:
		dwarnx("connection error");
		return CLOSE_ERR;
		break;
	case 0:
		DPRINTF("client closed connection\n");
		return CLOSE_OK;
		break;
	default:
		break;
	}

	/* we need at least 2B to have something to work with
	 * first is the flags and such, second is the beggining of packet len */
	while (SB_DATASIZE(usr->sbuf) >= 2) {
		size_t header_nbytes;
		int32_t remaining_length = decode_remaining_length(
			SB_DATA(usr->sbuf) + 1, SB_DATASIZE(usr->sbuf) - 1, &header_nbytes);
		++header_nbytes; /* +1 for fixed header */
		const size_t message_size = remaining_length + header_nbytes;

		switch (remaining_length) {
		case -2:
			DPRINTF("not enough data in buffer to determine packet length\n");
			return KEEP;
		case -1:
			dwarnx("invalid remaining length field");
			return CLOSE_ERR;
		default:
			if (message_size > SB_DATASIZE(usr->sbuf)) {
				DPRINTF("the whole packet hasn't arrived yet\n");
				return KEEP;
			}
			break;
		}

		uint8_t initial = *SB_DATA(usr->sbuf);
		fixed_header hdr = {
			.packet_type = (initial & 0xf0) >> 4,
			.flags = initial & 0x0f,
			.remaining_length = remaining_length,
		};

		DPRINTF("packet info: type: %d, flags: %d, length: %u\n", hdr.packet_type,
			hdr.flags, hdr.remaining_length);

		packet_handler handler = verify_fixed_header(&hdr, usr);
		if (handler == NULL) {
			dwarnx("invalid fixed header");
			return CLOSE_ERR;
		}

		uint8_t *packet_data = SB_DATA(usr->sbuf) + header_nbytes;
		switch (handler(&hdr, usr, packet_data, conn)) {
		case CLOSE_ERR:
			dwarnx(RED("CLOSING") " connection %d due to a malformed packet", conn);
			return CLOSE_ERR;
		case CLOSE_OK:
			return CLOSE_OK;
		case KEEP:
			break;
		}
		sbuf_mark_read(usr->sbuf, message_size);
	}

	return KEEP;
}

#include <assert.h>
#include <ctype.h>
#include <unistd.h>

#include "magic.h"
#include "mqtt.h"

#define MIN_LOAD 1024

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
 * @param buf The buffer from which to read the string.
 * @param buflen Size of the buffer.
 * @return The size of the string, not including the initial 2B which encode its stated length.
 * @retval -1 if invalid
 */
static ssize_t validate_str(const uint8_t *buf, const size_t bufsize) {
	uint16_t len = read_BE_16b(buf);
	if (len > bufsize)
		return -1;

	buf += 2;
	for (const uint8_t *head = buf; head < buf + len; ++head)
		if (*head < ' ')
			return -1;

	return len;
}

/*!
 * Verify that given utf8 string is a valid topic string.
 *
 * @param buf Buffer holding the topic string.
 * @param buflen Length of the buffer.
 * @retval length of the topic string, not counting the 2B of metadata at the beggining
 */
static ssize_t validate_topic(const uint8_t *buf, const size_t buflen) {
	ssize_t len = validate_str(buf, buflen);
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
 * @param buf Buffer holding the client id.
 * @param buflen Length of the buffer.
 * @retval length of the client id, not counting the 2B of metadata at the beggining
 */
static ssize_t validate_clientid(const uint8_t *buf, const size_t buflen) {
	ssize_t len = validate_str(buf, buflen);
	if (len < 1)
		return -1;

	/* [MQTT-3.1.3-5] */
	buf += 2;
	for (const uint8_t *head = buf; head < buf + len; ++head)
		if (!isgraph(*head)) /* be lenient here, because why not - the spec allows it */
			return -1;

	return len;
}

enum {
	REMLEN_INVALID = -1,
	REMLEN_INCOMPLETE = -2,
};

/*!
 * Read and decode between 1 and 4 bytes of data present in the 'Remaining Length' field of the
 * fixed header of a MQTT packet.
 *
 * @param src Memory buffer containing at least one byte of encoded length information
 * @param bufsize Size of the src buffer (ie. how many bytes may be accessed without wandering into
 * potentially unallocated memory)
 * @param len Output parameter storing the numer of bytes actually occupied by the packet length
 * information.
 * @retval The decoded number.
 * @returns REMLEN_INVALID on invalid input
 * @returns REMLEN_INCOMPLETE if more bytes in the buffer are required
 */
static int32_t decode_remlen(uint8_t *src, size_t bufsize, size_t *len) {
	int32_t output = 0;

	--src;
	*len = 0;
	bufsize = MIN(4, bufsize);
	do {
		output |= (*++src & 0x7f) << (*len * 7);
		++*len;
	} while ((*src & 0x80) && *len <= bufsize);

	if (*src & 0x80)
		return *len == 4 ? REMLEN_INVALID : REMLEN_INCOMPLETE;

	return output;
}

/*!
 * Encode a 4B unsigned integer to the MQTT remaining length format
 *
 * @param toencode The 4B unsigned integer to encode
 * @param dest A buffer of at least 4B to store the encoded number
 * @retval length of the encoded number.
 */
static int encode_remlen(uint32_t toencode, uint8_t dest[static 4]) {
	assert(toencode <= MQTT_MSG_MAX_LEN);

	for (int i = 0; i < 4; ++i) {
		dest[i] = toencode & 0x7f;
		toencode >>= 7;
		if (toencode != 0)
			dest[i] |= 0x80; /* continuation bit */
		else
			return i + 1;
	}

	return 4;
}

static pkt_action connect_handler(const pkt_info *pinfo, user *usr, const uint8_t *pkt, int conn) {
	DPRINTF("User (conn %d) sent a " MAGENTA("CONNECT") " packet\n", conn);

	assert(!usr->connected);
	assert(pinfo->rem_len >= 13);

	usr->connected = true;

	int connack_ret = CONNECTION_ACCEPTED;
	const uint8_t *read_head = pkt;

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
	usr->ttl = read_BE_16b(++read_head);
	read_head += 2;

	/* 10B read so far + 2B for the utf8 string header */
	ssize_t identifier_len = validate_clientid(read_head, pinfo->rem_len - 12);

	/* skip the 2B storing utf8 string length */
	read_head += 2;

	if (identifier_len != pinfo->rem_len - 12) {
		dwarnx("invalid client id of length %zd (expected %u)", identifier_len, pinfo->rem_len - 12);
		connack_ret = IDENTIFIER_REJECTED;
		goto finish;
	}

	/* [MQTT-3.1.3-5] */
	if (identifier_len > CLIENT_ID_MAXLEN) {
		dwarnx(MAGENTA("CONNECT") " supplied client id " RED("too long"));
		connack_ret = IDENTIFIER_REJECTED;
		goto finish;
	}

finish:;
	/* see Figure 3.8 - CONNACK Packet fixed header
	 * see Figure 3.9 - CONNACK Packet variable header */
	uint8_t buf[] = {'\x20', '\x02', '\x00', connack_ret};
	if (write(conn, buf, sizeof(buf)) != sizeof(buf)) {
		dwarnx("Unable to send CONNACK");
		return CLOSE_ERR;
	}

	if (connack_ret != CONNECTION_ACCEPTED)
		return CLOSE_ERR;

	/* disconnect any existing client with the same id [MQTT-3.1.4-2] */
	user *matching = usr_by_id((char *)read_head, identifier_len);
	if (matching != NULL) {
		usr_free(matching);
		DPRINTF("user with matching id disconnected\n");
	}

	/* store the userid string into the new client */
	memcpy(usr->id, read_head, identifier_len);
	usr->id[identifier_len] = '\0';

	DPRINTF(MAGENTA("CONNECT") " packet parsed " GREEN("SUCCESSFULLY") " client id is " MAGENTA("'%s'\n"),
		usr->id);

	return KEEP;
}

/* check whether a user is subscribed to given topic */
static bool is_subscribed(user *u, const uint8_t *topic, size_t topic_len) {
	str_vec *subs = u->subs;
	for (size_t i = 0; i < subs->nmemb; ++i) {
		/* valid topic strings don't contain '\0's so this is OK */
		if (strmemeq(topic_len, subs->arr[i], (char *)topic))
			return true;
	}
	return false;
}

static pkt_action publish_handler(const pkt_info *pinfo, user *usr, const uint8_t *pkt, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("PUBLISH") " packet\n", usr->id);

	ssize_t len = validate_topic(pkt, pinfo->rem_len);
	if (len == -1) {
		dwarnx("invalid topic string");
		return CLOSE_ERR;
	}

	const int pkt_len = pinfo->hdr_len + pinfo->rem_len;
	for (size_t i = 0; i < USERS->nmemb; ++i) {
		user *u = &USERS->arr[i];
		int uconn = CONNS->arr[i].fd;
		if (uconn == -1) /* beware of invalid users */
			continue;
		if (is_subscribed(u, pkt + 2, len)) {
			DPRINTF("sending a " MAGENTA("PUBLISH") " packet to user " MAGENTA("'%s'\n"), u->id);
			if (write(uconn, SB_DATA(usr->sbuf), pkt_len) != pkt_len) {
				dwarnx(RED("FAILED") " to properly send " MAGENTA("PUBLISH")
				       "packet to subscriber " MAGENTA("%s"), usr->id);
			}
		}
	}

	return KEEP;

	(void)conn;
}

static void send_suback(size_t nsubs, uint16_t pkt_id, int conn) {
	uint8_t remlen_buf[4];
	int encode_ret = encode_remlen(2 + nsubs, remlen_buf); /* +2 for packet identifier */
	assert(encode_ret != -1);

	/* +1B initial part of the fixed header (=MQTT packet type and flags)
	 * +encode_ret length of the "remaining length" field
	 * +2B packet identifier
	 * +nsubs one byte for each subscription status code
	 */
	const size_t packet_size = 3 + encode_ret + nsubs;
	uint8_t *pkt = xmalloc(packet_size);

	/* packet type and flags; Figure 3.24 - SUBACK Packet fixed header */
	uint8_t *write_head = pkt;
	*write_head = 0x90;

	/* remaining_length */
	memcpy(++write_head, remlen_buf, encode_ret);
	write_head += encode_ret;

	/* packet identifier */
	*write_head = pkt_id >> 8;
	*++write_head = pkt_id & 0xff;

	/* suback return codes */
	memset(++write_head, SUCCESS_QOS_0, nsubs);

	write(conn, pkt, packet_size);
	free(pkt);
}

/*!
 * Given a buffer of length buflen read the topic string which begins at the buffer address and
 * return its length, including the 2 length bytes and a QoS byte. If successful store a copy of it
 * in the topics vector.
 *
 * @param out Output param. Heap allocated copy of the topic string.
 * @param buflen Length of the buffer.
 * @param buf Read buffer.
 * @param QoS Whether a QoS byte follows the string data.
 * @retval Length of the topic string, including the 2B of length and possibly a QoS byte.
 * @returns -1 on failure
 */
static ssize_t read_topic(char **out, const uint8_t *buf, size_t buflen, bool QoS) {
	ssize_t string_len = validate_topic(buf, buflen);
	const size_t topic_len = string_len + 2 + !!QoS; /* 2 len bytes, 1 QoS byte */
	if (string_len == -1 || topic_len > buflen)
		return -1;

	buf += 2; /* skip len bytes */
	if (QoS) {
		switch (buf[string_len]) {
		case 0:
		case 1:
		case 2:
			break;
		default:
			dwarnx("invalid QoS byte in topic string");
			return -1;
		}
	}

	*out = xmalloc((string_len + 1) * sizeof(char));
	(*out)[string_len] = '\0';
	memcpy(*out, buf, string_len);

	return topic_len;
}

/*!
 * Given a buffer of len buflen and assuming this buffer contains only topic strings, extract these
 * and return a vector filled with them.
 *
 * @param buf The buffer.
 * @param buflen Length of the buffer.
 * @param QoS Whether a QoS byte follows the string data.
 * @retval vector of topics as null terminated strings
 * @returns NULL on failure
 */
static str_vec *extract_topics(const uint8_t *buf, size_t buflen, bool QoS) {
	str_vec *topics;
	vec_init(&topics, 8);

	const uint8_t *read_head = buf;

	while (read_head < buf + buflen) {
		char *new_topic = NULL;
		ssize_t nread = read_topic(&new_topic, read_head, buflen - (read_head - buf), QoS);
		/* the MQTT spec actually requires us to gracefully reject the subscription if it is
		 * a valid topic string containing a wildcard character, but we're too lazy to
		 * check, so just kill em ;p */
		if (nread == -1) {
			dwarnx("bad topic string");
			goto fail;
		}
		vec_append(&topics, new_topic);
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

static pkt_action subscribe_handler(const pkt_info *pinfo, user *usr, const uint8_t *pkt, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("SUBSCRIBE") " packet\n", usr->id);

	const uint8_t *read_head = pkt;

	uint16_t packet_identifier = read_BE_16b(read_head);
	read_head += 2;

	/* must be non-zero [MQTT-2.3.1-1] */
	if (packet_identifier == 0) {
		dwarnx("zero packet identifier in SUBSCRIBE packet");
		return CLOSE_ERR;
	}

	str_vec *topics = extract_topics(read_head, pinfo->rem_len - 2, true);
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
		for (size_t j = 0; j < usr->subs->nmemb; ++j) {
			if (!strcmp(topics->arr[i], usr->subs->arr[j])) {
				dwarnx("User " MAGENTA("'%s'") " trying to subscribe to an already subscribed-to topic (%s)",
				       usr->id, topics->arr[i]);
				free(topics->arr[i]);
				goto next_topic;
			}
		}
		vec_append(&usr->subs, topics->arr[i]);
next_topic:;
	}

	size_t nsubs = topics->nmemb;
	free(topics);

	DPRINTF(MAGENTA("SUBSCRIBE") " packet parsed " GREEN("SUCCESSFULLY\n"));
	DPRINTF("subscriptions for user " MAGENTA("'%s':\n"), usr->id);
	for (size_t i = 0; i < usr->subs->nmemb; ++i)
		DPRINTF("    topic: " MAGENTA("'%s'\n"), usr->subs->arr[i]);

	send_suback(nsubs, packet_identifier, conn);

	return KEEP;
}

static pkt_action unsubscribe_handler(const pkt_info *pinfo, user *usr, const uint8_t *pkt, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("UNSUBSCRIBE") " packet\n", usr->id);

	uint16_t pkt_id = read_BE_16b(pkt);

	str_vec *unsubs = extract_topics(pkt + 2, pinfo->rem_len - 2, false);
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
	str_vec *subs = usr->subs;
	for (ssize_t i = subs->nmemb - 1; i >= 0; --i) {
		for (size_t j = 0; j < unsubs->nmemb; ++j) {
			if (!strcmp(subs->arr[i], unsubs->arr[j])) {
				DPRINTF("removing subscription " MAGENTA("'%s'") " for user " MAGENTA("'%s'\n"),
					subs->arr[i], usr->id);
				free(subs->arr[i]);
				vec_remove_at(subs, i);
				break;
			}
		}
	}

	for (size_t i = 0; i < unsubs->nmemb; ++i)
		free(unsubs->arr[i]);
	free(unsubs);

	DPRINTF(MAGENTA("UNSUBSCRIBE") " packet parsed " GREEN("SUCCESSFULLY\n"));
	DPRINTF("subscriptions for user " MAGENTA("'%s':\n"), usr->id);
	for (size_t i = 0; i < usr->subs->nmemb; ++i)
		DPRINTF("    topic: " MAGENTA("'%s'\n"), usr->subs->arr[i]);

	/* Figure 3.31 - UNSUBACK Packet fixed header
	 * Figure 3.32 - UNSUBACK Packet variable header
	 */
	const uint8_t response[] = {'\xb0', '\x02', pkt_id >> 8, pkt_id & 0xff};
	write(conn, response, sizeof(response));

	return KEEP;
}

static pkt_action pingreq_handler(const pkt_info *pinfo, user *usr, const uint8_t *pkt, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("PING") " packet; " MAGENTA("PONG!\n"), usr->id);

	/* send PINGRESP */
	const uint8_t response[] = {'\xd0', '\x00'};
	write(conn, response, sizeof(response));

	return KEEP;

	(void)pinfo;
	(void)usr;
	(void)pkt;
}

static pkt_action disconnect_handler(const pkt_info *pinfo, user *usr, const uint8_t *pkt, int conn) {
	DPRINTF("User " MAGENTA("'%s'") " sent a " MAGENTA("DISCONNECT") " packet\n", usr->id);

	return CLOSE_OK;

	(void)pinfo;
	(void)usr;
	(void)pkt;
	(void)conn;
}

/*!
 * Verifies correctness of the fixed header.
 *
 * @retval handler function applicable to given packet type
 * @returns NULL if the fixed header has an invalid format
 */
static pkt_handler verify_fixed_header(const pkt_info *pinfo, const user *usr) {
	if (pinfo->rem_len < 0) {
		dwarnx("invalid remaining length field");
		return NULL;
	}

	if (pinfo->rem_len > MESSAGE_MAX_LEN) {
		dwarnx("Message too large (max: %d, message is: %d)", MESSAGE_MAX_LEN,
		       pinfo->rem_len);
		return NULL;
	}

	switch (pinfo->pkt_type) {
	case CONNECT:
		/* 10B variable header - Figure 3.6 - Variable header
		 * + client id which has 2B length prefix and contains at least one character
		 * [MQTT-3.1.3-5]
		 */
		if (pinfo->flags == CONNECT_DEF_FLAGS && pinfo->rem_len >= 13 && !usr->connected)
			return connect_handler;
		if (usr->connected)
			dwarnx("User " MAGENTA("%s") " sent a second " MAGENTA("CONNECT") " packet",
			       usr->id);
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
		if (!(pinfo->flags & 0x0e) && pinfo->rem_len >= 3 && usr->connected)
			return publish_handler;

		dwarnx(MAGENTA("PUBLISH") " requested QoS: %d", (pinfo->flags >> 1) & 0x03);
		break;
	case SUBSCRIBE:
		/* flags: see Figure 3.20 - SUBSCRIBE Packet fixed header
		 *
		 * length: variable header contains a packet identifier (2B) and the payload
		 * contains at least one topic filter [MQTT-3.8.3-3] which is a utf8 string, at
		 * least one character long [MQTT-4.7.3-1] + a QoS byte; in total 6B or more
		 */
		if (pinfo->flags == SUBSCRIBE_DEF_FLAGS && pinfo->rem_len >= 6 && usr->connected)
			return subscribe_handler;
		break;
	case UNSUBSCRIBE:
		/* flags: see Figure 3.28 - UNSUBSCRIBE Packet Fixed header
		 *
		 * length: packet identifier (2B), at least one topic filter (3B)
		 */
		if (pinfo->flags == UNSUBSCRIBE_DEF_FLAGS && pinfo->rem_len >= 5 && usr->connected)
			return unsubscribe_handler;
		break;
	case PINGREQ:
		/* see Figure 3.33 - PINGREQ Packet fixed header */
		if (pinfo->flags == PINGREQ_DEF_FLAGS && pinfo->rem_len == 0 && usr->connected)
			return pingreq_handler;
		break;
	case DISCONNECT:
		/* see Figure 3.35 - DISCONNECT Packet fixed header */
		if (pinfo->flags == DISCONNECT_DEF_FLAGS && pinfo->rem_len == 0 && usr->connected)
			return disconnect_handler;
		break;
	}

	return NULL;
}

pkt_action process_pkt(int conn, user *usr) {
	/* attempt to avoid unnecessary reallocation of the streambuf */
	size_t to_load = MAX(SB_FREE(usr->sbuf), MIN_LOAD);
	switch (sbuf_load(&usr->sbuf, conn, to_load)) {
	case -1:
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return KEEP;
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
		size_t hdr_bytes;
		int32_t rlen = decode_remlen(SB_DATA(usr->sbuf) + 1, SB_DATASIZE(usr->sbuf) - 1, &hdr_bytes);
		++hdr_bytes; /* +1 for fixed header */
		const size_t message_size = rlen + hdr_bytes;

		switch (rlen) {
		case REMLEN_INCOMPLETE:
			DPRINTF("not enough data in buffer to determine packet length\n");
			return KEEP;
		case REMLEN_INVALID:
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
		pkt_info pinfo = {
			.pkt_type = (initial & 0xf0) >> 4,
			.flags = initial & 0x0f,
			.hdr_len = hdr_bytes,
			.rem_len = rlen,
		};

		DPRINTF("packet info: type: %d, flags: %d, length: %u\n", pinfo.pkt_type,
			pinfo.flags, pinfo.rem_len);

		pkt_handler handler = verify_fixed_header(&pinfo, usr);
		if (handler == NULL) {
			dwarnx("invalid fixed header");
			return CLOSE_ERR;
		}

		uint8_t *pkt = SB_DATA(usr->sbuf) + hdr_bytes;
		switch (handler(&pinfo, usr, pkt, conn)) {
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

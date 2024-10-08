#ifndef MQTT_H_
#define MQTT_H_

/* Constants and definitions as per MQTT v3.1.1 */

#include <stdint.h>

#include "main.h"

/* max message length for this implementation */
#define MESSAGE_MAX_LEN		4096

/* theoretical message length supported by protocol */
#define MQTT_MSG_MAX_LEN	268435455

/* revision number of the MQTT protocol - we only support this one */
#define PROTOCOL_LEVEL 4

/* Figure 3.2 - Protocol Name bytes */
#define MQTT_PROTO_NAME (char[]){'\x00', '\x04', 'M', 'Q', 'T', 'T'}

/* - [0] = RESERVED; always 0
 * - [1] = Clean Session; 1 means to not deal with
 * sessions and is what we'll be using
 * - [2] = Will Flag; 0 means don't deal with last-will
 * messages and is what we'll be using
 * - [3] & [4] = Will QoS; since we're presuming [2]=0
 * these will also be 0
 * - [5] = Will Retain; has to be 0
 * - [6] = User Name; has to be 0
 * - [7] = Password; has to be 0
 */
#define CONNECT_FLAGS 2

enum pkt_type {
	CONNECT = 1,
	CONNACK = 2,
	PUBLISH = 3,
	PUBACK = 4,
	PUBREC = 5,
	PUBREL = 6,
	PUBCOMP = 7,
	SUBSCRIBE = 8,
	SUBACK = 9,
	UNSUBSCRIBE = 10,
	UNSUBACK = 11,
	PINGREQ = 12,
	PINGRESP = 13,
	DISCONNECT = 14,
};

enum connack_code {
	CONNECTION_ACCEPTED = 0,
	UNACCEPTABLE_PROTOCOL_LEVEL = 1,
	IDENTIFIER_REJECTED = 2,
	SERVER_UNAVAILABLE = 3,
	BAD_USER_OR_PASSWORD = 4,
	NOT_AUTHORIZED = 5,
};

enum suback_code {
	SUCCESS_QOS_0 = 0,
	SUCCESS_QOS_1 = 1,
	SUCCESS_QOS_2 = 2,
	FAILURE = 0x80,
};

/* to be returned by process_pkt_handler() in mqtt.c */
typedef enum {
	CLOSE_ERR,
	CLOSE_OK,
	KEEP,
} pkt_action;

/* except for PUBLISH all control packets have the flags field predefined
 * for PUBLISH these have the following meaning:
 * 	- 3 (msb) = DUP = Duplicate delivery of a PUBLISH Control Packet
 * 	- 2 = QoS msb = quality of service msb
 * 	- 1 = QoS lsb = quality of service lsb
 * 	- 0 = RETAIN
 */
#define CONNECT_DEF_FLAGS	0 // 0b0000
#define CONNACK_DEF_FLAGS	0 // 0b0000
#define PUBACK_DEF_FLAGS	0 // 0b0000
#define PUBREC_DEF_FLAGS	0 // 0b0000
#define PUBREL_DEF_FLAGS	2 // 0b0010
#define PUBCOMP_DEF_FLAGS	0 // 0b0000
#define SUBSCRIBE_DEF_FLAGS	2 // 0b0010
#define SUBACK_DEF_FLAGS	0 // 0b0000
#define UNSUBSCRIBE_DEF_FLAGS	2 // 0b0010
#define UNSUBACK_DEF_FLAGS	0 // 0b0000
#define PINGREQ_DEF_FLAGS	0 // 0b0000
#define PINGRESP_DEF_FLAGS	0 // 0b0000
#define DISCONNECT_DEF_FLAGS	0 // 0b0000
/* ...support for binary constants is coming in C23 ;p */

typedef struct {
	uint8_t pkt_type : 4; /* 0x0 and 0xf are reserved and mustn't be used */
	uint8_t flags : 4;
	int32_t hdr_len;
	int32_t rem_len; /* combined length of the variable header and payload */
} pkt_info;

/*!
 * functions for handling distinct packet types
 *
 * @retval enum describing action to be taken by the caller
 */
typedef pkt_action (*pkt_handler)(const pkt_info *pinfo, user *usr, const uint8_t *pkt, int conn);

/*!
 * To be called on a connection which has data ready for reading (ie. we expect to recieve an MQTT
 * packet).
 *
 * Reads and verifies the MQTT packet and performs any actions required.
 *
 * @param conn The TCP connection file descriptor.
 * @param usr Pointer to the data of the user in question.
 * @retval enum describing action to be taken by the caller
 */
pkt_action process_pkt(int conn, user *usr);

#endif

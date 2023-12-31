#ifndef MQTT_H_
#define MQTT_H_

/* Constants and definitions as per MQTT v3.1.1 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "main.h"

#define MESSAGE_MAX_LEN 1024

enum control_packet_type {
	Reserved = 0,
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
	Reserved_ = 15,
};

enum connack_code {
	CONNECTION_ACCEPTED = 0,
	UNSUPPORTED_MQTT_VERSION = 1,
	IDENTIFIER_REJECTED = 2,
	SERVER_UNAVAILABLE = 3,
	BAD_USER_OR_PASSWORD = 4,
	NOT_AUTHORIZED = 5,
};

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
// ...support for binary constants is coming in C23 ;p

typedef struct {
	// 0x0 and 0xf are reserved and mustn't be used
	char packet_type : 4;
	char DUP : 1;
	char QoS : 2;
	char RETAIN : 1;
	// max 0xffffff7f (=268 435 455)
	// combined length of the variable header and payload
	uint32_t remaining_length;
} fixed_header;

bool process_packet(int conn, user_data *u);

#endif

#ifndef MAIN_H_
#define MAIN_H_

#include <bits/stdint-uintn.h>
#include <poll.h>
#include <sys/socket.h>

#include "vector.h"

/* exit codes */
#define USER_ERR 1
#define SERVER_ERR 2
#define SIGINT_EXIT 125
#define NO_SOCKET 126
#define NO_MEMORY 127

#define POLL_TIMEOUT 50 // millisecs
#define READ_TIMEOUT 50 // millisecs
#define MQTT_DEFAULT_PORT "1883"
#define CLIENT_ID_MAXLEN 23

/* common vector types */
VECTOR_DEF(char *, str_vec);
VECTOR_DEF(int, int_vec);

/* command line arguments from getopt */
typedef struct {
	char *port;
} args;

typedef struct {
	socklen_t addrlen;
	struct sockaddr_storage addr;

	/* whether MQTT connection was estabilished */
	bool CONNECT_recieved;

	/* after 1,5x of this, if no control packet was recieved, terminate the connection
	 * [MQTT-3.1.2-24]
	 * 0 means no timeout
	 */
	uint16_t keep_alive;
	/* last recieved packet timestamp */
	time_t keepalive_timestamp;
	char client_id[CLIENT_ID_MAXLEN + 1]; // +1 for 0 terminator
	str_vec *subscriptions;
} user_data;

VECTOR_DEF(user_data, user_vec);
VECTOR_DEF(struct pollfd, pollfd_vec);

typedef struct {
	// these two vectors must stay synchronized
	// rest of the program assumes that connection[i] belongs to user[i]
	user_vec *data;
	pollfd_vec *conns;
} users_t;

/* FIXME: would be nice not to have globals in code */
extern users_t users;

/* Write a human readable IPv4 or IPv6 address and port to buffer */
char *print_inaddr(size_t bufsize, char dest[bufsize], struct sockaddr addr[static 1],
		   socklen_t addrlen);

/* Mark user with given id as removed. The user shouldn't be accessed after calling this.
 *
 * @param id null terminated string representing the MQTT user id
 * @param gracefully Whether the user's connection should be closed normally or if a TCP reset
 * should be sent.
 * @return true if success false if user not found
 */
bool remove_usr_by_id(char *id, bool gracefully);

/* Mark user as removed. The user shouldn't be accessed after calling this.
 *
 * @param usr Pointer to the user_data structure.
 * @param gracefully Whether the user's connection should be closed normally or if a TCP reset
 * should be sent.
 * @return true if success false if user not found
 */
bool remove_usr_by_ptr(user_data *usr, bool gracefully);

/* A wrapper around read() which blocks until it reads nbytes or there are no more data to be read
 * from fd or timeout expires.
 *
 * @param nbytes Number of bytes to read.
 * @param buf Destination buffer.
 * @param timeout Period after which if no new data is available the call will fail.
 * @retval Number of bytes read.
 * @returns -1 on timeout or read error
 * @returns <nbytes on EOF
 * @returns nbytes otherwise
 */
ssize_t readn(int fd, size_t nbytes, char buf[static nbytes], int timeout);

#endif

#ifndef MAIN_H_
#define MAIN_H_

#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>

#include "streambuf.h"

/* replace default vector allocator with an error checking one */
#define VEC_REALLOC memrealloc
#include "vector.h"

/* exit codes */
#define USER_ERR 1
#define SERVER_ERR 2
#define SIGINT_EXIT 125
#define NO_SOCKET 126
#define NO_MEMORY 127

#define POLL_TIMEOUT 50 // millisecs
#define MQTT_DEFAULT_PORT "1883"
#define CLIENT_ID_MAXLEN 23

/* common vector types */
VECTOR_DEF(char *, str_vec);
VECTOR_DEF(int, int_vec);
VECTOR_DEF(struct pollfd, pollfd_vec);

/* command line arguments from getopt */
typedef struct {
	char *port;
} args;

typedef struct {
	streambuf	*sbuf;
	str_vec		*subscriptions;
	time_t		keepalive_timestamp;	/* last recieved packet timestamp */
	uint16_t	keep_alive;		/* 0 => no timeout */
	bool		connect_recieved;
	socklen_t	addrlen;
	struct sockaddr_storage addr;
	char		client_id[CLIENT_ID_MAXLEN + 1];
} user_data;

VECTOR_DEF(user_data, user_vec);

typedef struct {
	/* these two vectors must stay synchronized
	 * rest of the program assumes that connection[i] belongs to user[i] */
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
 * @param max length to compare up to
 * @return true if success false if user not found
 */
bool remove_usr_by_id(char *id, bool gracefully, size_t id_len);

/* Mark user as removed. The user shouldn't be accessed after calling this.
 *
 * @param usr Pointer to the user_data structure.
 * @param gracefully Whether the user's connection should be closed normally or if a TCP reset
 * should be sent.
 * @return true if success false if user not found
 */
bool remove_usr_by_ptr(user_data *usr, bool gracefully);

#endif

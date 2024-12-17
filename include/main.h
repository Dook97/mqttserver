#ifndef MAIN_H_
#define MAIN_H_

#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>

#include "streambuf.h"

/* replace default vector allocator with an error checking one */
#define VEC_REALLOC xrealloc
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
VECTOR_DEF(struct pollfd, plfd_vec);

/* command line arguments from getopt */
typedef struct {
	char *port;
} args;

typedef struct {
	streambuf               *sbuf;
	str_vec                 *subs;
	time_t                  ttl_timestamp;   /* last recieved packet timestamp */
	uint16_t                ttl;             /* 0 => no timeout */
	bool                    connected;       /* whether an MQTT connection is estabilished */
	socklen_t               addrlen;
	struct sockaddr_storage addr;
	char                    id[CLIENT_ID_MAXLEN + 1];
} user;

VECTOR_DEF(user, user_vec);

typedef struct {
	/* these two vectors must stay synchronized
	 * rest of the program assumes that connection[i] belongs to user[i] */
	user_vec *data;
	plfd_vec *conns;
} clients_t;

extern clients_t clients;

#define USERS clients.data
#define CONNS clients.conns

/*!
 * Find user by id.
 *
 * @param id null terminated string representing the MQTT user id
 * @param max length to compare up to
 * @return pointer to user
 */
user *usr_by_id(char *id, size_t id_len);

/*!
 * Free user.
 *
 * @param u Pointer to the user.
 */
void usr_free(user *u);

#endif

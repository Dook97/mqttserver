#ifndef MAIN_H_
#define MAIN_H_

#include <bits/stdint-uintn.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>

#include "vector.h"
#include "magic.h"

#define POLL_TIMEOUT 50 // milisecs

typedef struct {
	char *port;
} args;

typedef struct {
	socklen_t addrlen;
	struct sockaddr_storage addr;

	bool CONNECT_recieved;
	/* after 1,5x of this, if no control packet was recieved, terminate the connection
	 * [MQTT-3.1.2-24]
	 * 0 means no timeout
	 */
	uint16_t keep_alive;
	time_t keepalive_timestamp;
	char client_id[CLIENT_ID_MAXLEN + 1]; // +1 for 0 terminator
	str_vec *subscriptions;
} user_data;

VECTOR_DEF(user_data, user_vec);
VECTOR_DEF(struct pollfd, pollfd_vec);

typedef struct {
	user_vec *data;
	pollfd_vec *conns;
} users_t;

extern users_t users;

char *print_inaddr(size_t bufsize, char dest[bufsize], struct sockaddr addr[static 1],
		   socklen_t addrlen);

bool remove_usr_by_id(char id[static CLIENT_ID_MAXLEN + 1], bool gracefully);
bool remove_usr_by_ptr(user_data *p, bool gracefully);
ssize_t readn(int fd, size_t nbytes, char buf[static nbytes], int timeout);

#endif

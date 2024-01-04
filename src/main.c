#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "main.h"
#include "mqtt.h"

/* server exit code */
int server_exit = 0;

#ifdef DEBUG
/* buffer for debug prints */
static char dbuf[4096];
#endif

users_t users = {
	.data = NULL,
	.conns = NULL,
};

static int sock = -1;

static void cleanup(void) {
	DPRINTF("Entering cleanup...\n");

	if (sock != -1 && close(sock) == -1)
		dwarn("failed to close socket %d", sock);

	if (users.conns != NULL) {
		for (size_t i = 0; i < users.data->nmemb; ++i)
			if (close(users.conns->arr[i].fd))
				dwarn("failed to close connection %d", users.conns->arr[i].fd);
	}

	free(users.data);
	free(users.conns);
	sock = -1;
	users.data = NULL;
	users.conns = NULL;
}

static void sigint_handler(int sig) {
	dwarnx("SIGINT intercepted");
	dwarnx("Exiting due to SIGINT with exit code %d", server_exit);

	// cleanup() will be called automatically
	exit(server_exit);

	(void)sig;
}

/* A wrapper around read() which blocks until it reads nbytes or there are no more data to be read from fd. */
ssize_t readn(int fd, size_t nbytes, char buf[static nbytes], int timeout) {
	ssize_t nread = 0;
	struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};

	while (true) {
		ssize_t loop_nread = 0;
		loop_nread = read(fd, buf + nread, nbytes - nread);

		if (loop_nread == -1)
			return -1;
		if (loop_nread == 0)
			return nread;

		nread += loop_nread;
		if (nread == (ssize_t)nbytes)
			return nread;

		/* if no data becomes available in timeout millis fail the call */
		poll(NULL, 0, timeout);
		if (poll(&pfd, 1, 0) == -1)
			dwarn("poll");
		if (!(pfd.revents & POLL_IN)) {
			dwarnx("timed out trying to read from %d", fd);
			return -1;
		}
	}
}

/* Parse commandline arguments.
 *
 * @param out Output parameter.
 * @return Value indicating succes or failure.
 * @retval 0 Success
 * @retval nonzero Failure
 */
static int parse_args(int argc, char *argv[static 1], args out[static 1]) {
	char *endptr = NULL;

	for (int c; (c = getopt(argc, argv, "p:")) != -1;) {
		switch (c) {
		case 'p': {
			uintmax_t port = strtoumax(optarg, &endptr, 10);
			if (*endptr != '\0')
				goto err;
			if (port > UINT16_MAX || port < 1) {
				fprintf(stderr, "A port number must be in range 1-%d\n",
					UINT16_MAX);
				goto err;
			}
			out->port = optarg;
			break;
		}
		default:
			goto err;
		}
	}
	if (argv[optind] != NULL) // don't allow trailing args
		goto err;

	return 0;

err:
	fprintf(stderr, "Usage: mqttserver [-p PORT]\n");
	return 1;
}

char *print_inaddr(size_t bufsize, char dest[bufsize], struct sockaddr addr[static 1],
			  socklen_t addrlen) {
	// FIXME: Overkill - find some handy POSIX macros for these
	char stripaddr[4096];
	char strport[4096];
	getnameinfo(addr, addrlen, stripaddr, sizeof(stripaddr), strport, sizeof(strport),
		    NI_NUMERICHOST | NI_NUMERICSERV);
	snprintf(dest, bufsize, addr->sa_family == AF_INET6 ? "[%s]:%s" : "%s:%s", stripaddr, strport);
	return dest;
}

/* Open, configure and bind all available sockets with given port on the device for both IPv6 and
 * IPv4 communication.
 *
 * @param port String representation of the desired port number.
 * @param err_out Output parameter signifying success (zero) or failure (nonzero).
 * @return Vector of properly configured sockets (as pollfd structs).
 * @retval NULL On some types of failure.
 */
static int bind_sockets(const char *port, int ai_family) {
	int sock_ = -1;

	struct addrinfo *res = NULL;
	struct addrinfo hints = {
		.ai_family = ai_family,
		.ai_flags = AI_PASSIVE, // use a wildcard IP address
	};

	int errn = getaddrinfo(NULL, port, &hints, &res);
	if (errn) {
		dwarnx("%s\n", gai_strerror(errn));
		goto end;
	}

	for (struct addrinfo *addr = res; addr != NULL; addr = addr->ai_next) {
		bool error = false;
		sock_ = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock_ == -1)
			continue;

		/* by default send a TCP RST on close(), only if the connection is to be closed
		 * properly use setsockopt to change this individually
		 */
		struct linger lingeropt = {
			.l_onoff = 1,
			.l_linger = 0,
		};
		if (setsockopt(sock_, SOL_SOCKET, SO_LINGER, &lingeropt, sizeof(lingeropt))) {
			dwarn("setsockopt");
			error = true;
		}

		/* Allow the reuse of sockets even if there are lingering connections from the
		 * previous invocation.
		 */
		int opt = 1;
		if (setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
			dwarn("setsockopt");
			error = true;
		}

		DPRINTF("attempting to bind %s\n",
			print_inaddr(sizeof(dbuf), dbuf, addr->ai_addr, addr->ai_addrlen));

		if (!error && bind(sock_, addr->ai_addr, addr->ai_addrlen) == 0) {
			DPRINTF(GREEN("SUCCESS!") " fd is %d\n", sock_);
			goto end;
		}

		dwarn(RED("FAILURE"));

		close(sock_);
	}

end:
	freeaddrinfo(res);
	return sock_;
}

static void users_append(user_data *data, int connection) {
	assert(users.data->nmemb == users.conns->nmemb);

	bool vecerr = false;
	struct pollfd item = {.fd = connection, .events = POLLIN};
	data->client_id[0] = '\0';
	data->CONNECT_recieved = false;

	SIG_PROTECT_BEGIN;

	vec_init(&data->subscriptions, 4);
	if (data->subscriptions == NULL)
		derr(NO_MEMORY, "malloc");

	vec_append(&users.data, *data, &vecerr);
	vec_append(&users.conns, item, &vecerr);

	if (vecerr)
		derr(NO_MEMORY, "malloc: failed to append user");

	DPRINTF(GREEN("SUCCESSFULY") " added user (connection %d)\n", connection);

	SIG_PROTECT_END;

	DPRINTF("active connections: %zu\n", users.conns->nmemb);

	assert(users.data->nmemb == users.conns->nmemb);
}

static void remove_usr_by_index(size_t index, bool gracefully) {
	if (users.conns->arr[index].fd == -1)
		return;

	if (gracefully) {
		struct linger lopt = {.l_onoff = 1, .l_linger = 3};
		setsockopt(users.conns->arr[index].fd, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt));
	}

	close(users.conns->arr[index].fd);
	users.conns->arr[index].fd = -1;
}

static void users_remove_at(size_t index, bool gracefully) {
	assert(users.data->nmemb == users.conns->nmemb);

	DPRINTF("removing user " MAGENTA("'%s'") "\n", users.data->arr[index].client_id);

	SIG_PROTECT_BEGIN;

	remove_usr_by_index(index, gracefully);
	free(users.data->arr[index].subscriptions);
	vec_remove_at(users.data, index);
	vec_remove_at(users.conns, index);

	DPRINTF(GREEN("SUCCESSFULY") " removed user\n");

	SIG_PROTECT_END;

	DPRINTF("active connections: %zu\n", users.conns->nmemb);

	assert(users.data->nmemb == users.conns->nmemb);
}

static void users_clean(void) {
	for (size_t i = 0; i < users.data->nmemb;) {
		if (users.conns->arr[i].fd == -1)
			users_remove_at(i, true);
		else
			++i;
	}
}

bool remove_usr_by_id(char id[static CLIENT_ID_MAXLEN + 1], bool gracefully) {
	for (size_t i = 0; i < users.data->nmemb; ++i) {
		if (!strncmp(id, users.data->arr[i].client_id, CLIENT_ID_MAXLEN)) {
			if (users.conns->arr[i].fd == -1)
				return false;

			remove_usr_by_index(i, gracefully);
			return true;
		}
	}
	return false;
}

bool remove_usr_by_ptr(user_data *p, bool gracefully) {
	ssize_t index = p - users.data->arr;
	if (index < 0 || (size_t)index > users.data->nmemb || users.conns->arr[index].fd == -1)
		return false;
	remove_usr_by_index(index, gracefully);
	return true;
}

static void users_init(size_t capacity) {
	vec_init(&users.data, capacity);
	vec_init(&users.conns, capacity);
	if (users.data == NULL || users.conns == NULL)
		derr(NO_MEMORY, "malloc");
}

static void accept_new_connections(int sock) {
	errno = 0;
	struct pollfd pfd = {.fd = sock, .events = POLLIN};
	while (poll(&pfd, 1, 0), pfd.revents & POLLIN) {
		user_data u = {.addrlen = sizeof(struct sockaddr_storage)};
		int conn = accept(sock, (struct sockaddr *)&u.addr, &u.addrlen);

		if (conn != -1) {
			DPRINTF("connection with %s " GREEN("ESTABILISHED") "; fd is %d\n",
				print_inaddr(sizeof(dbuf), dbuf, (struct sockaddr *)&u.addr, u.addrlen),
				conn);
			users_append(&u, conn);
		} else {
			if (errno != EAGAIN)
				dwarn("accept");
			break;
		}
	}
}

static void listen_and_serve(int sock) {
	if (listen(sock, SOMAXCONN))
		derr(SERVER_ERR, "listen");

	users_init(8);
	while (true) {
		accept_new_connections(sock);

		if (users.conns->nmemb == 0)
			continue;

		if (poll(users.conns->arr, users.conns->nmemb, POLL_TIMEOUT) == -1) {
			dwarn("poll");
			continue;
		}

		for (size_t i = 0; i < users.conns->nmemb; ++i) {
			user_data *u = &users.data->arr[i];
			int conn = users.conns->arr[i].fd;
			short events = users.conns->arr[i].revents;

			if (conn == -1)
				continue;

			/* keep-alive */
			if (u->CONNECT_recieved && u->keep_alive != 0
			    && time(NULL) - u->keepalive_timestamp > (u->keep_alive * 3) / 2) {
				dwarnx("user %s has exceeded his keep-alive timeout of %d - disconnecting",
				       u->client_id, u->keep_alive);
				remove_usr_by_index(i, true);
				continue;
			}

			assert(!(events & POLLNVAL)); // no invalid fildes present
			switch (events & (POLLIN|POLLHUP|POLLERR)) {
			case POLLIN:
				if (!process_packet(conn, &users.data->arr[i])) {
					dwarnx("error when processing packet - closing connection");
					remove_usr_by_index(i, false);
				}
				break;
			case POLLHUP:
			case POLLHUP | POLLIN:
				DPRINTF("connection %d terminated by client\n", conn);
				remove_usr_by_index(i, true);
				break;
			case POLLERR:
			case POLLERR | POLLIN:
			case POLLERR | POLLHUP:
			case POLLHUP | POLLIN | POLLERR:
				dwarnx(RED("error") " on connection %d - closing", conn);
				remove_usr_by_index(i, false);
				break;
			case 0:
				break;
#ifdef DEBUG
			default:
				derrx(SERVER_ERR,
				      RED("Unexpected code path taken: ") "conn=%d flags=%d", conn,
				      events);
#endif
			}

			users_clean();
		}
	}
}

static void prepare_cleanup(void) {
	struct sigaction sa = {.sa_handler = sigint_handler};
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL))
		derr(SERVER_ERR, "sigaction");

	if (atexit(cleanup))
		derr(SERVER_ERR, "atexit: failed to register at-exit cleanup function");
}

int main(int argc, char **argv) {
	DPRINTF(RED(">>> YOU ARE RUNNING A DEBUG BUILD <<<\n"));

	prepare_cleanup();

	args args = {.port = MQTT_DEFAULT_PORT};
	if (parse_args(argc, argv, &args) != 0)
		derrx(USER_ERR, "Failed to parse commandline arguments");

	// first try with ipv6 - if successful ipv4 addresses will be mapped to ipv6
	sock = bind_sockets(args.port, AF_INET6);
	if (sock == -1) {
		dwarnx("Unable to bind a wildcard socket - falling back to IPv4");
		sock = bind_sockets(args.port, AF_INET);
	}
	if (sock == -1)
		derrx(NO_SOCKET, "failed to bind to a socket");

	listen_and_serve(sock);

	return 0;
}

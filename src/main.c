#include <assert.h>
#include <err.h>
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

static users_t users = {
	.data = NULL,
	.conns = NULL,
};

static pollfd_vec *sockets;

static void cleanup(void) {
	if (sockets != NULL)
		for (size_t i = 0; i < sockets->nmemb; ++i)
			if (close(sockets->arr[i].fd))
				dwarn("failed to close socket %d", sockets->arr[i].fd);

	if (users.data != NULL && users.conns != NULL) {
		assert(users.data->nmemb == users.conns->nmemb);
		for (size_t i = 0; i < users.data->nmemb; ++i)
			if (close(users.conns->arr[i].fd))
				dwarn("failed to close connection %d", users.conns->arr[i].fd);
	}

	free(sockets);
	free(users.data);
	free(users.conns);
	sockets = NULL;
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
static pollfd_vec *bind_sockets(const char *port, int err_out[static 1]) {
	struct addrinfo *res = NULL;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC, // both IPv4 and IPv6 are allowed
		.ai_protocol = 6, // TCP
		.ai_flags = AI_PASSIVE | // use a wildcard IP address
			    AI_NUMERICSERV, // use a port number instead of service name
	};

	vec_init(&sockets, 2);
	if (sockets == NULL) {
		dwarnx("%s\n", "Couldn't allocate memory for vector.");
		*err_out = NO_MEMORY;
		goto err;
	}

	int errn = getaddrinfo(NULL, port, &hints, &res);
	if (errn) {
		dwarnx("%s\n", gai_strerror(errn));
		*err_out = USER_ERR;
		goto err;
	}

	for (struct addrinfo *addr = res; addr != NULL; addr = addr->ai_next) {
		bool error = false;
		int sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock == -1)
			continue;

		/* Allow the reuse of sockets even if there are lingering connections from the
		 * previous invocation.
		 */
		int opt = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
			dwarn("setsockopt");
			error = true;
		}

		/* From the ipv6(7) manpage:
		 *
		 * > If this flag [IPV6_V6ONLY] is set to true (nonzero), then the socket is
		 * > restricted to sending and receiving IPv6 packets only. In this case, an IPv4
		 * > and an IPv6 application can bind to a single port at the same time.
		 *
		 * We want that.
		 */
		if (addr->ai_family == AF_INET6) {
			if (setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &opt, sizeof(opt))) {
				dwarn("setsockopt");
				error = true;
			}
		}

		DPRINTF("attempting to bind %s\n",
			print_inaddr(sizeof(dbuf), dbuf, addr->ai_addr, addr->ai_addrlen));

		if (!error && bind(sock, addr->ai_addr, addr->ai_addrlen) == 0) {
			bool error = false;
			const struct pollfd item = {.fd = sock, .events = POLLIN};
			vec_append(&sockets, item, &error);
			if (error) {
				*err_out = NO_MEMORY;
				goto err;
			}
			DPRINTF(GREEN("SUCCESS:") " sockets[%zu] = %d\n", sockets->nmemb - 1, sock);
			continue;
		}

		dwarn(RED("FAILURE"));

		close(sock);
	}
	if (sockets->nmemb == 0)
		*err_out = NO_SOCKET;

err:
	freeaddrinfo(res);
	return sockets;
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

static void users_remove_at(size_t index) {
	assert(users.data->nmemb == users.conns->nmemb);

	DPRINTF("removing user '%s'\n", users.data->arr[index].client_id,
		users.conns->arr[index].fd);

	SIG_PROTECT_BEGIN;

	if (users.conns->arr[index].fd != -1)
		close(users.conns->arr[index].fd);
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
			users_remove_at(i);
		else
			++i;
	}
}

bool remove_usr_by_id(char id[static CLIENT_ID_MAXLEN + 1]) {
	for (size_t i = 0; i < users.data->nmemb; ++i) {
		if (!strncmp(id, users.data->arr[i].client_id, CLIENT_ID_MAXLEN)) {
			if (users.conns->arr[i].fd == -1)
				return false;

			close(users.conns->arr[i].fd);
			users.conns->arr[i].fd = -1;
			return true;
		}
	}
	return false;
}

bool remove_usr_by_ptr(user_data *p) {
	ssize_t index = p - users.data->arr;
	if (index < 0 || (size_t)index > users.data->nmemb || users.conns->arr[index].fd == -1)
		return false;
	close(users.conns->arr[index].fd);
	users.conns->arr[index].fd = -1;
	return true;
}

static void remove_usr_by_index(size_t index) {
	close(users.conns->arr[index].fd);
	users.conns->arr[index].fd = -1;
}

static void users_init(size_t capacity) {
	vec_init(&users.data, capacity);
	vec_init(&users.conns, capacity);
	if (users.data == NULL || users.conns == NULL)
		derr(NO_MEMORY, "malloc");
}

static void attempt_connect(int sock, short events) {
	if (events & POLLIN) {
		DPRINTF("connection pending on %d\n", sock);
		user_data u = {.addrlen = sizeof(struct sockaddr_storage)};
		int conn = accept(sock, (struct sockaddr *)&u.addr, &u.addrlen);
		if (conn != -1) {
			DPRINTF("connection with %s " GREEN("ESTABILISHED") "; fd is %d\n",
				print_inaddr(sizeof(dbuf), dbuf, (struct sockaddr *)&u.addr, u.addrlen),
				conn);
			users_append(&u, conn);
		} else {
			dwarn("accept");
		}
	}
}

static void listen_and_serve(pollfd_vec *sockets) {
	for (size_t i = 0; i < sockets->nmemb; ++i)
		if (listen(sockets->arr[i].fd, SOMAXCONN))
			derr(SERVER_ERR, "listen");

	users_init(8);
	while (true) {
		if (poll(sockets->arr, sockets->nmemb, POLL_TIMEOUT) == -1) {
			dwarn("poll");
			continue;
		}

		for (size_t i = 0; i < sockets->nmemb; ++i)
			attempt_connect(sockets->arr[i].fd, sockets->arr[i].revents);

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

			/* keep-alive */
			if (u->CONNECT_recieved && u->keep_alive != 0
			    && time(NULL) - u->keepalive_timestamp > (u->keep_alive * 3) / 2)
				goto close_sock;

			if (users.conns->arr[i].fd == -1)
				continue;

			assert(!(events & POLLNVAL)); // no invalid fildes present
			switch (events & (POLLIN|POLLHUP|POLLERR)) {
			case POLLIN:
				if (!process_packet(conn, &users.data->arr[i])) {
					DPRINTF("connection %d properly closed\n", conn);
					goto close_sock;
				}
				break;
			case POLLHUP:
			case POLLHUP | POLLIN:
				DPRINTF("connection %d terminated by client\n", conn);
				goto close_sock;
			case POLLERR:
			case POLLERR | POLLIN:
			case POLLERR | POLLHUP:
			case POLLHUP | POLLIN | POLLERR:
				dwarnx(RED("error") " on connection %d - closing", conn);
close_sock:
				remove_usr_by_index(i);
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

	int errn = 0;
	// stores bound sockets inside a global variable
	bind_sockets(args.port, &errn);
	if (errn != 0)
		derrx(errn, "Failed to bind socket with desired parameters");

	DPRINTF("bound sockets: %lu\n", sockets->nmemb);

	listen_and_serve(sockets);

	return 0;
}

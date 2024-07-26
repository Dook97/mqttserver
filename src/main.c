#include <assert.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "magic.h"
#include "main.h"
#include "mqtt.h"

#ifdef DEBUG
/* buffer for debug prints */
static char dbuf[256];
#endif

users_t users = {
	.data = NULL,
	.conns = NULL,
};

static int sock = -1;

static void mark_usr_removed(size_t index, bool gracefully);

/* for use with atexit() */
static void cleanup(void) {
	DPRINTF("entering cleanup\n");

	if (sock != -1 && close(sock) == -1)
		dwarn("failed to close socket %d", sock);

	if (users.conns != NULL) {
		for (size_t i = 0; i < users.data->nmemb; ++i)
			mark_usr_removed(i, false);
	}

	free(users.data);
	free(users.conns);
	sock = -1;
	users.data = NULL;
	users.conns = NULL;
}

static void sigint_handler(int sig) {
	dwarnx("SIGINT intercepted");
	dwarnx("Exiting due to SIGINT with exit code %d", SIGINT_EXIT);

	/* cleanup() will be called automatically */
	exit(SIGINT_EXIT);

	(void)sig;
}

/*!
 * Parse commandline arguments.
 *
 * @param out Output parameter.
 * @return Value indicating succes or failure.
 * @retval 0 Success
 * @retval nonzero Failure
 */
static bool parse_args(int argc, char *argv[static 1], args out[static 1]) {
	char *endptr = NULL;

	for (int c; (c = getopt(argc, argv, "p:")) != -1;) {
		switch (c) {
		case 'p': {
			uintmax_t port = strtoumax(optarg, &endptr, 10);
			if (*endptr != '\0')
				return false;
			if (port > UINT16_MAX || port < 1) {
				dwarnx("A port number must be in range 1-%d\n", UINT16_MAX);
				return false;
			}
			out->port = optarg;
			break;
		}
		default:
			return false;
		}
	}
	if (argv[optind] != NULL) // don't allow trailing args
		return false;

	return true;
}

char *print_inaddr(size_t bufsize, char dest[bufsize], struct sockaddr addr[static 1], socklen_t addrlen) {
	char stripaddr[INET6_ADDRSTRLEN];
	char strport[6]; // max port number is 65535, so 5 chars + null terminator
	getnameinfo(addr, addrlen, stripaddr, sizeof(stripaddr), strport, sizeof(strport),
		    NI_NUMERICHOST | NI_NUMERICSERV);
	snprintf(dest, bufsize, addr->sa_family == AF_INET6 ? "[%s]:%s" : "%s:%s", stripaddr, strport);
	return dest;
}

/*!
 * Open, configure and bind a socket with given port.
 *
 * @param port String representation of the desired port number.
 * @param ai_family AF_INET, AF_INET6 or AF_UNSPEC. If AF_INET6 is specified, IPv4 client addresses
 * will be mapped to IPv6.
 * @return A socket file descriptor.
 * @retval -1 if unable to bind a socket.
 */
static int bind_socket(const char *port, int ai_family) {
	int sock_ = -1;

	struct addrinfo *res = NULL;
	struct addrinfo hints = {
		.ai_family = ai_family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = getprotobyname("TCP")->p_proto,
		.ai_flags = AI_PASSIVE // use a wildcard IP address
			    | AI_NUMERICSERV, // host argument to getaddrinfo shall be a string
					      // representation of the desired port number
	};

	int errn = getaddrinfo(NULL, port, &hints, &res);
	if (errn) {
		dwarnx("%s\n", gai_strerror(errn));
		goto end;
	}

	for (struct addrinfo *addr = res; addr != NULL; addr = addr->ai_next) {
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
			goto err;
		}

		/* Allow the reuse of sockets even if there are lingering connections from the
		 * previous invocation.
		 */
		int opt = 1;
		if (setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
			dwarn("setsockopt");
			goto err;
		}

		DPRINTF("attempting to bind %s\n",
			print_inaddr(sizeof(dbuf), dbuf, addr->ai_addr, addr->ai_addrlen));

		if (bind(sock_, addr->ai_addr, addr->ai_addrlen) == 0) {
			DPRINTF(GREEN("SUCCESS!") " fd is %d\n", sock_);
			goto end;
		} else {
			dwarn("bind");
			goto err;
		}

err:
		close(sock_);
		sock_ = -1;
	}

end:
	freeaddrinfo(res);
	return sock_;
}

/* Add a new user to the global vector of users. */
static void users_append(user_data *data, int connection) {
	assert(users.data->nmemb == users.conns->nmemb);

	struct pollfd item = {.fd = connection, .events = POLLIN};
	data->client_id[0] = '\0';
	data->connect_recieved = false;

	SIG_PROTECT_BEGIN;

	vec_init(&data->subscriptions, 4);
	data->sbuf = sbuf_make();
	if (data->sbuf == NULL)
		derr(NO_MEMORY, "malloc");

	vec_append(&users.data, *data, NULL);
	vec_append(&users.conns, item, NULL);

	DPRINTF(GREEN("SUCCESSFULY") " added user (connection %d)\n", connection);

	SIG_PROTECT_END;

	DPRINTF("active connections: %zu\n", users.conns->nmemb);

	assert(users.data->nmemb == users.conns->nmemb);
}

/*!
 * Mark user at index as removed. The user shouldn't be accessed after calling this.
 *
 * @param index Index in the global users vector.
 * @param gracefully Whether the user's connection should be closed normally or if a TCP reset
 * should be sent.
 */
static void mark_usr_removed(size_t index, bool gracefully) {
	int *conn = &users.conns->arr[index].fd;

	if (*conn == -1)
		return;

	user_data *u = &users.data->arr[index];
	str_vec *subs = u->subscriptions;

	for (size_t i = 0; i < subs->nmemb; ++i)
		free(subs->arr[i]);
	free(u->subscriptions);
	free(u->sbuf);

	if (gracefully) {
		struct linger lopt = {.l_onoff = 0};
		if (setsockopt(*conn, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt)))
			dwarn("setsockopt");
	}

	close(*conn);
	*conn = -1;
}

/*!
 * Remove a user from the global users vector. Cleanup will be performed.
 *
 * @param index Index in the global users vector.
 * @param gracefully Whether the user's connection should be closed normally or if a TCP reset
 * should be sent.
 */
static void users_remove_at(size_t index, bool gracefully) {
	assert(users.data->nmemb == users.conns->nmemb);

	const char *usrname = (*users.data->arr[index].client_id == '\0')
				      ? "[[UNNAMED]]"
				      : users.data->arr[index].client_id;

	DPRINTF("removing user " MAGENTA("'%s'") "\n", usrname);

	SIG_PROTECT_BEGIN;

	mark_usr_removed(index, gracefully);
	vec_remove_at(users.data, index);
	vec_remove_at(users.conns, index);

	DPRINTF(GREEN("SUCCESSFULY") " removed user\n");

	SIG_PROTECT_END;

	DPRINTF("active connections: %zu\n", users.conns->nmemb);

	assert(users.data->nmemb == users.conns->nmemb);
}

/* Remove users marked by mark_usr_removed from the global users vector. */
static void users_clean(void) {
	for (ssize_t i = (ssize_t)users.data->nmemb - 1; i >= 0; --i) {
		if (users.conns->arr[i].fd == -1)
			users_remove_at(i, true);
	}
}

bool remove_usr_by_id(char *id, bool gracefully, size_t id_len) {
	for (size_t i = 0; i < users.data->nmemb; ++i) {
		size_t other_len = strlen(users.data->arr[i].client_id);
		if (id_len != other_len)
			continue;

		if (!memcmp(id, users.data->arr[i].client_id, id_len)) {
			mark_usr_removed(i, gracefully);
			return true;
		}
	}
	return false;
}

bool remove_usr_by_ptr(user_data *usr, bool gracefully) {
	ssize_t index = usr - users.data->arr;
	if (index < 0 || (size_t)index > users.data->nmemb || users.conns->arr[index].fd == -1) {
		dwarnx("Invalid user pointer passed to remove_usr_by_ptr");
		return false;
	}
	mark_usr_removed(index, gracefully);
	return true;
}

/* Check if there are any new connections pending and if so accept them
 *
 * @param sock The socket from which the connections are to be accepted.
 * @param timeout A timeout which is applied only once to avoid excessive syscalls when the
 * function is called repeatedly.
 */
static void accept_new_connections(int sock, int timeout) {
	struct pollfd pfd = {.fd = sock, .events = POLLIN};
	int pollret = 0;
	while ((pollret = poll(&pfd, 1, timeout)) != -1 && (pfd.revents & POLLIN)) {
		user_data u = {.addrlen = sizeof(struct sockaddr_storage)};
		int conn = accept(sock, (struct sockaddr *)&u.addr, &u.addrlen);

		if (conn == -1) {
			dwarn("accept");
			continue;
		}

		DPRINTF("connection with %s " GREEN("ESTABILISHED") "; fd is %d\n",
			print_inaddr(sizeof(dbuf), dbuf, (struct sockaddr *)&u.addr, u.addrlen), conn);
		users_append(&u, conn);

		/* only wait on the first connection - this avoids potentially excessive waiting
		 * when multiple users at once are waiting to have their connection request accepted
		 * while also ensuring that we won't be bullying the kernel with syscalls
		 */
		timeout = 0;
	}
	if (pollret == -1)
		dwarn("poll");
}

/*!
 * Check whether user exceeded his keep-alive period and if he did, disconnect him.
 *
 * @retval true if client was disconnected else false
 */
static bool handle_keepalive(user_data *u, time_t now) {
	if (u->connect_recieved && u->keep_alive != 0
	    && now - u->keepalive_timestamp > (u->keep_alive * 3) / 2) {
		dwarnx("keep alive period expired for user " MAGENTA("'%s'"), u->client_id);
		/* sending TCP RST as per [MQTT-3.1.2-24] */
		remove_usr_by_ptr(u, false);
		return true;
	}
	return false;
}

/*!
 * Main program loop.
 *
 * Accepts new connections, checks if any of the connections have available data then calls the
 * proper handlers or removes closed/erroneous connections etc.
 *
 * @param sock The socket from which the connections are to be accepted.
 */
static void listen_and_serve(int sock) {
	if (listen(sock, SOMAXCONN))
		derr(SERVER_ERR, "listen");

	while (true) {
		do {
			accept_new_connections(sock, POLL_TIMEOUT);
		} while (users.conns->nmemb == 0);

		/* zero timeout is OK - we've already waited in accept_new_connections() */
		if (poll(users.conns->arr, users.conns->nmemb, 0) == -1) {
			dwarn("poll");
			continue;
		}

		time_t now = time(NULL);
		for (size_t i = 0; i < users.conns->nmemb; ++i) {
			user_data *u = &users.data->arr[i];
			int conn = users.conns->arr[i].fd;
			short events = users.conns->arr[i].revents & (POLLIN|POLLHUP|POLLERR|POLLNVAL);

			/* users with conn == -1 were marked as invalid, so skip them - we'll remove
			 * them later */
			if (conn == -1)
				continue;

			if (events & POLLIN)
				u->keepalive_timestamp = now;
			if (handle_keepalive(u, now))
				continue;

			switch (events) {
			case POLLHUP | POLLIN:
				DPRINTF("POLLHUP on connection %d, but there's still data to be read\n", conn);
				/* fallthrough */
			case POLLIN:
				switch (process_packet(conn, &users.data->arr[i])) {
				case CLOSE_ERR:
					dwarnx(RED("error") " on connection %d - closing", conn);
					mark_usr_removed(i, false);
					break;
				case CLOSE_OK:
					mark_usr_removed(i, true);
					break;
				case KEEP:
					break;
				}
				break;
			case POLLHUP:
				DPRINTF("connection %d terminated by client\n", conn);
				mark_usr_removed(i, true);
				break;
			case POLLERR:
			case POLLERR | POLLIN:
			case POLLERR | POLLHUP:
			case POLLERR | POLLHUP | POLLIN:
				dwarnx(RED("error") " on connection %d - closing", conn);
				mark_usr_removed(i, false);
				break;
			case 0:
				break;
			default: // POLLNVAL present - should never happen
				derrx(SERVER_ERR, RED("POLLNVAL") "on connection %d with events %d",
				      conn, events);
			}

			users_clean();
		}
	}
}

/* helper function to setup atexit and signal handlers */
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
	if (!parse_args(argc, argv, &args))
		derrx(USER_ERR, "Usage: mqttserver [-p PORT]");

	/* first try with ipv6 - if successful ipv4 addresses will be mapped to ipv6 */
	sock = bind_socket(args.port, AF_INET6);
	if (sock == -1) {
		dwarnx("Unable to bind a wildcard socket - falling back to IPv4");
		sock = bind_socket(args.port, AF_INET);
	}
	if (sock == -1)
		derrx(NO_SOCKET, "failed to bind to a socket");

	static const size_t USERS_INITIAL_SIZE = 8;
	vec_init(&users.data, USERS_INITIAL_SIZE);
	vec_init(&users.conns, USERS_INITIAL_SIZE);

	listen_and_serve(sock);

	/* we should never get here */
	derrx(SERVER_ERR, "Escaped main program loop. This shouldn't happen.");
}

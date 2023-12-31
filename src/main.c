#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "magic.h"
#include "main.h"

#ifdef DEBUG
static char dbuf[4096];
#endif

static pollfd_vec *sockets = NULL;

/* server exit code */
int server_exit = 0;

static void cleanup(void) {
	if (sockets == NULL)
		return;

	for (size_t i = 0; i < sockets->nmemb; ++i) {
		if (close(sockets->data[i].fd))
			dwarn("failed to close socket %d", sockets->data[i].fd);
	}

	free(sockets);
	sockets = NULL;
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

static char *print_inaddr(size_t bufsize, char dest[bufsize], struct sockaddr addr[static 1],
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

static bool process_packet(int conn, user *u) {
	char buf[1024] = {0};
	int i = read(conn, buf, sizeof(buf));

	if (i == 0)
		return false;

	char addrbuf[128];
	fprintf(stderr, "[%s]: ", print_inaddr(sizeof(addrbuf), addrbuf, (struct sockaddr *)&u->addr, u->addrlen));
	write(2, buf, i);

	return true;
}

static void listen_and_serve(pollfd_vec *sockets) {
	bool vec_err; // vector error indication

	for (size_t i = 0; i < sockets->nmemb; ++i)
		if (listen(sockets->data[i].fd, SOMAXCONN))
			derr(SERVER_ERR, "listen");

	/* these two vectors must stay synchronized */
	user_vec *users;
	pollfd_vec *userconns;
	vec_init(&users, 8);
	vec_init(&userconns, 8);
	if (users == NULL || userconns == NULL)
		derr(NO_MEMORY, "malloc");

	while (true) {
		assert(users->nmemb == userconns->nmemb);

		if (poll(sockets->data, sockets->nmemb, POLL_TIMEOUT) == -1) {
			dwarn("poll");
			continue;
		}

		for (size_t i = 0; i < sockets->nmemb; ++i) {
			if (sockets->data[i].revents & POLLIN) {
				DPRINTF("connection pending on %d\n", sockets->data[i].fd);
				user u = {.addrlen = sizeof(struct sockaddr_storage)};
				int conn = accept(sockets->data[i].fd, (struct sockaddr *)&u.addr, &u.addrlen);
				if (conn != -1) {
					DPRINTF("connection with %s " GREEN("ESTABILISHED") "; fd is %d\n",
						print_inaddr(sizeof(dbuf), dbuf, (struct sockaddr *)&u.addr, u.addrlen), conn);
					struct pollfd item = {.fd = conn, .events = POLLIN};
					vec_init(&u.subscriptions, 4);
					vec_append(&userconns, item, &vec_err);
					vec_append(&users, u, &vec_err);
					if (vec_err || u.subscriptions == NULL)
						derr(NO_MEMORY, "malloc");
				} else {
					dwarn("accept");
				}
			}
		}

		if (userconns->nmemb == 0)
			continue;

		if (poll(userconns->data, userconns->nmemb, POLL_TIMEOUT) == -1) {
			dwarn("poll");
			continue;
		}

		for (size_t i = 0; i < userconns->nmemb; ++i) {
			short events = userconns->data[i].revents;
			int *conn = &userconns->data[i].fd;

			// assert(!(events & POLLNVAL));
			switch (events & (POLLIN|POLLHUP|POLLERR)) {
			case POLLIN:
				if (!process_packet(*conn, &users->data[i])) {
					DPRINTF("connection %d properly closed by client\n", *conn);
					goto close_sock;
				}
				break;
			case POLLHUP:
			case POLLHUP | POLLIN:
				DPRINTF("connection %d terminated by client\n", *conn);
				goto close_sock;
			case POLLERR:
			case POLLERR | POLLIN:
			case POLLHUP | POLLIN | POLLERR:
				dwarnx("error on connection %d - closing", *conn);
close_sock:
				close(*conn);
				*conn = -1;
				/* TODO: remove from userconns and users */
				break;
#ifdef DEBUG
			default:
				derrx(SERVER_ERR,
				      RED("Unexpected code path taken: ") "conn=%d flags=%d", *conn,
				      events);
#endif
			}
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
	bind_sockets(args.port, &errn);
	if (errn != 0)
		derrx(errn, "Failed to bind socket with desired parameters");

	DPRINTF("bound sockets: %lu\n", sockets->nmemb);

	listen_and_serve(sockets);

	return 0;
}

#include <err.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "magic.h"
#include "main.h"

/* Parse commandline arguments.
 *
 * @param out Output parameter.
 * @return Value indicating succes or failure.
 * @retval 0 Success
 * @retval nonzero Failure
 */
static int parse_args(int argc, char **argv, args *out) {
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

static char *print_inaddr(size_t bufsize, char dest[bufsize], struct sockaddr *addr, socklen_t addrlen) {
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
static pollfd_vec *bind_sockets(const char *port, int *err_out) {
	struct addrinfo *res = NULL;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC, // both IPv4 and IPv6 are allowed
		.ai_protocol = 6, // TCP
		.ai_flags = AI_PASSIVE | // use a wildcard IP address
			    AI_NUMERICSERV, // use a port number instead of service name
	};

	pollfd_vec *sockets;
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

#ifdef DEBUG
		char buf[4096];
		dprintf("attempting to bind %s\n",
			print_inaddr(sizeof(buf), buf, addr->ai_addr, addr->ai_addrlen));
#endif

		if (!error && bind(sock, addr->ai_addr, addr->ai_addrlen) == 0) {
			bool error = false;
			const struct pollfd item = {.fd = sock, .events = POLLIN};
			vec_append(&sockets, item, &error);
			if (error) {
				*err_out = NO_MEMORY;
				goto err;
			}
#ifdef DEBUG
			dprintf(GREEN("SUCCESS:") " sockets[%zu] = %d\n", sockets->nmemb - 1, sock);
#endif
			continue;
		}

#ifdef DEBUG
		dwarn(RED("FAILURE"));
#endif

		close(sock);
	}
	if (sockets->nmemb == 0)
		*err_out = NO_SOCKET;

err:
	freeaddrinfo(res);
	return sockets;
}

static void handle_connection(int conn) {
	char buf[4096] = {0};
	for (int i; (i = read(conn, buf, sizeof(buf))) > 0;)
		write(2, buf, i);
	close(conn);
}

static void listen_and_serve(pollfd_vec *sockets) {
	for (size_t i = 0; i < sockets->nmemb; ++i)
		if (listen(sockets->data[i].fd, SOMAXCONN))
			derr(SERVER_ERR, "listen");

	while (true) {
		if (poll(sockets->data, sockets->nmemb, -1) == -1) {
			dwarn("poll");
			continue;
		}

		for (size_t i = 0; i < sockets->nmemb; ++i) {
			if (sockets->data[i].revents & POLLIN) {
				struct sockaddr_storage *addr = NULL;
				socklen_t *addrlen = NULL;
#ifdef DEBUG
				struct sockaddr_storage backing = (struct sockaddr_storage){0};
				socklen_t backing2;
				addr = &backing;
				addrlen = &backing2;
				dprintf("connection pending on %d\n", sockets->data[i].fd);
#endif
				int conn = accept(sockets->data[i].fd, (struct sockaddr *)addr, addrlen);
				if (conn != -1) {
#ifdef DEBUG
					char buf[4096];
					dprintf("connection with %s " GREEN("ESTABILISHED") "; fd is %d\n",
						print_inaddr(sizeof(buf), buf, (struct sockaddr *)addr, *addrlen), conn);
#endif
					handle_connection(conn);
				} else {
					dwarn("accept");
				}
			}
		}
	}
}

int main(int argc, char **argv) {
#ifdef DEBUG
	fprintf(stderr, RED(">>> YOU ARE RUNNING A DEBUG BUILD <<<\n\n"));
#endif

	args args = {.port = MQTT_DEFAULT_PORT};
	if (parse_args(argc, argv, &args) != 0)
		derrx(USER_ERR, "Failed to parse commandline arguments");

	int errn = 0;
	pollfd_vec *sockets = bind_sockets(args.port, &errn);
	if (errn != 0)
		derrx(errn, "Failed to bind socket with desired parameters");

#ifdef DEBUG
	dprintf("bound sockets: %lu\n", sockets->nmemb);
#endif

	listen_and_serve(sockets);

	return 0;
}

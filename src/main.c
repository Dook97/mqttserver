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

static int_vec *bind_sockets(const char *port, int *err_out) {
	struct addrinfo *res = NULL;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC, // both IPv4 and IPv6 are allowed
		.ai_protocol = 6, // TCP
		.ai_flags = AI_PASSIVE | // use a wildcard IP address
			    AI_NUMERICSERV, // use a port number instead of service name
	};

	int_vec *sockets;
	vec_init(&sockets, 2);
	if (sockets == NULL) {
		*err_out = NO_MEMORY;
		goto err;
	}

	int errn = getaddrinfo(NULL, port, &hints, &res);
	if (errn) {
		fprintf(stderr, "%s\n", gai_strerror(errn));
		*err_out = USER_ERR;
		goto err;
	}

	for (struct addrinfo *addr = res; addr != NULL; addr = addr->ai_next) {
		int sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock == -1)
			continue;

		/* Allow the reuse of sockets even if there are lingering connections from the
		 * previous invocation.
		 */
		int opt = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
			err(SERVER_ERR, "setsockopt");

		/* From the ipv6(7) manpage:
		 *
		 * > If this flag [IPV6_V6ONLY] is set to true (nonzero), then the socket is
		 * > restricted to sending and receiving IPv6 packets only. In this case, an IPv4
		 * > and an IPv6 application can bind to a single port at the same time.
		 *
		 * We want that.
		 */
		if (addr->ai_family == AF_INET6) {
			if (setsockopt(sock, SOL_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)))
				err(SERVER_ERR, "setsockopt");
		}

#ifdef DEBUG
		char stripaddr[4096];
		char strport[4096];
		getnameinfo(addr->ai_addr, addr->ai_addrlen, stripaddr, sizeof(stripaddr), strport,
			    sizeof(strport), NI_NUMERICHOST | NI_NUMERICSERV);
		dprintf(addr->ai_family == AF_INET6 ? "attempting to bind [%s]:%s\n"
						    : "attempting to bind %s:%s\n",
			stripaddr, strport);
#endif

		if (bind(sock, addr->ai_addr, addr->ai_addrlen) == 0) {
			bool error = false;
			vec_append(&sockets, sock, &error);
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
#include <errno.h>
		dprintf(RED("FAILURE: ") "%s\n", strerror(errno));
#endif

		close(sock);
	}
	if (sockets->nmemb == 0)
		*err_out = NO_SOCKET;

err:
	freeaddrinfo(res);
	return sockets;
}

static void listen_and_serve(int_vec *sockets) {
	for (size_t i = 0; i < sockets->nmemb; ++i)
		if (listen(sockets->data[i], SOMAXCONN))
			err(SERVER_ERR, "listen");
}

int main(int argc, char **argv) {
#ifdef DEBUG
	fprintf(stderr, RED(">>> YOU ARE RUNNING A DEBUG BUILD OF THE PROGRAM <<<\n\n"));
#endif

	args args = {.port = MQTT_DEFAULT_PORT};
	if (parse_args(argc, argv, &args) != 0)
		errx(USER_ERR, "Failed to parse commandline arguments");

	int errn = 0;
	int_vec *sockets = bind_sockets(args.port, &errn);
	if (errn != 0)
		errx(errn, "Failed to bind socket with desired parameters");

#ifdef DEBUG
	dprintf("bound sockets: %lu\n", sockets->nmemb);
#endif

	listen_and_serve(sockets);

	return 0;
}

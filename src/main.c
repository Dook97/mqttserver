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
				fprintf(stderr, "A port number must be in range 1-%d\n", UINT16_MAX);
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

int bind_socket(const char *port, int *err_out) {
	int sock = -1;

	struct addrinfo *res = NULL;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC, // both IPv4 and IPv6 are allowed
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 6, // TCP
		.ai_flags = AI_PASSIVE | // use a wildcard IP address
			    AI_NUMERICSERV, // use a port number instead of service name
	};

	int err = getaddrinfo(NULL, port, &hints, &res);
	if (err) {
		fprintf(stderr, "%s\n", gai_strerror(err));
		*err_out = USER_ERR;
		goto err;
	}

	for (struct addrinfo *addr = res; addr != NULL; addr = addr->ai_next) {
		sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock == -1)
			continue;

		if (bind(sock, addr->ai_addr, addr->ai_addrlen) == 0)
			break; // success

		close(sock);
		sock = -1;
	}
	if (sock == -1)
		*err_out = NO_SOCKET;

err:
	freeaddrinfo(res);
	return sock;
}

void handle_MQTT_client(int sock) {
	int connection_fd = accept(sock, NULL, NULL);
	for (int c; read(connection_fd, &c, 1) == 1;) {
		write(1, &c, 1);
	}
}

int main(int argc, char **argv) {
	args args = { .port = MQTT_DEFAULT_PORT };
	if (parse_args(argc, argv, &args) != 0)
		errx(USER_ERR, "Failed to parse commandline arguments");

	int sock = 0, errn = 0;
	if ((sock = bind_socket(args.port, &errn)) == -1)
		errx(errn, "Failed to bind socket with desired parameters");

	if (listen(sock, SOMAXCONN) == -1)
		err(SERVER_ERR, "listen");

	while (true)
		handle_MQTT_client(sock);

	return 0;
}

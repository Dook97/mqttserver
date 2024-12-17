#include <assert.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "magic.h"
#include "main.h"
#include "mqtt.h"

#ifndef NDEBUG
/* buffer for debug prints */
static char dbuf[256];
#endif

clients_t clients = {
	.data = NULL,
	.conns = NULL,
};

static int sock = -1;

/* for use with atexit() */
static void cleanup(void) {
	DPRINTF("entering cleanup\n");

	if (sock >= 0 && close(sock) == -1)
		dwarn("failed to close socket %d", sock);

	if (CONNS != NULL) {
		for (size_t i = 0; i < USERS->nmemb; ++i)
			usr_free(&USERS->arr[i]);
	}

	free(USERS);
	free(CONNS);
	sock = -1;
	USERS = NULL;
	CONNS = NULL;
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
	if (argv[optind] != NULL) /* don't allow trailing args */
		return false;

	return true;
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
		.ai_flags = AI_PASSIVE /* use a wildcard IP address */
			    | AI_NUMERICSERV, /* host argument to getaddrinfo shall be a string
						 representation of the desired port number */
	};

	int errn = getaddrinfo(NULL, port, &hints, &res);
	if (errn) {
		dwarnx("%s\n", gai_strerror(errn));
		goto end;
	}

	for (struct addrinfo *addr = res; addr != NULL; addr = addr->ai_next) {
		sock_ = socket(addr->ai_family, addr->ai_socktype | SOCK_NONBLOCK, addr->ai_protocol);
		if (sock_ == -1)
			continue;

		errno = 0;
		setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
		if (errno) {
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
static void users_append(user *data, int connection) {
	assert(USERS->nmemb == CONNS->nmemb);

	struct pollfd item = {.fd = connection, .events = POLLIN};
	data->id[0] = '\0';
	data->connected = false;

	vec_init(&data->subs, 4);
	data->sbuf = sbuf_make();

	vec_append(&USERS, *data);
	vec_append(&CONNS, item);

	assert(USERS->nmemb == CONNS->nmemb);

	DPRINTF(GREEN("SUCCESSFULY") " added user (connection %d)\n", connection);
	DPRINTF("active connections: %zu\n", CONNS->nmemb);
}

void usr_free(user *u) {
	size_t index = u - USERS->arr;
	int conn = CONNS->arr[index].fd;
	close(conn);

	DPRINTF(MAGENTA("DISCONNECTING") " user " MAGENTA("'%s'") " (connection %d)\n",
		*u->id ? u->id : "[[UNNAMED]]", conn);

	assert(index <= USERS->nmemb && conn >= 0);

	str_vec *subs = u->subs;
	for (size_t i = 0; i < subs->nmemb; ++i)
		free(subs->arr[i]);
	free(u->subs);
	free(u->sbuf);

	/* mark user invalid */
	CONNS->arr[index].fd = -1;
}

user *usr_by_id(char *id, size_t id_len) {
	for (size_t i = 0; i < USERS->nmemb; ++i) {
		user *u = &USERS->arr[i];
		if (strmemeq(id_len, u->id, id))
			return u;
	}
	return NULL;
}

/*! Remove dead users from global users vectors. */
static void sweep_dead_users(void) {
	if (USERS->nmemb == 0)
		return;

	user *left = USERS->arr;
	user *right = &USERS->arr[USERS->nmemb - 1];

#define VALID(u) (CONNS->arr[(u) - USERS->arr].fd >= 0)
	while (left <= right) {
		if (VALID(left)) {
			++left;
		} else if (VALID(right)) {
			CONNS->arr[left - USERS->arr] = CONNS->arr[right - USERS->arr];
			*left = *right;
			++left;
			--right;
		} else {
			--right;
		}
	}
#undef VALID

	USERS->nmemb = CONNS->nmemb = left - USERS->arr;
}

/*!
 * Check if there are any new connections pending and if so accept them.
 *
 * @param sock The socket from which the connections are to be accepted.
 */
static void accept_conns(int sock) {
	while (true) {
		errno = 0;
		user u = {.addrlen = sizeof(struct sockaddr_storage)};
		int conn = accept(sock, (struct sockaddr *)&u.addr, &u.addrlen);

		switch (errno) {
		case 0:
			DPRINTF("connection with %s " GREEN("ESTABILISHED") "; fd is %d\n",
				print_inaddr(sizeof(dbuf), dbuf, (struct sockaddr *)&u.addr, u.addrlen), conn);
			users_append(&u, conn);
			break;
		case EAGAIN: /* all conns from system queue have been accepted */
#if (EAGAIN != EWOULDBLOCK)
		case EWOULDBLOCK:
#endif
			return;
		default:
			dwarn("accept");
			continue;
		}
	}
}

/*!
 * Check whether user exceeded his keep-alive period and if he did, disconnect him.
 *
 * @retval true if client was disconnected else false
 */
static bool check_keepalive(user *u, time_t now) {
	if (u->connected && u->ttl && (now - u->ttl_timestamp) > (u->ttl * 3) / 2) {
		dwarnx("keep alive period expired for user " MAGENTA("'%s'"), u->id);
		usr_free(u);
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
static void mqtt_serve(int sock) {
	if (USERS->nmemb == 0) {
		switch (poll(&(struct pollfd){.fd = sock, .events = POLLIN}, 1, -1)) {
		case -1:
			dwarn("poll");
		case 0:
			return;
		case 1:
			break;
		}
	}

	accept_conns(sock);

	if (poll(CONNS->arr, CONNS->nmemb, POLL_TIMEOUT) == -1) {
		dwarn("poll");
		return;
	}

	time_t now = time(NULL);
	for (size_t i = 0; i < CONNS->nmemb; ++i) {
		user *u = &USERS->arr[i];
		int conn = CONNS->arr[i].fd;
		short events = CONNS->arr[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL);

		if (conn == -1)
			continue;

		if (events & POLLIN)
			u->ttl_timestamp = now;
		if (check_keepalive(u, now))
			continue;

		switch (events) {
		case POLLHUP | POLLIN:
			DPRINTF("POLLHUP on connection %d, but there's still data to be read\n", conn);
			/* fallthrough */
		case POLLIN:
			switch (process_pkt(conn, u)) {
			case CLOSE_ERR:
				dwarnx(RED("error") " on connection %d - closing", conn);
				usr_free(u);
				break;
			case CLOSE_OK:
				usr_free(u);
				break;
			case KEEP:
				break;
			}
			break;
		case POLLHUP:
			DPRINTF("connection %d terminated by client\n", conn);
			usr_free(u);
			break;
		case POLLERR:
		case POLLERR | POLLIN:
		case POLLERR | POLLHUP:
		case POLLERR | POLLHUP | POLLIN:
			dwarnx(RED("error") " on connection %d - closing", conn);
			usr_free(u);
			break;
		case 0:
			break;
		default:
			derrx(SERVER_ERR, (events & POLLNVAL) ? "POLLNVAL occured" : "unexpected code path");
		}
	}

	sweep_dead_users();
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

	if (listen(sock, SOMAXCONN))
		derr(SERVER_ERR, "listen");

	static const size_t USERS_INITIAL_SIZE = 8;
	vec_init(&USERS, USERS_INITIAL_SIZE);
	vec_init(&CONNS, USERS_INITIAL_SIZE);

	while (true)
		mqtt_serve(sock);

	derrx(SERVER_ERR, "Escaped main program loop. This shouldn't happen.");
}

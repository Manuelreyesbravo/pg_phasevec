/*
 * pg_phasevec 0.9.0: the database asks the watch's sealed reader for a question's codes.
 *
 * phasevec._ask(watch, request) connects to <phasevec.socket_dir>/<watch>.sock, the socket the
 * reader of that watch serves (phasevec-reader --serve), sends one JSON line and returns the one
 * line that comes back. The path is not the caller's to choose: the directory is a superuser
 * setting and the file name is the watch's name (checked against [A-Za-z0-9_.-]). The function is
 * revoked from PUBLIC; phasevec.search() is what callers use. A reader that is down, slow or gone
 * is an ERROR with its cause, never an empty answer: the caller decides what to do, and says so.
 *
 * The reader stays a separate, sealed process: the database calls it, it does not absorb it.
 */
#include "postgres.h"

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "fmgr.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/timestamp.h"

void		_PG_init(void);
extern bool phasevec_shared_ivf_cache;	/* phasevec_ivf.c */
extern int	phasevec_shared_ivf_cache_mb;	/* phasevec_ivf.c */

static char *socket_dir = NULL;
static int	ask_timeout_ms = 10000;

void
_PG_init(void)
{
	DefineCustomIntVariable("phasevec.shared_ivf_cache_mb",
							"Memory the shared copies of the coarse indexes may hold, in MB (0.10.0)",
							"Past it, unreferenced copies go least recently used first; an index larger than it stays private to each backend.",
							&phasevec_shared_ivf_cache_mb, 1024, 16, 1024 * 1024, PGC_SUSET, GUC_UNIT_MB, NULL, NULL, NULL);
	DefineCustomBoolVariable("phasevec.shared_ivf_cache",
							 "Sweep the coarse index from the copy shared by every backend (0.10.0)",
							 "Off: each connection loads and keeps its own copy, as before 0.10.0.",
							 &phasevec_shared_ivf_cache, true, PGC_USERSET, 0, NULL, NULL, NULL);
	DefineCustomStringVariable("phasevec.socket_dir",
							   "Directory of the readers' sockets (<watch>.sock); empty: /run/user/<uid>/phasevec.",
							   NULL, &socket_dir, "", PGC_SUSET, 0, NULL, NULL, NULL);
	DefineCustomIntVariable("phasevec.ask_timeout_ms",
							"How long phasevec.search() waits for a reader.",
							NULL, &ask_timeout_ms, 10000, 100, 600000, PGC_USERSET, GUC_UNIT_MS, NULL, NULL, NULL);
	MarkGUCPrefixReserved("phasevec");
}

static void
wait_for(int fd, short ev, TimestampTz deadline, const char *path)
{
	for (;;)
	{
		long		left = TimestampDifferenceMilliseconds(GetCurrentTimestamp(), deadline);
		struct pollfd p = {fd, ev, 0};
		int			n;

		CHECK_FOR_INTERRUPTS();
		if (left <= 0)
		{
			close(fd);
			ereport(ERROR, (errmsg("phasevec: the reader at %s did not answer within %d ms", path, ask_timeout_ms)));
		}
		n = poll(&p, 1, (int) Min(left, 250));	/* short slices: a cancel is seen within 250 ms */
		if (n > 0)
			return;
		if (n < 0 && errno != EINTR)
		{
			int			e = errno;

			close(fd);
			ereport(ERROR, (errmsg("phasevec: waiting for the reader at %s: %s", path, strerror(e))));
		}
	}
}

PG_FUNCTION_INFO_V1(phasevec_ask);
Datum
phasevec_ask(PG_FUNCTION_ARGS)
{
	char	   *watch = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char	   *req = text_to_cstring(PG_GETARG_TEXT_PP(1));
	char		path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
	struct sockaddr_un addr;
	StringInfoData out;
	TimestampTz deadline;
	size_t		len = strlen(req), sent = 0;
	int			fd;

	for (const char *c = watch; *c; c++)
		if (!(isalnum((unsigned char) *c) || *c == '_' || *c == '.' || *c == '-'))
			ereport(ERROR, (errmsg("phasevec: \"%s\" is not a watch name a socket can carry", watch)));
	if (*watch == '\0' || *watch == '.')
		ereport(ERROR, (errmsg("phasevec: \"%s\" is not a watch name a socket can carry", watch)));
	if (strchr(req, '\n'))
		ereport(ERROR, (errmsg("phasevec: a request is one JSON line")));
	if (socket_dir && *socket_dir)
		snprintf(path, sizeof path, "%s/%s.sock", socket_dir, watch);
	else
		snprintf(path, sizeof path, "/run/user/%d/phasevec/%s.sock", (int) geteuid(), watch);

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, path, sizeof addr.sun_path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		ereport(ERROR, (errmsg("phasevec: socket(): %m")));
	deadline = TimestampTzPlusMilliseconds(GetCurrentTimestamp(), ask_timeout_ms);
	if (connect(fd, (struct sockaddr *) &addr, sizeof addr) < 0)
	{
		int			e = errno;

		if (e == EINPROGRESS || e == EAGAIN)
			wait_for(fd, POLLOUT, deadline, path);
		else
		{
			close(fd);
			ereport(ERROR, (errmsg("phasevec: the reader of watch \"%s\" is not reachable at %s: %s", watch, path, strerror(e)),
							errhint("Start it: systemctl --user start phasevec-lector-...@%s", watch)));
		}
	}
	while (sent <= len)
	{
		const char *buf = sent < len ? req + sent : "\n";
		size_t		n = sent < len ? len - sent : 1;
		ssize_t		w;

		wait_for(fd, POLLOUT, deadline, path);
		w = send(fd, buf, n, MSG_NOSIGNAL);
		if (w < 0)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;
			close(fd);
			ereport(ERROR, (errmsg("phasevec: sending to the reader at %s: %m", path)));
		}
		sent += (size_t) w;
	}
	initStringInfo(&out);
	for (;;)
	{
		char		buf[8192];
		ssize_t		r;

		wait_for(fd, POLLIN, deadline, path);
		r = recv(fd, buf, sizeof buf, 0);
		if (r < 0)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;
			close(fd);
			ereport(ERROR, (errmsg("phasevec: reading from the reader at %s: %m", path)));
		}
		if (r == 0)
			break;
		appendBinaryStringInfo(&out, buf, (int) r);
		if (out.len > 0 && out.data[out.len - 1] == '\n')
			break;
		if (out.len > 64 * 1024 * 1024)
		{
			close(fd);
			ereport(ERROR, (errmsg("phasevec: the reader at %s answered more than 64 MB", path)));
		}
	}
	close(fd);
	if (out.len == 0 || out.data[out.len - 1] != '\n')
		ereport(ERROR, (errmsg("phasevec: the reader at %s closed without a whole answer", path)));
	out.data[--out.len] = '\0';
	PG_RETURN_TEXT_P(cstring_to_text_with_len(out.data, out.len));
}

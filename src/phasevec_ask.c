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
extern bool phasevec_delta_cache;	/* phasevec_ivf.c */

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
	DefineCustomBoolVariable("phasevec.delta_cache",
							 "Keep the coarse index's delta between questions (0.11.0)",
							 "Off: every question reads the delta again, as before 0.11.0. The kept copy is used only while no write to readings or ivf_dirty has committed since it was read.",
							 &phasevec_delta_cache, true, PGC_USERSET, 0, NULL, NULL, NULL);
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

/*
 * One line to <phasevec.socket_dir>/<watch><suffix> and its answer: up to the first newline (the reader,
 * phasevec._ask) or up to a blank line (phasevec-npu, phasevec._npu_ask: one line per result). The watch
 * name is the file name, checked against [A-Za-z0-9_.-]; a server that is down, slow or gone is an ERROR.
 */
static text *
hablar(const char *watch, const char *req, const char *suffix, bool hasta_vacia, const char *quien, const char *pista)
{
	char		path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
	struct sockaddr_un addr;
	StringInfoData out;
	TimestampTz deadline;
	size_t		len = strlen(req), sent = 0;
	int			fd;
	int			plen;
	size_t		slen;

	for (const char *c = watch; *c; c++)
		if (!(isalnum((unsigned char) *c) || *c == '_' || *c == '.' || *c == '-'))
			ereport(ERROR, (errmsg("phasevec: \"%s\" is not a watch name a socket can carry", watch)));
	if (*watch == '\0' || *watch == '.')
		ereport(ERROR, (errmsg("phasevec: \"%s\" is not a watch name a socket can carry", watch)));
	if (strchr(req, '\n'))
		ereport(ERROR, (errmsg(hasta_vacia ? "phasevec: a request is one line" : "phasevec: a request is one JSON line")));
	if (socket_dir && *socket_dir)
		plen = snprintf(path, sizeof path, "%s/%s%s", socket_dir, watch, suffix);
	else
		plen = snprintf(path, sizeof path, "/run/user/%d/phasevec/%s%s", (int) geteuid(), watch, suffix);
	if (plen >= (int) sizeof path)
		ereport(ERROR, (errmsg("phasevec: the socket path for watch \"%s\" is too long", watch)));

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	slen = strlcpy(addr.sun_path, path, sizeof addr.sun_path);
	if (slen >= sizeof addr.sun_path)
		ereport(ERROR, (errmsg("phasevec: the socket path for watch \"%s\" is too long", watch)));
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
			ereport(ERROR, (errmsg("phasevec: the %s of watch \"%s\" is not reachable at %s: %s", quien, watch, path, strerror(e)),
							errhint("%s", pista)));
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
			ereport(ERROR, (errmsg("phasevec: sending to the %s at %s: %m", quien, path)));
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
			ereport(ERROR, (errmsg("phasevec: reading from the %s at %s: %m", quien, path)));
		}
		if (r == 0)
			break;
		appendBinaryStringInfo(&out, buf, (int) r);
		if (!hasta_vacia && out.len > 0 && out.data[out.len - 1] == '\n')
			break;
		if (hasta_vacia && ((out.len == 1 && out.data[0] == '\n') ||
							(out.len >= 2 && out.data[out.len - 1] == '\n' && out.data[out.len - 2] == '\n')))
			break;
		if (out.len > 64 * 1024 * 1024)
		{
			close(fd);
			ereport(ERROR, (errmsg("phasevec: the %s at %s answered more than 64 MB", quien, path)));
		}
	}
	close(fd);
	if (out.len == 0 || out.data[out.len - 1] != '\n')
		ereport(ERROR, (errmsg("phasevec: the %s at %s closed without a whole answer", quien, path)));
	out.data[--out.len] = '\0';
	if (hasta_vacia && out.len > 0 && out.data[out.len - 1] == '\n')
		out.data[--out.len] = '\0';
	return cstring_to_text_with_len(out.data, out.len);
}

PG_FUNCTION_INFO_V1(phasevec_ask);
Datum
phasevec_ask(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(hablar(text_to_cstring(PG_GETARG_TEXT_PP(0)), text_to_cstring(PG_GETARG_TEXT_PP(1)),
							".sock", false, "reader",
							psprintf("Start it: systemctl --user start phasevec-lector-...@%s", text_to_cstring(PG_GETARG_TEXT_PP(0)))));
}

/*
 * 0.12.0: phasevec._npu_ask(watch, "k v0,...,v255") asks phasevec-npu, the server that keeps the watch's
 * copy on the NPU, at <phasevec.socket_dir>/<watch>.npu.sock. One line per result, "key<TAB>score<TAB>hash",
 * up to a blank line. phasevec.find_npu() validates and completes what it says; nothing else calls this.
 */
PG_FUNCTION_INFO_V1(phasevec_npu_ask);
Datum
phasevec_npu_ask(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(hablar(text_to_cstring(PG_GETARG_TEXT_PP(0)), text_to_cstring(PG_GETARG_TEXT_PP(1)),
							".npu.sock", true, "NPU server",
							psprintf("Start it: phasevec-npu --vigia %s ...", text_to_cstring(PG_GETARG_TEXT_PP(0)))));
}

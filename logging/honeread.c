/*
 * honeread - Example reader for hone character device
 *
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See ../src/LICENSE for the full text of the license.
 * See ../src/DISCLAIMER for additional disclaimers.
 *
 * Author: Brandon Carpenter
 *
 * honeread is a rewrite of honelogd. The SysV daemon features were
 * removed in favor of new-style daemon behavior used in systemd. Those
 * requiring SysV behavior should use honeread with start-stop-daemon.
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>
#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "honeevent.h"


#define DEV_PATH "/dev/hone"


static sig_atomic_t done = 0;
static sig_atomic_t restart = 0;


static void sighandler(int signum)
{
	switch(signum) {
		case SIGHUP:
			if (!restart)
				restart = 1;
			break;
		case SIGINT: case SIGTERM:
			done++;
			if (done > 3)
				exit(EX_OK);
			break;
		default:
			break;
	}
}


static int log_stderr(const char *format, ...)
{
	int result;
	va_list args;

	va_start(args, format);
	result = vdprintf(STDERR_FILENO, format, args);
	va_end(args);
	return result;
}


static int nolog(const char *format, ...)
{
	return 0;
}


static int (*verbose1)(const char *format, ...) = nolog;
static int (*verbose2)(const char *format, ...) = nolog;
static int (*verbose3)(const char *format, ...) = nolog;


static int parse_unsigned_int(unsigned int *value, const char *str)
{
	unsigned long tmp;
	char *end;

	tmp = strtoul(str, &end, 10);
	if (!*str || *end || (tmp > UINT32_MAX && tmp != -1))
		return -1;
	*value = tmp == -1 ? UINT32_MAX : (unsigned int) tmp;
	return 0;
}


const char *argp_program_version = "honeread 0.9";
const char *argp_program_bug_address =
		"Brandon Carpenter <brandon.carpenter@pnnl.gov>";


int main(int argc, char *argv[])
{
	int out_fd = -1, use_splice = 1, truncate = O_TRUNC, verboseness = 0;
	char *buf = NULL, *dev_path = DEV_PATH, *out_path = NULL;
	int restart_requested, dev_fd, pipe_in, pipe_out, pipe_fd[2];
	ssize_t n, m;
	unsigned int snaplen = 0, buflen = 8192;
	ssize_t (*read_dev)(void);
	ssize_t (*write_out)(void);
	
	struct argp_option options[] = {
		{"append", 'a', 0, 0, "append new records instead of overwriting"},
		{"device", 'd', "DEVICE", 0, "read events from DEVICE (default: " DEV_PATH ")"},
		{"buflen", 'l', "BYTES", 0, "set buffer length; implies -n (default: 8192)"},
		{"no-splice", 'n', 0, 0, "use read()/write() instead of splice"},
		{"quiet", 'q', 0, 0, "decrease verboseness of debug output"},
		{"snaplen", 's', "BYTES", 0, "set maximum packet capture size to BYTES bytes"},
		{"verbose", 'v', 0, 0, "increase verboseness of debug output"},
		{0},
	};

	error_t parse_opt(int key, char *arg, struct argp_state *state)
	{
		switch (key) {
		case 'a':
			truncate = 0;
			break;
		case 'd':
			dev_path = arg;
			break;
		case 'l':
			if (parse_unsigned_int(&buflen, arg))
				argp_error(state, "invalid buflen: %s\n", arg);
			use_splice = 0;
			break;
		case 'n':
			use_splice = 0;
			break;
		case 'q':
			verboseness--;
			break;
		case 's':
			if (parse_unsigned_int(&snaplen, arg))
				argp_error(state, "invalid snaplen: %s\n", arg);
			break;
		case 'v':
			verboseness++;
			break;
		case ARGP_KEY_ARG:
			if (!state->arg_num)
				out_path = arg;
			else
				return ARGP_ERR_UNKNOWN;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
		}
		return 0;
	}

	struct argp argp = {options, parse_opt, "[OUTPUT_FILE]",
			"Log Hone events to a file.", NULL, NULL, NULL};

	if (argp_parse(&argp, argc, argv, 0, NULL, NULL))
		err(EX_OSERR, "argp_parse() failed");

	if (verboseness > 0)
		verbose1 = log_stderr;
	if (verboseness > 1)
		verbose2 = log_stderr;
	if (verboseness > 2)
		verbose3 = log_stderr;

	verbose2("Options:\n");
	verbose2("   buffer size: ");
	if (use_splice)
		verbose2("unused\n");
	else
		verbose2("%u\n", buflen);
	verbose2("   input device: %s\n", dev_path);
	verbose2("   output file: %s\n", out_path ?: "<standard output>");
	verbose2("   snaplen: %u\n", snaplen);
	verbose2("   use splice: %s\n", use_splice ? "yes" : "no");
	verbose2("   verbosity level: %d\n", verboseness);

	if (verboseness > 3)
		err(EX_USAGE, "verboseness limit exceeded");

	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	ssize_t splice_read(void)
	{
		return splice(dev_fd, NULL, pipe_in, NULL, 65536, 0);
	}

	ssize_t splice_write(void)
	{
		return splice(pipe_out, NULL, out_fd, NULL, n, 0);
	}

	ssize_t conventional_read(void)
	{
		return read(dev_fd, buf, buflen);
	}

	ssize_t conventional_write(void)
	{
		return write(out_fd, buf, n);
	}

	if (use_splice) {
		if (pipe(pipe_fd))
			err(EX_OSERR, "pipe() failed");
		pipe_out = pipe_fd[0];
		pipe_in = pipe_fd[1];
		read_dev = splice_read;
		write_out = splice_write;
	} else {
		if (!(buf = (typeof(buf)) malloc(buflen)))
			err(EX_OSERR, "malloc() failed");
		read_dev = conventional_read;
		write_out = conventional_write;
	}

	if ((dev_fd = open(dev_path, O_RDONLY, 0)) == -1)
		err(EX_NOINPUT, "open() failed on %s", dev_path);
	if (snaplen && ioctl(dev_fd, HEIO_SET_SNAPLEN, snaplen) == -1)
		err(EX_IOERR, "set snaplen ioctl() failed");

	void close_log(void)
	{
		if (close(out_fd))
			err(EX_OSERR, "close() failed on %s", out_path);
		out_fd = -1;
	}

restart:
	restart = 0;
	restart_requested = 0;

	if (out_fd != -1)
		close_log();
	if (!out_path || !strcmp(out_path, "-")) {
		if ((out_fd = dup(STDOUT_FILENO)) == -1)
			err(EX_CANTCREAT, "dup() failed on stdout");
	} else {
		if ((out_fd = open(out_path,
					O_WRONLY | O_CREAT | O_LARGEFILE | truncate, 00664)) == -1)
			err(EX_CANTCREAT, "open() failed on %s", out_path);
		if (!truncate && lseek(out_fd, 0, SEEK_END) == (off_t) -1)
			err(EX_OSERR, "error seeking to end of output file");
	}

	if (use_splice) {
		int is_fifo = 0;
		struct stat st;

		if (fstat(out_fd, &st))
			warn("fstat() failed");
		else
			is_fifo = S_ISFIFO(st.st_mode);
		pipe_in = is_fifo ? out_fd : pipe_fd[1];

		verbose2("output file is%s a FIFO\n", is_fifo ? "" : " not");
	}

	for (;;) {
		if ((restart || done) && !restart_requested) {
			if (ioctl(dev_fd, HEIO_RESTART) == -1)
				err(EX_OSERR, "reset ioctl() failed");
			verbose1("Requesting device restart.\n");
			restart_requested = 1;
		}

		if ((n = read_dev()) == -1) {
			if (errno != EINTR && errno != EAGAIN)
				err(EX_OSERR, "reading from device failed");
			continue;
		}

		if (!n) {
			verbose1("Device restarted.\n");
			if (done || ioctl(dev_fd, HEIO_GET_AT_HEAD) <= 0)
				break;
			verbose1("Reopening log file.\n");
			goto restart;
		}

		verbose3("Read %ld bytes\n", n);
		if (out_fd == pipe_in)  /* spliced directly to FIFO */
			continue;

		while (n > 0) {
			if ((m = write_out()) == -1) {
				if (errno != EINTR && errno != EAGAIN)
					err(EX_OSERR, "writing to output failed");
				continue;
			}
			verbose3("Wrote %ld bytes\n", m);
			n -= m;
		}
	}

	close_log();
	close(dev_fd);
	close(pipe_fd[0]);
	close(pipe_fd[1]);
	free(buf);

	exit(EX_OK);
}


/*
 * honelogd - Log daemon for hone character device
 *
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See ../src/LICENSE for the full text of the license.
 * See ../src/DISCLAIMER for additional disclaimers.
 *
 * Author: Brandon Carpenter
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <sys/stat.h>
#include <sys/ioctl.h>
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
#include <syslog.h>
#include <signal.h>

#include "honeevent.h"


#define DAEMON_NAME "honelogd"
#define PID_PATH "/var/run/" DAEMON_NAME ".pid"
#define DEV_PATH "/dev/hone"
#define LOG_PATH "/var/log/hone/hone"


static void stdlog(int priority, const char *format, ...);

static char *log_path = LOG_PATH;
static void (*log_msg)(int priority, const char *format, ...) = stdlog;

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


static void stdlog(int priority, const char *format, ...)
{
	va_list args;

	va_start(args, format);

	if (priority & LOG_INFO) {
		vprintf(format, args);
		fflush(stdout);
	} else {
		fprintf(stderr, "%s: error: ", program_invocation_name);
		vfprintf(stderr, format, args);
		fflush(stderr);
	}

	va_end(args);
}


static void daemon_exit(void)
{
	log_msg(LOG_INFO, "daemon proccess with pid %d stopped\n", getpid());
	if (!access(PID_PATH, F_OK)) {
		if (unlink(PID_PATH))
			log_msg(LOG_ERR, "error removing pid file: %m: %s\n", PID_PATH);
	}
}


static void daemonize(const char *pid_path)
{
	pid_t pid, sid;

	/* Fork the daemon process */
	pid = fork();
	if (pid < 0) {
		log_msg(LOG_ERR, "fork() failed: %m\n");
		exit(EX_OSERR);
	} else if (pid > 0) {
		exit(EX_OK);
	}

	/* Get pid of child (current) process */
	pid = getpid();

	/* Change the file mode mask */
	umask(0022);

	openlog(DAEMON_NAME, 0, LOG_DAEMON);
	log_msg = syslog;

	/* Create a new session ID for the daemon process */
	sid = setsid();
	if (sid < 0) {
		log_msg(LOG_ERR, "setsid() failed: %m\n");
		exit(EX_OSERR);
	}

	/* Change the current working directory */
	if (chdir("/") < 0) {
		log_msg(LOG_ERR, "chdir() failed: %m: /\n");
		exit(EX_OSERR);
	}

	/* Close standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* Write pid file */
	{
		FILE *file = fopen(pid_path, "w");
		if (file) {
			if (fprintf(file, "%d", pid) < 0)
				log_msg(LOG_ERR, "%s: error writing pid file: %m\n", pid_path);
			fclose(file);
		} else {
			log_msg(LOG_ERR, "%s: error opening pid file: %m\n", pid_path);
		}
	}

	log_msg(LOG_INFO, "daemon proccess started with pid %d\n", pid);
	atexit(daemon_exit);
}


const char *argp_program_version = "honelogd 0.2";
const char *argp_program_bug_address =
		"Brandon Carpenter <brandon.carpenter@pnnl.gov>";


int main(int argc, char *argv[])
{
	int rc, n, restart_requested, fd = -1, background = 0;
	unsigned int snaplen = 0;
	char *dev_path = DEV_PATH, *pid_path = PID_PATH;
	FILE *log_file = NULL;
	char *mode = "w";
	char buf[8192];

	struct argp_option options[] = {
		{"append", 'a', 0, 0, "open output in append mode"},
		{"background", 'b', 0, 0, "background (daemonize) process after starting"},
		{"device", 'd', "DEVICE", 0, "read events from DEVICE (default: " DEV_PATH ")"},
		{"output", 'o', "FILE", 0, "write events to FILE (default: " LOG_PATH ")"},
		{"pid-file", 'p', "FILE", 0, "write process ID to FILE (default: " PID_PATH ")"},
		{"snaplen", 's', "BYTES", 0, "set maximum packet capture size to BYTES bytes"},
		{0},
	};

	error_t parse_opt(int key, char *arg, struct argp_state *state)
	{
		switch (key) {
		case 'a':
			mode = "a";
			break;
		case 'b':
			background = 1;
			break;
		case 'd':
			dev_path = arg;
			break;
		case 'o':
			log_path = arg;
			break;
		case 'p':
			pid_path = arg;
			break;
		case 's':
		{
			unsigned long tmp;
			char *end;
			tmp = strtoul(arg, &end, 10);
			if (!*arg || *end || (tmp > UINT32_MAX && tmp != -1))
				argp_error(state, "invalid snaplen: %s\n", arg);
			snaplen = tmp == -1 ? UINT32_MAX : (unsigned int) tmp;
			break;
		}
		case ARGP_KEY_ARG:
			argp_error(state, "too many arguments");
		default:
			return ARGP_ERR_UNKNOWN;
		}
		return 0;
	}

	struct argp argp = {options, parse_opt, NULL,
			"Log Hone events to a file.", NULL, NULL, NULL};

	if ((rc = argp_parse(&argp, argc, argv, 0, NULL, NULL)))
		err(EX_OSERR, NULL);

	/*
	printf("OPTIONS: background=%d, device=\"%s\", mode=\"%s\", "
			"output=\"%s\", pid-file=\"%s\", snaplen=%u\n",
			background, dev_path, mode, log_path, pid_path, snaplen);
	exit(EX_OK);
	*/

	if (background)
		daemonize(pid_path);

	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	void close_log(void)
	{
		if (fclose(log_file))
			log_msg(LOG_ERR, "%s: fclose() failed: %m\n", log_path, rc);
		log_file = NULL;
	}

	fd = open(dev_path, O_RDONLY, 0);
	if (fd == -1) {
		log_msg(LOG_ERR, "%s: open() failed: %m:\n", dev_path);
		exit(EX_NOINPUT);
	}
	if (snaplen && ioctl(fd, HEIO_SET_SNAPLEN, snaplen) == -1) {
		log_msg(LOG_ERR, "ioctl() failed: %m\n");
		exit(EX_IOERR);
	}

restart:
	restart = 0;
	restart_requested = 0;

	if (log_file)
		close_log();
	if (!strcmp(log_path, "-") && !(log_file = fdopen(STDOUT_FILENO, "w"))) {
		log_msg(LOG_ERR, "stdout: fdopen() failed: %m\n");
		exit(EX_CANTCREAT);
	} else if (!(log_file = fopen(log_path, mode))) {
		log_msg(LOG_ERR, "%s: fopen() failed: %m\n", log_path);
		exit(EX_CANTCREAT);
	}
	mode = "a";

	for (;;) {
		if ((restart || done) && !restart_requested) {
			if (ioctl(fd, HEIO_RESTART) == -1) {
				log_msg(LOG_ERR, "ioctl() failed: %m\n");
				exit(EX_IOERR);
			}
			log_msg(LOG_DEBUG, "Requesting device restart.\n");
			restart_requested = 1;
		}

		if ((n = read(fd, buf, sizeof(buf))) == -1) {
			if (errno != EINTR && errno != EAGAIN) {
				log_msg(LOG_ERR, "%s: read failure: %m\n", dev_path);
				goto out;
			}
			continue;
		}

		if (!n) {
			log_msg(LOG_DEBUG, "Device restarted.\n");
			if (done || ioctl(fd, HEIO_GET_AT_HEAD) <= 0)
				goto out;
			log_msg(LOG_DEBUG, "Reopening log file.\n");
			goto restart;
		}

		while ((n -= fwrite(buf, 1, n, log_file))) {
			if (ferror(log_file) && (errno == EINTR || errno == EAGAIN))
				continue;
			log_msg(LOG_ERR, "%s: write failure: %m\n", log_path);
			goto out;
		}
	}

out:
	close_log();
	if (fd != -1)
		close(fd);

	exit(done ? EX_OK : EX_SOFTWARE);
}


/*
 * honelogd - Log daemon for hone character device
 *
 * Copyright (C) 2011 Battelle Memorial Institute <http://www.battelle.org>
 *
 * Author: Brandon Carpenter
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _FILE_OFFSET_BITS 64

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <getopt.h>
#include <signal.h>

#include <arpa/inet.h>

#include "honeevent.h"

#define DAEMON_NAME "honelogd"
#define PID_PATH "/var/run/" DAEMON_NAME ".pid"
#define DEV_PATH "/dev/hone"
#define LOG_PATH "/var/log/hone/hone"

static void stdlog(int priority, const char *format, ...);

static const char *daemon_name = DAEMON_NAME;
static const char *exe_name = DAEMON_NAME;
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
				exit(EXIT_SUCCESS);
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
		fprintf(stderr, "%s: error: ", exe_name);
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
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Get pid of child (current) process */
	pid = getpid();

	/* Change the file mode mask */
	umask(0022);

	openlog(daemon_name, 0, LOG_DAEMON);
	log_msg = syslog;

	/* Create a new session ID for the daemon process */
	sid = setsid();
	if (sid < 0) {
		log_msg(LOG_ERR, "setsid() failed: %m\n");
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory */
	if (chdir("/") < 0) {
		log_msg(LOG_ERR, "chdir() failed: %m: /\n");
		exit(EXIT_FAILURE);
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

static void print_tip(void)
{
	printf("Try `%s --help' for more information.\n", exe_name);
}

static void print_help(void)
{
	printf(
"Usage: %s [OPTION]...\n"
"Log Hone packet/process data to a file.\n\n"
"Mandatory arguments to long options are mandatory for short options too.\n"
"  -a, --append           append new records to log file instead of overwriting\n"
"  -b, --background       background (daemonize) process after starting\n"
"  -e, --event-file=FILE  read events from FILE [%s]\n"
"  -f, --log-file=FILE    write events to FILE [%s]\n"
"  -p, --pid-file=FILE    write the process ID to FILE [%s]\n"
"  -s, --snaplen=LENGTH   set the maximum packet capture size to LENGTH\n"
"  -h, --help             display this help and exit\n"
	, exe_name, DEV_PATH, LOG_PATH, PID_PATH);
}

int main(int argc, char *argv[])
{
	int rc, n, restart_requested, fd = -1, background = 0;
	unsigned int snaplen = 0;
	char *dev_path = DEV_PATH, *pid_path = PID_PATH;
	FILE *log_file = NULL;
	char *mode = "w";
	char buf[8192];
 
	/* Get the base name of the executable */
	exe_name = argv[0];
	daemon_name = exe_name + strlen(exe_name);
	while (daemon_name > argv[0] && *(daemon_name - 1) != '/')
		daemon_name--;

	/* Parse command-line options */
	while (1) {
		static struct option long_options[] = {
			{"append", no_argument, 0, 'a'},
			{"background", no_argument, 0, 'b'},
			{"event-file", required_argument, 0, 'e'},
			{"help", no_argument, 0, 'h'},
			{"log-file", required_argument, 0, 'f'},
			{"pid-file", required_argument, 0, 'p'},
			{"snaplen", required_argument, 0, 's'},
		};
		int c, option_index;

		c = getopt_long(argc, argv, "abe:f:hp:s:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				mode = "a";
				break;
			case 'b':
				background = 1;
				break;
			case 'e':
				dev_path = optarg;
				break;
			case 'f':
				log_path = optarg;
				break;
			case 'h':
				print_help();
				exit(EXIT_FAILURE);
			case '?':
				print_tip();
				exit(EXIT_FAILURE);
			case 'p':
				pid_path = optarg;
				break;
			case 's':
			{
				unsigned long tmp;
				char *end;
				tmp = strtoul(optarg, &end, 10);
				if (!*optarg || *end || (tmp > UINT32_MAX && tmp != -1)) {
					fprintf(stderr, "%s: invalid snaplen: %s\n", exe_name, optarg);
					exit(EXIT_FAILURE);
				}
				snaplen = tmp == -1 ? UINT32_MAX : (unsigned int) tmp;
				break;
			}
			default:
				fprintf(stderr, "invalid option -- %c\n", c);
				print_tip();
				exit(EXIT_FAILURE);
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "%s: too many arguments\n", exe_name);
		print_tip();
		exit(EXIT_FAILURE);
	}

	/*
	printf("OPTIONS: background %d event-file %s log-file %s pid-file %s\n",
			background, dev_path, log_path, pid_path);
	exit(EXIT_SUCCESS);
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
		exit(EXIT_FAILURE);
	}
	if (snaplen && ioctl(fd, HEIO_SET_SNAPLEN, &snaplen) == -1) {
		log_msg(LOG_ERR, "ioctl() failed: %m\n");
		exit(EXIT_FAILURE);
	}

restart:
	restart = 0;
	restart_requested = 0;

	if (log_file)
		close_log();
	if (!strcmp(log_path, "-") && !(log_file = fdopen(STDOUT_FILENO, "w"))) {
		log_msg(LOG_ERR, "stdout: fdopen() failed: %m\n");
		exit(EXIT_FAILURE);
	} else if (!(log_file = fopen(log_path, mode))) {
		log_msg(LOG_ERR, "%s: fopen() failed: %m\n", log_path);
		exit(EXIT_FAILURE);
	}
	mode = "a";

	for (;;) {
		if ((restart || done) && !restart_requested) {
			if (ioctl(fd, HEIO_RESTART) == -1) {
				log_msg(LOG_ERR, "ioctl() failed: %m\n");
				exit(EXIT_FAILURE);
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

	exit(done ? EXIT_SUCCESS : EXIT_FAILURE);
}


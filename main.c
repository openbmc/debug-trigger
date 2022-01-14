// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2021 IBM Corp.

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <linux/reboot.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct debug_source_ops {
	int (*poll)(void *ctx, char *op);
};

struct debug_source {
	const struct debug_source_ops *ops;
	void *ctx;
};

struct debug_source_basic {
	int source;
};

struct debug_sink_ops {
	void (*debug)(void *ctx);
	void (*reboot)(void *ctx);
};

struct debug_sink {
	const struct debug_sink_ops *ops;
	void *ctx;
};

struct debug_sink_sysrq {
	int sink;
};

static void sysrq_sink_debug(void *ctx)
{
	struct debug_sink_sysrq *sysrq = ctx;
	static const char action = 'c';
	ssize_t rc;

	sync();

	if ((rc = write(sysrq->sink, &action, sizeof(action))) == sizeof(action))
		return;

	if (rc == -1) {
		warn("Failed to execute debug command");
	} else {
		warnx("Failed to execute debug command: %zd", rc);
	}
}

static void sysrq_sink_reboot(void *ctx __attribute__((unused)))
{
	ssize_t rc;

	sync();

	if ((rc = reboot(LINUX_REBOOT_CMD_RESTART))) {
		if (rc == -1)
			warn("Failed to reboot BMC");
		else
			warnx("Failed to reboot BMC: %zd", rc);
	}
}

const struct debug_sink_ops sysrq_sink_ops = {
	.debug = sysrq_sink_debug,
	.reboot = sysrq_sink_reboot,
};

static int basic_source_poll(void *ctx, char *op)
{
	struct debug_source_basic *basic = ctx;
	ssize_t ingress;

	if ((ingress = read(basic->source, op, 1)) != 1) {
		if (ingress < 0) {
			warn("Failed to read from basic source");
			return -errno;
		}

		/* Unreachable */
		errx(EXIT_FAILURE, "Bad read, requested 1 got %zd", ingress);
	}

	return 0;
}

const struct debug_source_ops basic_source_ops = {
	.poll = basic_source_poll,
};

static int process(struct debug_source *source, struct debug_sink *sink)
{
	char command;
	int rc;

	while (!(rc = source->ops->poll(source->ctx, &command))) {
		switch (command) {
		case 'D':
			sink->ops->debug(sink->ctx);
			break;
		case 'R':
			sink->ops->reboot(sink->ctx);
			break;
		default:
			warnx("Unexpected command: 0x%02x (%c)", command, command);
		}
	}

	if (rc < 0)
		warnx("Failed to poll source: %s", strerror(-rc));

	return rc;
}

int main(int argc, char * const argv[])
{
	struct debug_source_basic basic;
	struct debug_sink_sysrq sysrq;
	struct debug_source source;
	struct debug_sink sink;
	char devnode[PATH_MAX];
	const char *sink_name;
	char *devid;
	int sourcefd;
	int sinkfd;

	sink_name = NULL;
	while (1) {
		static struct option long_options[] = {
			{"sink", required_argument, 0, 's'},
			{0, 0, 0, 0},
		};
		int c;

		c = getopt_long(argc, argv, "", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 's':
			sink_name = optarg;
			break;
		default:
			break;
		}
	}

	sourcefd = 0;
	sinkfd = 1;

	if (optind < argc) {
		char devpath[PATH_MAX];

		strncpy(devpath, argv[optind], sizeof(devpath));
		devpath[PATH_MAX - 1] = '\0';
		devid = basename(devpath);

		strncpy(devnode, "/dev/", sizeof(devnode));
		strncat(devnode, devid, sizeof(devnode));
		devnode[PATH_MAX - 1] = '\0';

		if ((sourcefd = open(devnode, O_RDONLY)) == -1)
			err(EXIT_FAILURE, "Failed to open %s", devnode);

		optind++;
	}

	if (!sink_name || !strcmp("sysrq", sink_name)) {
		if (optind < argc) {
			if ((sinkfd = open(argv[optind], O_WRONLY)) == -1)
				err(EXIT_FAILURE, "Failed to open %s", argv[optind]);

			optind++;
		}

		sysrq.sink = sinkfd;
		sink.ops = &sysrq_sink_ops;
		sink.ctx = &sysrq;
	}

	if (optind < argc)
		err(EXIT_FAILURE, "Found %d unexpected arguments", argc - optind);

	basic.source = sourcefd;
	source.ops = &basic_source_ops;
	source.ctx = &basic;

	if (process(&source, &sink) < 0)
		errx(EXIT_FAILURE, "Failure while processing command stream");

	return 0;
}

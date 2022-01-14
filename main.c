// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2021 IBM Corp.

#include "config.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <linux/reboot.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

struct sd_bus;
struct sd_event;

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

struct debug_source_dbus {
	struct sd_bus *bus;
#define DBUS_SOURCE_PFD_SOURCE	0
#define DBUS_SOURCE_PFD_DBUS	1
	struct pollfd pfds[2];
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

struct debug_sink_dbus {
	struct sd_bus *bus;
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

const struct debug_sink_ops sysrq_sink_ops = {
	.debug = sysrq_sink_debug,
	.reboot = sysrq_sink_reboot,
};

const struct debug_source_ops basic_source_ops = {
	.poll = basic_source_poll,
};

#if HAVE_SYSTEMD
#include <systemd/sd-bus.h>

static void dbus_sink_reboot(void *ctx);
static int dbus_sink_dump_progress(sd_bus_message *m, void *userdata __attribute__((unused)),
				   sd_bus_error *ret_error)
{
	const char *status;
	const char *iface;
	int rc;

	// sa{sv}as
	rc = sd_bus_message_read_basic(m, 's', &iface);
	if (rc < 0) {
		warnx("Failed to extract interface from PropertiesChanged signal: %s",
		      strerror(-rc));
		return rc;
	}

	/* Bail if it's not an update to the Progress interface */
	if (strcmp(iface, "xyz.openbmc_project.Common.Progress"))
		return 0;

	rc = sd_bus_message_enter_container(m, 'a', "{sv}");
	if (rc < 0)
		return rc;

	if (!rc)
		return 0;

	status = NULL;
	while (1) {
		const char *member;

		rc = sd_bus_message_enter_container(m, 'e', "sv");
		if (rc < 0)
			return rc;

		if (!rc)
			break;

		rc = sd_bus_message_read_basic(m, 's', &member);
		if (rc < 0) {
			warnx("Failed to extract member name from PropertiesChanged signal: %s",
			      strerror(-rc));
			return rc;
		}

		if (!strcmp(member, "Status")) {
			rc = sd_bus_message_enter_container(m, 'v', "s");
			if (rc < 0) {
				warnx("Failed to enter variant container in PropertiesChanged signal: %s",
				      strerror(-rc));
				return rc;
			}

			if (!rc)
				goto exit_dict_container;

			rc = sd_bus_message_read_basic(m, 's', &status);
			if (rc < 0) {
				warnx("Failed to extract status value from PropertiesChanged signal: %s",
				      strerror(-rc));
				return rc;
			}

			sd_bus_message_exit_container(m);
		} else {
			rc = sd_bus_message_skip(m, "v");
			if (rc < 0) {
				warnx("Failed to skip variant for unrecognised member %s in PropertiesChanged signal: %s",
				      member, strerror(-rc));
				return rc;
			}
		}

exit_dict_container:
		sd_bus_message_exit_container(m);
	}

	sd_bus_message_exit_container(m);

	if (!status)
		return 0;

	printf("Dump progress on %s: %s\n", sd_bus_message_get_path(m), status);

	/* If we're finished with the dump, reboot the system */
	if (!strcmp(status, "xyz.openbmc_project.Common.Progress.OperationStatus.Completed"))
		dbus_sink_reboot(userdata);

	return 0;
}

static void dbus_sink_debug(void *ctx)
{
	sd_bus_error ret_error = SD_BUS_ERROR_NULL;
	struct debug_sink_dbus *dbus = ctx;
	sd_bus_message *reply;
	const char *path;
	char *status;
	int rc;

	/* Start a BMC dump */
	rc = sd_bus_call_method(dbus->bus,
				"xyz.openbmc_project.Dump.Manager",
				"/xyz/openbmc_project/dump/bmc",
				"xyz.openbmc_project.Dump.Create",
				"CreateDump",
				&ret_error,
				&reply, "a{sv}", 0);
	if (rc < 0) {
		warnx("Failed to call CreateDump: %s", strerror(-rc));
		return;
	}

	/* Extract the dump path */
	rc = sd_bus_message_read_basic(reply, 'o', &path);
	if (rc < 0) {
		warnx("Failed to extract dump object path: %s", strerror(-rc));
		goto cleanup_reply;
	}

	/* Watch for dump completion */
	rc = sd_bus_match_signal(dbus->bus,
				 NULL,
				 "xyz.openbmc_project.Dump.Manager",
				 path,
				 "org.freedesktop.DBus.Properties",
				 "PropertiesChanged",
				 dbus_sink_dump_progress,
				 ctx);
	if (rc < 0) {
		warnx("Failed to add signal match for progress status on dump object %s: %s",
		      path, strerror(-rc));
		goto cleanup_reply;
	}

	printf("Registered progress match on dump object %s\n", path);

	/* Now that the match is set up, check the current value in case we missed any updates */
	rc = sd_bus_get_property_string(dbus->bus,
					"xyz.openbmc_project.Dump.Manager",
					path,
					"xyz.openbmc_project.Common.Progress",
					"Status",
					&ret_error,
					&status);
	if (rc < 0) {
		warnx("Failed to get progress status property on dump object %s: %s",
		      path, strerror(-rc));
		goto cleanup_reply;
	}

	printf("Dump state for %s is currently %s\n", path, status);

	/* If we're finished with the dump, reboot the system */
	if (!strcmp(status, "xyz.openbmc_project.Common.Progress.OperationStatus.Completed")) {
		dbus_sink_reboot(ctx);
	}

cleanup_reply:
	sd_bus_message_unref(reply);
}

static void dbus_sink_reboot(void *ctx)
{
	sd_bus_error ret_error = SD_BUS_ERROR_NULL;
	struct debug_sink_dbus *dbus = ctx;
	sd_bus_message *reply;
	int rc;

	printf("Rebooting the system\n");

	rc = sd_bus_call_method(dbus->bus,
				"org.freedesktop.systemd1",
				"/org/freedesktop/systemd1",
				"org.freedesktop.systemd1.Manager",
				"Reboot",
				&ret_error,
				&reply,
				"");
	if (rc < 0) {
		warnx("Failed to call Reboot: %s", strerror(-rc));
	}
}

static int dbus_source_poll(void *ctx, char *op)
{
	struct debug_source_dbus *dbus = ctx;
	int rc;

	while (1) {
		if ((rc = poll(dbus->pfds, ARRAY_SIZE(dbus->pfds), -1)) < 0) {
			warn("Failed polling source fds");
			return -errno;
		}

		if (dbus->pfds[DBUS_SOURCE_PFD_SOURCE].revents) {
			ssize_t ingress;

			if ((ingress = read(dbus->pfds[DBUS_SOURCE_PFD_SOURCE].fd, op, 1)) != 1) {
				if (ingress < 0) {
					warn("Failed to read from basic source");
					return -errno;
				}

				errx(EXIT_FAILURE, "Bad read, requested 1 got %zd", ingress);
			}

			return 0;
		}

		if (dbus->pfds[DBUS_SOURCE_PFD_DBUS].revents) {
			if ((rc = sd_bus_process(dbus->bus, NULL)) < 0) {
				warnx("Failed processing inbound D-Bus messages: %s",
				      strerror(-rc));
				return rc;
			}
		}
	}
}
#else
static void dbus_sink_debug(void *ctx)
{
	warnx("%s: Configured without systemd, dbus sinks disabled", __func__);
}

static void dbus_sink_reboot(void *ctx)
{
	warnx("%s: Configured without systemd, dbus sinks disabled", __func__);
}

static int dbus_source_poll(void *ctx, char *op)
{
	errx(EXIT_FAILURE, "Configured without systemd, dbus sources disabled", __func__);
}
#endif

const struct debug_sink_ops dbus_sink_ops = {
	.debug = dbus_sink_debug,
	.reboot = dbus_sink_reboot,
};

const struct debug_source_ops dbus_source_ops = {
	.poll = dbus_source_poll,
};

static int process(struct debug_source *source, struct debug_sink *sink)
{
	char command;
	int rc;

	while (!(rc = source->ops->poll(source->ctx, &command))) {
		switch (command) {
		case 'D':
			printf("Debug action triggered\n");
			sink->ops->debug(sink->ctx);
			break;
		case 'R':
			printf("Reboot action triggered\n");
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
	struct debug_source_basic basic_source;
	struct debug_source_dbus dbus_source;
	struct debug_sink_sysrq sysrq_sink;
	struct debug_sink_dbus dbus_sink;
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
			err(EXIT_FAILURE, "Failed to open source %s", devnode);

		optind++;
	}

	if (!sink_name || !strcmp("sysrq", sink_name)) {
		if (optind < argc) {
			if ((sinkfd = open(argv[optind], O_WRONLY)) == -1)
				err(EXIT_FAILURE, "Failed to open sink %s", argv[optind]);

			optind++;
		}

		basic_source.source = sourcefd;
		source.ops = &basic_source_ops;
		source.ctx = &basic_source;

		sysrq_sink.sink = sinkfd;
		sink.ops = &sysrq_sink_ops;
		sink.ctx = &sysrq_sink;
	}

	if (sink_name && !strcmp("dbus", sink_name)) {
		sd_bus *bus;
		int rc;

		rc = sd_bus_open_system(&bus);
		if (rc < 0) {
			errx(EXIT_FAILURE, "Failed to connect to the system bus: %s",
			       strerror(-rc));
		}

		dbus_source.bus = bus;
		dbus_source.pfds[DBUS_SOURCE_PFD_SOURCE].fd = sourcefd;
		dbus_source.pfds[DBUS_SOURCE_PFD_SOURCE].events = POLLIN;
		dbus_source.pfds[DBUS_SOURCE_PFD_DBUS].fd = sd_bus_get_fd(bus);
		dbus_source.pfds[DBUS_SOURCE_PFD_DBUS].events = POLLIN;
		source.ops = &dbus_source_ops;
		source.ctx = &dbus_source;

		dbus_sink.bus = bus;
		sink.ops = &dbus_sink_ops;
		sink.ctx = &dbus_sink;
	}

	if (optind < argc)
		errx(EXIT_FAILURE, "Found %d unexpected arguments", argc - optind);

	if (!(source.ops && source.ctx))
		errx(EXIT_FAILURE, "Invalid source configuration");

	if (!(sink.ops && sink.ctx))
		errx(EXIT_FAILURE, "Unrecognised sink: %s", sink_name);

	if (process(&source, &sink) < 0)
		errx(EXIT_FAILURE, "Failure while processing command stream");

	return 0;
}

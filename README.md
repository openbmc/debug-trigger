# BMC Debug Trigger

`debug-trigger` listens for an external signal that the BMC is in some way
unresponsive. When the signal is received it triggers a crash to collect debug
data and reboots the system in the hope that it will recover.

## Trigger sources

`debug-trigger` implements a simple protocol over an LPC KCS device as its
trigger source.

## Debug actions

`debug-trigger` implements a single action once the trigger event is received,
which is to crash the kernel via `/proc/sysrq-trigger`. For systems with kdump
configured this results in collection of system state as context for why the
system was externally unresponsive.

## Failover

On systems with redundant BMCs, receiving `F` on the trigger source requests a
failover to the other BMC by calling `StartFailover` on the
`xyz.openbmc_project.Control.Failover` D-Bus interface, with the host as the
requester. Failover is only available with `--sink-actions=dbus`; with the
default `sysrq` sink actions the request is logged and ignored.

# Spinel CLI Reference

The Spinel CLI exposes the OpenThread configuration and management APIs running on an NCP build via a command line interface. Spinel CLI is primarily targeted for driving the automated continuous integration tests, and is suitable for manual experimentation with controlling OpenThread NCP instances. For a production grade host driver, see [wpantund]: https://github.com/openthread/wpantund.

Use the CLI to play with NCP builds of OpenThread on a Linux or Mac OS platform, including starting a basic tunnel interface to allow IPv6 applications to run on the HOST and use the Thread network.

The power of this tool is three fold:

1. As a path to add testing of the NCP in simulation to continuous integration
2. As a path to automated testing of testbeds running NCP firmware on hardware
3. As a simple debugging tool for NCP builds of OpenThread

## System Requirements

| OS     | Minimum Version  |
| ------ | ---------------- |
| Ubuntu | 14.04 Trusty     |
| Mac OS | 10.11 El Capitan |

| Language | Minimum Version |
| -------- | --------------- |
| Python   | 3.6.8           |

### Package installation

Install dependencies:

```
$ sudo apt install python3-pip
$ pip3 install --user pyserial ipaddress
```

Install Pyspinel:

```
# From pyspinel root
$ sudo python3 setup.py install
```

## Usage

### NAME

    spinel-cli.py - shell tool for controlling OpenThread NCP instances

### SYNOPSIS

    spinel-cli.py [-hupsnqv]

### DESCRIPTION

```
    -h, --help
    	Show this help message and exit

    -u <UART>, --uart=<UART>
       	Open a serial connection to the OpenThread NCP device
	where <UART> is a device path such as "/dev/ttyUSB0".

    -b <BAUDRATE>, --baudrate=<BAUDRATE>
        Specify a serial connection baudrate. By default set to 115200.

    --rtscts
        Enable the serial connection hardware flow control. By default disabled.

    -p <PIPE>, --pipe=<PIPE>
        Open a piped process connection to the OpenThread NCP device
        where <PIPE> is the command to start an emulator, such as
        "ot-ncp-ftd".  Spinel-cli will communicate with the child process
        via stdin/stdout.

    -s <SOCKET>, --socket=<SOCKET>
        Open a socket connection to the OpenThread NCP device
        where <SOCKET> is the port to open.
	This is useful for SPI configurations when used in conjunction
	with a spinel spi-driver daemon.
	Note: <SOCKET> will eventually map to hostname:port tuple.

    -n NODEID, --nodeid=NODEID
        The unique nodeid for the HOST and NCP instance.

    -q, --quiet
        Minimize debug and log output.

    -v, --verbose
        Maximize debug and log output.

    -d <DEBUG_LEVEL>, --debug=<DEBUG_LEVEL>
        Specify the debug level.

    --vendor-path
        Provide a custom location of the vendor package. If not specified, the
        default location will be used (the vendor package shipped with the
        pyspinel installation).
        Note: The vendor package location can also be specified with
        SPINEL_VENDOR_PATH environment variable.
```

## Quick start

The spinel-cli tool provides an intuitive command line interface, including all the standard OpenThread CLI commands, plus full history accessible by pressing the up/down keys, or searchable via ^R. There are a few commands that spinel-cli provides as well that aren't part of the standard set documented in the command reference section.

First, clone and build a simulated OpenThread NCP, as described in [How to build OpenThread](https://openthread.io/guides/build#how_to_build_openthread) on openthread.io. After cloning bootstrapping, build the `simulation` example:

```
$ make -f <path-to-openthread>/examples/Makefile-simulation
```

Then run the Pyspinel CLI, using the path to your simulated build:

```
$ cd <path-to-pyspinel>
$ spinel-cli.py -p <path-to-openthread>/output/x86_64-unknown-linux-gnu/bin/ot-ncp-ftd -n 1
Opening pipe to ../../examples/apps/ncp/ot-ncp-ftd 1
spinel-cli > version
OPENTHREAD/20180926-01310-g9fdcef20; SIMULATION; Feb 11 2020 14:09:56
Done
spinel-cli > panid 1234
Done
spinel-cli > ifconfig up
Done
spinel-cli > thread start
Done
spinel-cli > state
leader
Done
spinel-cli >
```

## Running the NCP tests

The OpenThread automated test suite can be run against any of the following node types by passing the NODE_TYPE environment variable:

| NODE_TYPE | Description |
| --- | --- |
| sim (default) | Runs against ot-cli posix emulator |
| ncp-sim | Runs against ot-ncp posix emulator with spinel-cli |
| soc | Runs against CLI firmware on a device connected via /dev/ttyUSB<nodeid> |

### Manual run of NCP thread-cert test

```
# From top-level of openthread tree
$ NODE_TYPE=ncp-sim ./script/test clean build
$ NODE_TYPE=ncp-sim ./script/test cert tests/scripts/thread-cert/Cert_5_1_02_ChildAddressTimeout.py
```

### Run entire NCP thread-cert suite

```
# From top-level of openthread tree
$ NODE_TYPE=ncp-sim ./script/test cert_suite tests/scripts/thread-cert/Cert_*
```

## Command reference

### OpenThread CLI commands

The primary intent of spinel-cli is to support the exact syntax and output of the OpenThread CLI command set in order to seamlessly reapply the thread-cert automated test suite against NCP targets.

See [cli module][1] for more information on these commands.

[1]: https://github.com/openthread/openthread/blob/main/src/cli/README.md

### Diagnostics CLI commands

The Diagnostics module is enabled only when building OpenThread with the --enable-diag configure option.

See [diag module][2] for more information on these commands.

[2]: https://github.com/openthread/openthread/blob/main/src/core/diags/README.md

### NCP CLI commands

These commands extend beyond the core OpenThread CLI, and are specific to the spinel-cli tool for the purposes of debugging, access to NCP-specific Spinel parameters, and support of advanced configurations.

- [help](#help)
- [?](#help)
- [v](#v)
- [exit](#exit)
- [quit](#quit)
- [q](#quit)
- [clear](#clear)
- [history](#history)
- [h](#history)
- [debug](#debug)
- [debug-term](#debug-term)
- [ncp-tun](#ncp-tun)
- [ncp-ml64](#ncp-ml64)
- [ncp-ll64](#ncp-ll64)

#### help

Display help all top-level commands supported by spinel-cli.

```bash
spinel-cli > help

Available commands (type help <name> for more information):
============================================================
bufferinfo         extaddr       mode              releaserouterid
channel            extpanid      ncp-filter        reset
child              h             ncp-ll64          rloc16
childmax           help          ncp-ml64          route
childtimeout       history       ncp-raw           router
clear              ifconfig      ncp-tun           routerdowngradethreshold
commissioner       ipaddr        netdataregister   routerselectionjitter
contextreusedelay  joiner        networkidtimeout  routerupgradethreshold
counters           keysequence   networkname       scan
debug              leaderdata    panid             state
debug-mem          leaderweight  parent            thread
diag               mac           ping              txpower
discover           macfilter     prefix            v
eidcache           networkkey    q                 vendor
exit               mfg           quit              version
```

#### help \<command\>

Display detailed help on a specific command.

```bash
spinel-cli > help version

version

    Print the build version information.

    > version
    OPENTHREAD/20180926-01310-g9fdcef20; SIMULATION; Feb 11 2020 14:09:56
    Done
```

#### v

Display version of spinel-cli tool.

```bash
spinel-cli > v
spinel-cli ver. 0.1.0
Copyright (c) 2016 The OpenThread Authors.
```

#### exit

Exit spinel-cli. CTRL+C may also be used.

#### quit

Exit spinel-cli. CTRL+C may also be used.

### clear

Clear screen.

#### history

Display history of most recent commands run.

```bash
spinel-cli > history
ping fd00::1
quit
help
history
```

#### debug

Get whether debug verbose output is enabled.

```bash
spinel-cli > debug
DEBUG_ENABLE = 0
```

#### debug \<enabled\>

Set whether debug verbose output is enabled.

spinel-cli > debug DEBUG_ENABLE = 0

```bash
spinel-cli > debug 1
DEBUG_ENABLE = 1
spinel-cli > version
PROP_VALUE_GET [tid=1]: NCP_VERSION
PROP_VALUE_IS [tid=1]: NCP_VERSION = 4f:50:45:4e:54:48:52:45:41:44:2f:32:30:31:38:30:39:32:36:2d:30:31:34:30:36:2d:67:63:33:30:33:64:30:66:63:3b:20:53:49:4d:55:4c:41:54:49:4f:4e:3b:20:4d:61:72:20:20:32:20:32:30:32:30:20:31:32:3a:31:37:3a:34:33
OPENTHREAD/20180926-01406-gc303d0fc; SIMULATION; Mar  2 2020 12:17:43
Done
```

#### debug-term

Get whether debug terminal title bar is enabled.

#### debug-term \<enabled\>

Set whether debug terminal title bar is enabled.

#### ncp-tun

Control sideband tunnel interface.

#### ncp-tun up

Bring up Thread TUN interface.

```bash
spinel-cli > ncp-tun up
Done
```

#### ncp-tun down

Bring down Thread TUN interface.

```bash
spinel-cli > ncp-tun down
Done
```

#### ncp-tun add \<ipaddr\>

Add an IPv6 address to the Thread TUN interface.

```bash
spinel-cli > ncp-tun add 2001::dead:beef:cafe
Done
```

#### ncp-tun del \<ipaddr\>

Delete an IPv6 address from the Thread TUN interface.

```bash
spinel-cli > ncp-tun del 2001::dead:beef:cafe
Done
```

#### ncp-tun ping \<ipaddr\> \[size\] \[count\] \[interval\]

Send an ICMPv6 Echo Request via a posix host system call.

```bash
spinel-cli > ncp-tun ping fdde:ad00:beef:0:558:f56b:d688:799
16 bytes from fdde:ad00:beef:0:558:f56b:d688:799: icmp_seq=1 hlim=64 time=28ms
```

#### ncp-ml64

Return the Mesh Local 64-bit IPv6 address for the node.

```
spinel-cli > ncp-ml64
fdde:ad00:beef:0:558:f56b:d688:799
Done
```

#### ncp-ll64

Return the Link Local 64-bit IPv6 address for the node.

## Vendor package

Extension of the Spinel CLI with custom properties and commands. This plugin-like extension adds vendor-specific commands and properties to pyspinel in a way that does not impact the implementation of core pyspinel functionalities.

The vendor package contains the following modules:

| MODULE | DESCRIPTION                                        |
| ------ | -------------------------------------------------- |
| vendor | Module that provides a specific vendor commands.   |
| const  | Module with constants for vendor spinel extension. |
| codec  | Module that provides a vendor property handlers.   |

Each module comes with an example that shows how to add specific vendor codecs and constants.

By default, pyspinel will use the vendor package shipped with pyspinel installation. You can provide a custom vendor package location with --vendor-path option or SPINEL_VENDOR_PATH environment variable.

### Vendor commands

The vendor package adds several vendor-specific pyspinel commands. Use the help command to list them all.

```bash
spinel-cli > vendor help
Available vendor commands:
==============================================
help
```

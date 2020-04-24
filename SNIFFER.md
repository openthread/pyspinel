# Spinel Sniffer Reference

Any Spinel NCP node can be made into a promiscuous packet sniffer, and this tool both intializes a device into this mode and outputs a pcap stream that can be saved or piped directly into Wireshark.

For a complete guide to installation and usage, see [Packet Sniffing with Pyspinel](https://openthread.io/guides/pyspinel/sniffer) on openthread.io.

## System requirements

The tool has been tested on the following platforms:

| Platforms | Version          |
| --------- | ---------------- |
| Ubuntu    | 14.04 Trusty     |
| Mac OS    | 10.11 El Capitan |

| Language | Version |
| -------- | ------- |
| Python   | 3.6.8   |

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

    sniffer.py - shell tool for controlling OpenThread NCP instances

### SYNOPSIS

    sniffer.py [-hupsnqvdxco]

### DESCRIPTION

```
    -h, --help
    	Show this help message and exit

    -u <UART>, --uart=<UART>
       	Open a serial connection to the OpenThread NCP device
	where <UART> is a device path such as "/dev/ttyUSB0".

    -b <baudrate>, --baudrate=<baudrate>
        Set the uart baud rate, default is 115200.

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

    -n NODEID, --nodeid=<NODEID>
        The unique nodeid for the HOST and NCP instance.

    -d <DEBUG_LEVEL>, --debug=<DEBUG_LEVEL>
        Set the debug level.  Enabling debug output is typically coupled with -x.
           0: Supress all debug output.  Required to stream to Wireshark.
           1: Show spinel property changes and values.
           2: Show spinel IPv6 packet bytes.
           3: Show spinel raw packet bytes (after HDLC decoding).
           4: Show spinel HDLC bytes.
           5: Show spinel raw stream bytes: all serial traffic to NCP.

    -x, --hex
        Output packets as ASCII HEX rather than pcap.

    -c, --channel
        Set the channel upon which to listen.

    -o <FILE_NAME>, --output=<FILE_NAME>
        Write capture to a file named <FILE_NAME>

    --crc
        Recalculate crc for NCP sniffer (useful for platforms that do not provide the crc).

    --no-reset
        Do not reset the NCP during initialization (useful for some NCPs with the native USB connection).

    --rssi
        Include RSSI information in pcap output.

    --tap
        Specify DLT_IEEE802_15_4_TAP(283) for frame format, with a pseudo-header containing TLVs with metadata (e.g. FCS, RSSI, LQI, channel etc).
        If not specified, DLT_IEEE802_15_4_WITHFCS(195) would be used by default with the additional RSSI, LQI following the PHY frame directly (TI style FCS format).
```

## Quick start

```
    For building an OpenThread ncp to support sniffer:
    add --enable-raw-link-api as a build option

    $ sudo ./sniffer.py -c 11 -n 1 -u /dev/ttyUSB0 | wireshark -k -i -

    For the sniffers that do not provide the crc:
    $ sudo ./sniffer.py -c 11 -n 1 --crc -u /dev/ttyUSB0 | wireshark -k -i -

    For the sniffers that are connected to the host with the native USB connection and reset during init results in failed start:
    $ sudo ./sniffer.py -c 11 -n 1 --no-reset -u /dev/ttyUSB0 | wireshark -k -i -

    To display RSSI on Wireshark:
    1. Configue Wireshark:
        Edit->Preferences->Protocols->IEEE802.15.4, enable "TI CC24xx FCS format" option
        Edit->Preferences->Appearance->Columns, add a new entry:
            Title:   RSSI
            Type:    Custom
            Fields:  wpan.rssi
    2. Run by command:
        $ sudo ./sniffer.py -c 11 -n 1 --rssi -u /dev/ttyUSB0 | wireshark -k -i -

    To display Channel on Wireshark: (only for Wireshark 3.0 and later)
    1. Configue Wireshark:
        Edit->Preferences->Appearance->Columns, add a new entry:
            Title:   Channel
            Type:    Custom
            Fields:  wpan-tap.ch_num
    2. Run by command:
        $ sudo ./sniffer.py -c 11 --tap -u /dev/ttyUSB0 | wireshark -k -i -

```

This will connect to stock openthread ncp firmware over the given UART, make the node into a promiscuous mode sniffer on the given channel, open up wireshark, and start streaming packets into wireshark.

## Troubleshooting

Q1: high packet loss rate when sniffing heavy traffic

A1: use higher uart baud rate in Sniffer firmware(NCP), and use '-b <baudrate>' option to set the same baud rate on host side.

to avoid packet loss, the baud rate should be higher than 250kbps, which is the maximum bitrate of the 802.15.4 2.4GHz PHY

# Spinel Sniffer Reference

Any Spinel NCP node can be made into a promiscuous packet sniffer, and this
tool both intializes a device into this mode and outputs a pcap stream that
can be saved or piped directly into Wireshark.

## System Requirements

The tool has been tested on the following platforms:

| Platforms | Version          |
|-----------|------------------|
| Ubuntu    | 14.04 Trusty     |
| Mac OS    | 10.11 El Capitan |

| Language  | Version          |
|-----------|------------------|
| Python    | 2.7.10           |

### Package Installation

```
sudo easy_install pip
sudo pip install --user pyserial
sudo pip install --user ipaddress
```

## Usage

### NAME
    sniffer.py - shell tool for controlling OpenThread NCP instances

### SYNOPSIS
    sniffer.py [-hupsnqvdxc]

### DESCRIPTION

```
    -h, --help            
    	Show this help message and exit

    -u <UART>, --uart=<UART>
       	Open a serial connection to the OpenThread NCP device
	where <UART> is a device path such as "/dev/ttyUSB0".

    -b <baudrate>, --baudrate=<baudrate>
        Set the uart baud rate, default is 115200.

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

    --crc
        Recalculate crc for NCP sniffer (useful for platforms that do not provide the crc).

    --no-reset
        Do not reset the NCP during initialization (useful for some NCPs with the native USB connection).

    --rssi
        Include RSSI information in pcap output.
```

## Quick Start

```
    For building an OpenThread ncp to support sniffer:
    add --enable-raw-link-api as a build option

    sudo ./sniffer.py -c 11 -n 1 -u /dev/ttyUSB0 | wireshark -k -i -

    For the sniffers that do not provide the crc:
    sudo ./sniffer.py -c 11 -n 1 --crc -u /dev/ttyUSB0 | wireshark -k -i -

    For the sniffers that are connected to the host with the native USB connection and reset during init results in failed start:
    sudo ./sniffer.py -c 11 -n 1 --no-reset -u /dev/ttyUSB0 | wireshark -k -i -

    To display RSSI on Wireshark:
    1. Configue Wireshark:
        Edit->Preferences->Protocols->IEEE802.15.4, enable "TI CC24xx FCS format" option
        Edit->Preferences->Appearance->Columns, add a new entry:
            Title:   RSSI
            Type:    Custom
            Fields:  wpan.rssi
    2. Run by command:
        sudo ./sniffer.py -c 11 -n 1 --rssi -u /dev/ttyUSB0 | wireshark -k -i -
```

This will connect to stock openthread ncp firmware over the given UART,
make the node into a promiscuous mode sniffer on the given channel,
open up wireshark, and start streaming packets into wireshark.

## Troubleshooting
Q1: sniffer.py throws ```ImportError: No module named dnet``` on OSX

A1: install the libdnet package for OSX -
```
brew install --with-python libdnet
mkdir -p /Users/YourUsernameHere/Library/Python/2.7/lib/python/site-packages
touch /Users/YourUsernameHere/Library/Python/2.7/lib/python/site-packages/homebrew.pth
echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' >> /Users/YourUsernameHere/Library/Python/2.7/lib/python/site-packages/homebrew.pth
```
you may need to reinstall the scapy pip dependency listed above

you can read more about this issue here: http://stackoverflow.com/questions/26229057/scapy-installation-fails-on-osx-with-dnet-import-error


Q2: high packet loss rate when sniffing heavy traffic

A2: use higher uart baud rate in Sniffer firmware(NCP), and use '-b <baudrate>' option to set the same baud rate on host side.

to avoid packet loss, the baud rate should be higher than 250kbps, which is the maximum bitrate of the 802.15.4 2.4GHz PHY

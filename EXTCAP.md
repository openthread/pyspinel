# Spinel Extcap Reference

Spinel Extcap provides a more user-friendly way to use OpenThread Sniffer. Spinel Extcap is primarily targeted for integrating OpenThread Sniffer with Wireshark, and is suitable for use with the Wireshark GUI.

For a complete guide to installation and usage, see [Packet Sniffing using Extcap](https://openthread.io/guides/pyspinel/sniffer-extcap) on openthread.io.

## System requirements

The tool has been tested on the following platforms:

| Platforms  | Version          |
| ---------- | ---------------- |
| Ubuntu     | 14.04 Trusty     |
| macOS      | 10.11 El Capitan |
| Windows 10 | 1803             |

| Language | Version |
| -------- | ------- |
| Python   | 3.6.8   |

| Software  | Version |
| --------- | ------- |
| Wireshark | 3.0.6   |

## Package installation

### 1. Find Wireshark extcap location

To find the correct installation path of the extcap utility on any system, open Wireshark:

```
"Help" -> "About Wireshark" -> "Folders" -> "Extcap path"
```

Copy the path. It is refered to as `<extcap_path>` in the following sections.

### 2. Installation

#### Automatic installation from source

```
$ git clone https://github.com/openthread/pyspinel
$ cd pyspinel
$ sudo python3 setup.py install --extcap-path=<extcap_path>
```

#### Automatic install from PYPI

```
$ pip3 install pyspinel --install-option="--extcap-path=<extcap_path>"
```

#### Manual installation

**1. Install pyspinel package**

```
$ pip3 install pyspinel
```

**2. Install extcap script on Wireshark**

Copy the provided `extcap_ot.py` to the extcap directory.

For Windows, also copy the provided `extcap_ot.bat` to the extcap directory.

For Linux and macOS, verify that the `extcap_ot.py` file has the execute (x) permission. If not, add it using:

```
$ chmod +x extcap_ot.py
```

## Usage

### Name

    extcap_ot.py - extcap interface for integrating OpenThread Sniffer with Wireshark

### Synopsis

    extcap_ot.py [--arguments]

### Description

```
    -h, --help
        Show this help message and exit

    --extcap-interfaces
        Provide a list of interfaces to capture from.

    --extcap-interface <EXTCAP_INTERFACE>
        Provide the interface to capture from.

    --extcap-dlts
        Provide a list of dlts for the given interface

    --extcap-config
        Provide a list of configurations for the given interface.

    --fifo <FIFO>
        Use together with capture to provide the fifo to dump data to.

    --channel <CHANNEL>
        IEEE 802.15.4 capture channel [11-26].

    --baudrate <BAUDRATE>
        Set the serial port baud rate.

    --tap
        Use to specify DLTs as IEEE 802.15.4 TAP (only for Wireshark3.0 and later).
```

## Quick start

### Configuring Wireshark for Thread

- Wireshark configuration - [Protocols](https://openthread.io/guides/ncp/sniffer#wireshark_configuration_-_protocols)
- Wireshark configuration - [FCS Format](https://openthread.io/guides/ncp/sniffer#wireshark_configuration_-_rssi)

### Using the sniffer

#### Wireshark welcome window

The Wireshark welcome window is displayed when Wireshark is first launched. OpenThread Sniffer will be enumerated in the interface list section of Wireshark welcome window.

#### Start sniffing

There are three ways to start sniffing:

- If this is your first time using an interface, click on **Interface Options** to set channel and baudrate, then click **Start Capture**. The parameters will be saved after the start of the capture, and you will not need to set it again the next time you use the interface (unless you need to change the channel).

- Double click on the hardware interface.

- Select the hardware interface and then click **Start Capture** to start sniffing.

#### Capture from multiple hardware interfaces/boards

Select all hardware interfaces in the Wireshark welcome window and click the Wireshark icon on the top left to start sniffing.

These fields are useful when capturing from multiple interfaces:

**Interface name (frame.interface_name)** — Interface Identifier used by Wireshark to identify the capture interfaces

**Channel (wpan-tap.ch_num)** — IEEE 802.15.4 capture channel [11-26]

## Troubleshooting

### The OpenThread sniffer is not listed in the Wireshark interface

1. If you have multiple Python interpreters installed, ensure that only the Python3 interpreter is being used by the extcap script. Python2 is no longer supported.
2. See if the hardware has been enumerated on USB and the drivers are loaded.
3. Check that the HEX file for the hardware has been flashed.
4. Reset the hardware by unplugging the hardware, waiting 5 seconds, and plugging it back in.
5. Restart Wireshark. If it still doesn’t appear, verify the python script located in the extcap folder is able to run.

   For Linux and macOS:

   1. Verify that the execute (x) permission is present for the `extcap_ot.py` file.
      ```
      $ ls -l extcap_ot.py
      ```
   2. If the execute permission is missing:
      ```
      $ chmod +x extcap_ot.py
      ```
   3. List the interfaces:
      ```
      $ ./extcap_ot.py --extcap-interfaces
      ```

   For Windows:

   1. List the interfaces:
      ```
      C:\> extcap_ot.bat --extcap-interfaces
      ```
   2. If this exits with a python error, verify that `python.exe` can be run from the command line:
      ```
      C:\> py -3 --version
      ```

### Wireshark only allows the root user to capture packets

During the Wireshark installation on Ubuntu the user will be prompted to choose one of the following options:

- Create the `wireshark` user group and allow all members of that group to capture packets.
- Only allow the root user to capture packets.

**Note**: Using Wireshark as the root user is strongly discouraged.

To change the settings after the installation, run the following command:

```
$ sudo dpkg-reconfigure wireshark-common
```

If Wireshark was configured to restrict the capture to members of the `wireshark` group, add the correct user to the group:

```
$ sudo usermod -a -G wireshark [user]
```

Add the correct user to the `dialout` group:

```
$ sudo usermod -a -G dialout [user]
```

Log out and log in again to apply the new user group settings.

### Wireshark format error when capturing on multiple USB interfaces on windows

[Known issue](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13653) of some old versions of Wireshark. Please upgrade to [Wireshark 3.0.6](https://www.wireshark.org/docs/relnotes/wireshark-3.0.6.html) or later.

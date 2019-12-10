#
#  Copyright (c) 2016-2017, The OpenThread Authors.
#  All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
""" Module-wide constants for spinel package. """

class SPINEL(object):
    """ Singular class that contains all Spinel constants. """
    HEADER_ASYNC = 0x80
    HEADER_DEFAULT = 0x81
    HEADER_EVENT_HANDLER = 0x82

    #=========================================
    # Spinel Commands: Host -> NCP
    #=========================================

    CMD_NOOP = 0
    CMD_RESET = 1
    CMD_PROP_VALUE_GET = 2
    CMD_PROP_VALUE_SET = 3
    CMD_PROP_VALUE_INSERT = 4
    CMD_PROP_VALUE_REMOVE = 5

    #=========================================
    # Spinel Command Responses: NCP -> Host
    #=========================================
    RSP_PROP_VALUE_IS = 6
    RSP_PROP_VALUE_INSERTED = 7
    RSP_PROP_VALUE_REMOVED = 8

    CMD_NET_SAVE = 9
    CMD_NET_CLEAR = 10
    CMD_NET_RECALL = 11

    RSP_HBO_OFFLOAD = 12
    RSP_HBO_RECLAIM = 13
    RSP_HBO_DROP = 14

    CMD_HBO_OFFLOADED = 15
    CMD_HBO_RECLAIMED = 16
    CMD_HBO_DROPPED = 17

    CMD_NEST__BEGIN = 15296
    CMD_NEST__END = 15360

    CMD_VENDOR__BEGIN = 15360
    CMD_VENDOR__END = 16384

    CMD_EXPERIMENTAL__BEGIN = 2000000
    CMD_EXPERIMENTAL__END = 2097152

    #=========================================
    # Spinel Properties
    #=========================================

    PROP_LAST_STATUS = 0  # < status [i]
    PROP_PROTOCOL_VERSION = 1  # < major, minor [i,i]
    PROP_NCP_VERSION = 2  # < version string [U]
    PROP_INTERFACE_TYPE = 3  # < [i]
    PROP_VENDOR_ID = 4  # < [i]
    PROP_CAPS = 5  # < capability list [A(i)]
    PROP_INTERFACE_COUNT = 6  # < Interface count [C]
    PROP_POWER_STATE = 7  # < PowerState [C]
    PROP_HWADDR = 8  # < PermEUI64 [E]
    PROP_LOCK = 9  # < PropLock [b]
    PROP_HBO_MEM_MAX = 10  # < Max offload mem [S]
    PROP_HBO_BLOCK_MAX = 11  # < Max offload block [S]

    PROP_PHY__BEGIN = 0x20
    PROP_PHY_ENABLED = PROP_PHY__BEGIN + 0  # < [b]
    PROP_PHY_CHAN = PROP_PHY__BEGIN + 1  # < [C]
    PROP_PHY_CHAN_SUPPORTED = PROP_PHY__BEGIN + 2  # < [A(C)]
    PROP_PHY_FREQ = PROP_PHY__BEGIN + 3  # < kHz [L]
    PROP_PHY_CCA_THRESHOLD = PROP_PHY__BEGIN + 4  # < dBm [c]
    PROP_PHY_TX_POWER = PROP_PHY__BEGIN + 5  # < [c]
    PROP_PHY_RSSI = PROP_PHY__BEGIN + 6  # < dBm [c]
    PROP_PHY__END = 0x30

    PROP_MAC__BEGIN = 0x30
    PROP_MAC_SCAN_STATE = PROP_MAC__BEGIN + 0  # < [C]
    PROP_MAC_SCAN_MASK = PROP_MAC__BEGIN + 1  # < [A(C)]
    PROP_MAC_SCAN_PERIOD = PROP_MAC__BEGIN + 2  # < ms-per-channel [S]
    # < chan,rssi,(laddr,saddr,panid,lqi),(proto,xtra) [Cct(ESSC)t(i)]
    PROP_MAC_SCAN_BEACON = PROP_MAC__BEGIN + 3
    PROP_MAC_15_4_LADDR = PROP_MAC__BEGIN + 4  # < [E]
    PROP_MAC_15_4_SADDR = PROP_MAC__BEGIN + 5  # < [S]
    PROP_MAC_15_4_PANID = PROP_MAC__BEGIN + 6  # < [S]
    PROP_MAC_RAW_STREAM_ENABLED = PROP_MAC__BEGIN + 7  # < [C]
    PROP_MAC_FILTER_MODE = PROP_MAC__BEGIN + 8  # < [C]
    PROP_MAC__END = 0x40

    PROP_MAC_EXT__BEGIN = 0x1300
    # Format: `A(T(Ec))`
    # * `E`: EUI64 address of node
    # * `c`: Optional fixed RSSI. OT_MAC_FILTER_FIXED_RSS_OVERRIDE_DISABLED(127) means not set.
    PROP_MAC_WHITELIST = PROP_MAC_EXT__BEGIN + 0   # < [A(T(Ec))]
    PROP_MAC_WHITELIST_ENABLED = PROP_MAC_EXT__BEGIN + 1  # < [b]

    # Format: `A(T(E))`
    # * `E`: EUI64 address of node
    PROP_MAC_BLACKLIST = PROP_MAC_EXT__BEGIN + 6   # <[A(T(E))]
    PROP_MAC_BLACKLIST_ENABLED = PROP_MAC_EXT__BEGIN + 7  # < [b]

    # Format: `A(T(Ec))`
    # * `E`: Optional EUI64 address of node. Set default RSS if not included.
    # * `c`: Fixed RSS. OT_MAC_FILTER_FIXED_RSS_OVERRIDE_DISABLED(127) means not set.
    PROP_MAC_FIXED_RSS = PROP_MAC_EXT__BEGIN + 8   # < [A(T(Ec))]

    # Format: `S`
    # * `S`: Current CCA (Clear Channel Assessment) failure rate.
    PROP_MAC_CCA_FAILURE_RATE = PROP_MAC_EXT__BEGIN + 9

    # Format: `C`
    # * `C`: The maximum (user-specified) number of direct frame transmission retries.
    PROP_MAC_MAX_RETRY_NUMBER_DIRECT = PROP_MAC_EXT__BEGIN + 10

    # Format: `C`
    # * `C`: The maximum (user-specified) number of indirect frame transmission retries.
    PROP_MAC_MAX_RETRY_NUMBER_INDIRECT = PROP_MAC_EXT__BEGIN + 11

    PROP_MAC_EXT__END = 0x1400

    PROP_NET__BEGIN = 0x40
    PROP_NET_SAVED = PROP_NET__BEGIN + 0  # < [b]
    PROP_NET_IF_UP = PROP_NET__BEGIN + 1  # < [b]
    PROP_NET_STACK_UP = PROP_NET__BEGIN + 2  # < [C]
    PROP_NET_ROLE = PROP_NET__BEGIN + 3  # < [C]
    PROP_NET_NETWORK_NAME = PROP_NET__BEGIN + 4  # < [U]
    PROP_NET_XPANID = PROP_NET__BEGIN + 5  # < [D]
    PROP_NET_MASTER_KEY = PROP_NET__BEGIN + 6  # < [D]
    PROP_NET_KEY_SEQUENCE_COUNTER = PROP_NET__BEGIN + 7  # < [L]
    PROP_NET_PARTITION_ID = PROP_NET__BEGIN + 8  # < [L]
    PROP_NET_KEY_SWITCH_GUARDTIME = PROP_NET__BEGIN + 10  # < [L]
    PROP_NET__END = 0x50

    PROP_THREAD__BEGIN = 0x50
    PROP_THREAD_LEADER_ADDR = PROP_THREAD__BEGIN + 0  # < [6]
    PROP_THREAD_PARENT = PROP_THREAD__BEGIN + 1  # < LADDR, SADDR [ES]
    PROP_THREAD_CHILD_TABLE = PROP_THREAD__BEGIN + 2  # < [A(t(ES))]
    PROP_THREAD_LEADER_RID = PROP_THREAD__BEGIN + 3  # < [C]
    PROP_THREAD_LEADER_WEIGHT = PROP_THREAD__BEGIN + 4  # < [C]
    PROP_THREAD_LOCAL_LEADER_WEIGHT = PROP_THREAD__BEGIN + 5  # < [C]
    PROP_THREAD_NETWORK_DATA = PROP_THREAD__BEGIN + 6  # < [D]
    PROP_THREAD_NETWORK_DATA_VERSION = PROP_THREAD__BEGIN + 7  # < [S]
    PROP_THREAD_STABLE_NETWORK_DATA = PROP_THREAD__BEGIN + 8  # < [D]
    PROP_THREAD_STABLE_NETWORK_DATA_VERSION = PROP_THREAD__BEGIN + 9  # < [S]
    # < array(ipv6prefix,prefixlen,stable,flags) [A(t(6CbC))]
    PROP_THREAD_ON_MESH_NETS = PROP_THREAD__BEGIN + 10
    # < array(ipv6prefix,prefixlen,stable,flags) [A(t(6CbC))]
    PROP_THREAD_LOCAL_ROUTES = PROP_THREAD__BEGIN + 11
    PROP_THREAD_ASSISTING_PORTS = PROP_THREAD__BEGIN + 12  # < array(portn) [A(S)]
    PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE = PROP_THREAD__BEGIN + 13  # < [b]
    PROP_THREAD_MODE = PROP_THREAD__BEGIN + 14
    PROP_THREAD__END = 0x60

    PROP_THREAD_EXT__BEGIN = 0x1500
    PROP_THREAD_CHILD_TIMEOUT = PROP_THREAD_EXT__BEGIN + 0  # < [L]
    PROP_THREAD_RLOC16 = PROP_THREAD_EXT__BEGIN + 1  # < [S]
    PROP_THREAD_ROUTER_UPGRADE_THRESHOLD = PROP_THREAD_EXT__BEGIN + 2  # < [C]
    PROP_THREAD_CONTEXT_REUSE_DELAY = PROP_THREAD_EXT__BEGIN + 3  # < [L]
    PROP_THREAD_NETWORK_ID_TIMEOUT = PROP_THREAD_EXT__BEGIN + 4  # < [b]
    PROP_THREAD_ACTIVE_ROUTER_IDS = PROP_THREAD_EXT__BEGIN + 5  # < [A(b)]
    PROP_THREAD_RLOC16_DEBUG_PASSTHRU = PROP_THREAD_EXT__BEGIN + 6  # < [b]
    PROP_THREAD_ROUTER_ROLE_ENABLED = PROP_THREAD_EXT__BEGIN + 7  # < [b]
    PROP_THREAD_ROUTER_DOWNGRADE_THRESHOLD = PROP_THREAD_EXT__BEGIN + 8  # < [C]
    PROP_THREAD_ROUTER_SELECTION_JITTER = PROP_THREAD_EXT__BEGIN + 9  # < [C]
    PROP_THREAD_PREFERRED_ROUTER_ID = PROP_THREAD_EXT__BEGIN + 10  # < [C]
    PROP_THREAD_NEIGHBOR_TABLE = PROP_THREAD_EXT__BEGIN + 11  # < [A(t(ESLCcCbLL))]
    PROP_THREAD_CHILD_COUNT_MAX = PROP_THREAD_EXT__BEGIN + 12  # < [C]

    PROP_THREAD_EXT__END = 0x1600

    PROP_MESHCOP_EXT__BEGIN = 0x1600
    PROP_MESHCOP_JOINER_ENABLE = PROP_MESHCOP_EXT__BEGIN + 0  # < [b]
    PROP_MESHCOP_JOINER_CREDENTIAL = PROP_MESHCOP_EXT__BEGIN + 1  # < [D]
    PROP_MESHCOP_JOINER_URL = PROP_MESHCOP_EXT__BEGIN + 2  # < [U]
    PROP_MESHCOP_BORDER_AGENT_ENABLE = PROP_MESHCOP_EXT__BEGIN + 3  # < [b]
    PROP_MESHCOP_EXT__END = 0x1700

    PROP_IPV6__BEGIN = 0x60
    PROP_IPV6_LL_ADDR = PROP_IPV6__BEGIN + 0  # < [6]
    PROP_IPV6_ML_ADDR = PROP_IPV6__BEGIN + 1  # < [6C]
    PROP_IPV6_ML_PREFIX = PROP_IPV6__BEGIN + 2  # < [6C]
    # < array(ipv6addr,prefixlen,valid,preferred,flags) [A(t(6CLLC))]
    PROP_IPV6_ADDRESS_TABLE = PROP_IPV6__BEGIN + 3
    # < array(ipv6prefix,prefixlen,iface,flags) [A(t(6CCC))]
    PROP_IPV6_ROUTE_TABLE = PROP_IPV6__BEGIN + 4
    PROP_IPv6_ICMP_PING_OFFLOAD = PROP_IPV6__BEGIN + 5  # < [b]

    PROP_STREAM__BEGIN = 0x70
    PROP_STREAM_DEBUG = PROP_STREAM__BEGIN + 0  # < [U]
    PROP_STREAM_RAW = PROP_STREAM__BEGIN + 1  # < [D]
    PROP_STREAM_NET = PROP_STREAM__BEGIN + 2  # < [D]
    PROP_STREAM_NET_INSECURE = PROP_STREAM__BEGIN + 3  # < [D]
    PROP_STREAM__END = 0x80

    # UART Bitrate
    # Format: `L`
    PROP_UART_BITRATE = 0x100

    # UART Software Flow Control
    # Format: `b`
    PROP_UART_XON_XOFF = 0x101

    PROP_PIB_15_4__BEGIN = 1024
    PROP_PIB_15_4_PHY_CHANNELS_SUPPORTED = PROP_PIB_15_4__BEGIN + 0x01  # < [A(L)]
    PROP_PIB_15_4_MAC_PROMISCUOUS_MODE = PROP_PIB_15_4__BEGIN + 0x51  # < [b]
    PROP_PIB_15_4_MAC_SECURITY_ENABLED = PROP_PIB_15_4__BEGIN + 0x5d  # < [b]
    PROP_PIB_15_4__END = 1280

    PROP_CNTR__BEGIN = 1280

    # Counter reset behavior
    # Format: `C`
    PROP_CNTR_RESET = PROP_CNTR__BEGIN + 0

    # The total number of transmissions.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_TOTAL = PROP_CNTR__BEGIN + 1

    # The number of transmissions with ack request.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_ACK_REQ = PROP_CNTR__BEGIN + 2

    # The number of transmissions that were acked.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_ACKED = PROP_CNTR__BEGIN + 3

    # The number of transmissions without ack request.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_NO_ACK_REQ = PROP_CNTR__BEGIN + 4

    # The number of transmitted data.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_DATA = PROP_CNTR__BEGIN + 5

    # The number of transmitted data poll.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_DATA_POLL = PROP_CNTR__BEGIN + 6

    # The number of transmitted beacon.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_BEACON = PROP_CNTR__BEGIN + 7

    # The number of transmitted beacon request.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_BEACON_REQ = PROP_CNTR__BEGIN + 8

    # The number of transmitted other types of frames.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_OTHER = PROP_CNTR__BEGIN + 9

    # The number of retransmission times.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_RETRY = PROP_CNTR__BEGIN + 10

    # The number of CCA failure times.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_ERR_CCA = PROP_CNTR__BEGIN + 11

    # The total number of received packets.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_TOTAL = PROP_CNTR__BEGIN + 100

    # The number of received data.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_DATA = PROP_CNTR__BEGIN + 101

    # The number of received data poll.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_DATA_POLL = PROP_CNTR__BEGIN + 102

    # The number of received beacon.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_BEACON = PROP_CNTR__BEGIN + 103

    # The number of received beacon request.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_BEACON_REQ = PROP_CNTR__BEGIN + 104

    # The number of received other types of frames.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_OTHER = PROP_CNTR__BEGIN + 105

    # The number of received packets filtered by whitelist.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_FILT_WL = PROP_CNTR__BEGIN + 106

    # The number of received packets filtered by destination check.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_FILT_DA = PROP_CNTR__BEGIN + 107

    # The number of received packets that are empty.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_EMPTY = PROP_CNTR__BEGIN + 108

    # The number of received packets from an unknown neighbor.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_UKWN_NBR = PROP_CNTR__BEGIN + 109

    # The number of received packets whose source address is invalid.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_NVLD_SADDR = PROP_CNTR__BEGIN + 110

    # The number of received packets with a security error.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_SECURITY = PROP_CNTR__BEGIN + 111

    # The number of received packets with a checksum error.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_BAD_FCS = PROP_CNTR__BEGIN + 112

    # The number of received packets with other errors.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_OTHER = PROP_CNTR__BEGIN + 113

    # The message buffer counter info
    # Format: `SSSSSSSSSSSSSSSS` (Read-only)
    #     `S`, (TotalBuffers)           The number of buffers in the pool.
    #     `S`, (FreeBuffers)            The number of free message buffers.
    #     `S`, (6loSendMessages)        The number of messages in the 6lo send queue.
    #     `S`, (6loSendBuffers)         The number of buffers in the 6lo send queue.
    #     `S`, (6loReassemblyMessages)  The number of messages in the 6LoWPAN reassembly queue.
    #     `S`, (6loReassemblyBuffers)   The number of buffers in the 6LoWPAN reassembly queue.
    #     `S`, (Ip6Messages)            The number of messages in the IPv6 send queue.
    #     `S`, (Ip6Buffers)             The number of buffers in the IPv6 send queue.
    #     `S`, (MplMessages)            The number of messages in the MPL send queue.
    #     `S`, (MplBuffers)             The number of buffers in the MPL send queue.
    #     `S`, (MleMessages)            The number of messages in the MLE send queue.
    #     `S`, (MleBuffers)             The number of buffers in the MLE send queue.
    #     `S`, (ArpMessages)            The number of messages in the ARP send queue.
    #     `S`, (ArpBuffers)             The number of buffers in the ARP send queue.
    #     `S`, (CoapClientMessages)     The number of messages in the CoAP client send queue.
    #     `S`  (CoapClientBuffers)      The number of buffers in the CoAP client send queue.
    PROP_MSG_BUFFER_COUNTERS = PROP_CNTR__BEGIN + 400

    # All MAC related counters.
    # Format: t(A(L))t(A(L))  (Read-only)
    #
    # The transmit structure includes:
    #
    #     'L': TxTotal              (The total number of transmissions).
    #     'L': TxUnicast            (The total number of unicast transmissions).
    #     'L': TxBroadcast          (The total number of broadcast transmissions).
    #     'L': TxAckRequested       (The number of transmissions with ack request).
    #     'L': TxAcked              (The number of transmissions that were acked).
    #     'L': TxNoAckRequested     (The number of transmissions without ack request).
    #     'L': TxData               (The number of transmitted data).
    #     'L': TxDataPoll           (The number of transmitted data poll).
    #     'L': TxBeacon             (The number of transmitted beacon).
    #     'L': TxBeaconRequest      (The number of transmitted beacon request).
    #     'L': TxOther              (The number of transmitted other types of frames).
    #     'L': TxRetry              (The number of retransmission times).
    #     'L': TxErrCca             (The number of CCA failure times).
    #     'L': TxErrAbort           (The number of frame transmission failures due to abort error).
    #     'L': TxErrBusyChannel     (The number of frames that were dropped due to a busy channel).
    #
    # The receive structure includes:
    #
    #     'L': RxTotal              (The total number of received packets).
    #     'L': RxUnicast            (The total number of unicast packets received).
    #     'L': RxBroadcast          (The total number of broadcast packets received).
    #     'L': RxData               (The number of received data).
    #     'L': RxDataPoll           (The number of received data poll).
    #     'L': RxBeacon             (The number of received beacon).
    #     'L': RxBeaconRequest      (The number of received beacon request).
    #     'L': RxOther              (The number of received other types of frames).
    #     'L': RxAddressFiltered    (The number of received packets filtered by address filter (whitelist or blacklist)).
    #     'L': RxDestAddrFiltered   (The number of received packets filtered by destination check).
    #     'L': RxDuplicated         (The number of received duplicated packets).
    #     'L': RxErrNoFrame         (The number of received packets with no or malformed content).
    #     'L': RxErrUnknownNeighbor (The number of received packets from unknown neighbor).
    #     'L': RxErrInvalidSrcAddr  (The number of received packets whose source address is invalid).
    #     'L': RxErrSec             (The number of received packets with security error).
    #     'L': RxErrFcs             (The number of received packets with FCS error).
    #     'L': RxErrOther           (The number of received packets with other error).
    PROP_CNTR_ALL_MAC_COUNTERS = PROP_CNTR__BEGIN + 401

    # Thread MLE counters.
    # Format: `SSSSSSSSS`  (Read-only)
    #    'S': DisabledRole                  (The number of times device entered OT_DEVICE_ROLE_DISABLED role).
    #    'S': DetachedRole                  (The number of times device entered OT_DEVICE_ROLE_DETACHED role).
    #    'S': ChildRole                     (The number of times device entered OT_DEVICE_ROLE_CHILD role).
    #    'S': RouterRole                    (The number of times device entered OT_DEVICE_ROLE_ROUTER role).
    #    'S': LeaderRole                    (The number of times device entered OT_DEVICE_ROLE_LEADER role).
    #    'S': AttachAttempts                (The number of attach attempts while device was detached).
    #    'S': PartitionIdChanges            (The number of changes to partition ID).
    #    'S': BetterPartitionAttachAttempts (The number of attempts to attach to a better partition).
    #    'S': ParentChanges                 (The number of times device changed its parents).
    PROP_CNTR_MLE_COUNTERS = PROP_CNTR__BEGIN + 402

    # MAC retry histogram.
    # Format: t(A(L))t(A(L)) (Read-only)
    #
    # The first structure is histogram which corresponds to retries of direct transmission:
    #   'L': DirectRetry[0]                   (The number of packets send with 0 retransmissions).
    #   'L': DirectRetry[1]                   (The number of packets send with 1 retransmissions).
    #    ...
    #   'L': DirectRetry[n]                   (The number of packets send with n retransmissions).
    #
    # The second structure provides the histogram of retries for indirect transmission:
    #   'L': IndirectRetry[0]                 (The number of packets send with 0 retransmissions).
    #   'L': IndirectRetry[1]                 (The number of packets send with 1 retransmissions).
    #    ...
    #   'L': IndirectRetry[m]                 (The number of packets send with m retransmissions).
    #
    PROP_CNTR_MAC_RETRY_HISTOGRAM = PROP_CNTR__BEGIN + 404

    PROP_CNTR__END = 0x800

    PROP_NEST__BEGIN = 0x3BC0
    PROP_NEST_STREAM_MFG = PROP_NEST__BEGIN + 0  # < [U]
    PROP_NEST__END = 0x3C00

    #=========================================

    MAC_FILTER_MDOE_NORMAL = 0
    MAC_FILTER_MODE_PROMISCUOUS = 1
    MAC_FILTER_MODE_MONITOR = 2

    #=========================================

    RSSI_OVERRIDE = 127

    #=========================================


class kThread(object):
    """ OpenThread constant class. """
    PrefixPreferenceOffset = 6
    PrefixPreferredFlag = 1 << 5
    PrefixSlaacFlag = 1 << 4
    PrefixDhcpFlag = 1 << 3
    PrefixConfigureFlag = 1 << 2
    PrefixDefaultRouteFlag = 1 << 1
    PrefixOnMeshFlag = 1 << 0

#=========================================

SPINEL_LAST_STATUS_MAP = {
    0: "STATUS_OK: Operation has completed successfully.",
    1: "STATUS_FAILURE: Operation has failed for some undefined reason.",
    2: "STATUS_UNIMPLEMENTED: The given operation has not been implemented.",
    3: "STATUS_INVALID_ARGUMENT: An argument to the given operation is invalid.",
    4: "STATUS_INVALID_STATE : The given operation is invalid for the current state of the device.",
    5: "STATUS_INVALID_COMMAND: The given command is not recognized.",
    6: "STATUS_INVALID_INTERFACE: The given Spinel interface is not supported.",
    7: "STATUS_INTERNAL_ERROR: An internal runtime error has occured.",
    8: "STATUS_SECURITY_ERROR: A security or authentication error has occured.",
    9: "STATUS_PARSE_ERROR: An error has occured while parsing the command.",
    10: "STATUS_IN_PROGRESS: The operation is in progress and will be completed asynchronously.",
    11: "STATUS_NOMEM: The operation has been prevented due to memory pressure.",
    12: "STATUS_BUSY: The device is currently performing a mutually exclusive operation.",
    13: "STATUS_PROPERTY_NOT_FOUND: The given property is not recognized.",
    14: "STATUS_PACKET_DROPPED: The packet was dropped.",
    15: "STATUS_EMPTY: The result of the operation is empty.",
    16: "STATUS_CMD_TOO_BIG: The command was too large to fit in the internal buffer.",
    17: "STATUS_NO_ACK: The packet was not acknowledged.",
    18: "STATUS_CCA_FAILURE: The packet was not sent due to a CCA failure.",
    19: "SPINEL_STATUS_ALREADY: The operation is already in progress.",
    20: "SPINEL_STATUS_ITEM_NOT_FOUND: The given item could not be found.",

    104: "SPINEL_STATUS_JOIN_FAILURE",
    105: "SPINEL_STATUS_JOIN_SECURITY: The network key has been set incorrectly.",
    106: "SPINEL_STATUS_JOIN_NO_PEERS: The node was unable to find any other peers on the network.",
    107: "SPINEL_STATUS_JOIN_INCOMPATIBLE: The only potential peer nodes found are incompatible.",

    112: "STATUS_RESET_POWER_ON",
    113: "STATUS_RESET_EXTERNAL",
    114: "STATUS_RESET_SOFTWARE",
    115: "STATUS_RESET_FAULT",
    116: "STATUS_RESET_CRASH",
    117: "STATUS_RESET_ASSERT",
    118: "STATUS_RESET_OTHER",
    119: "STATUS_RESET_UNKNOWN",
    120: "STATUS_RESET_WATCHDOG",

    0x4000: "kThreadError_None",
    0x4001: "kThreadError_Failed",
    0x4002: "kThreadError_Drop",
    0x4003: "kThreadError_NoBufs",
    0x4004: "kThreadError_NoRoute",
    0x4005: "kThreadError_Busy",
    0x4006: "kThreadError_Parse",
    0x4007: "kThreadError_InvalidArgs",
    0x4008: "kThreadError_Security",
    0x4009: "kThreadError_AddressQuery",
    0x400A: "kThreadError_NoAddress",
    0x400B: "kThreadError_NotReceiving",
    0x400C: "kThreadError_Abort",
    0x400D: "kThreadError_NotImplemented",
    0x400E: "kThreadError_InvalidState",
    0x400F: "kThreadError_NoTasklets",

}

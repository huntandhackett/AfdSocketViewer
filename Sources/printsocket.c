/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "printsocket.h"
#include "nativesocket.h"
#include "string_helpers.h"
#include "socket_strings.h"
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <ws2bth.h>
#include <hvsocket.h>
#include <wchar.h>

// Selects whether the program should output raw (machine-readable) or prettified (human-readable) property names and values
BOOLEAN H2RawPrintMode = FALSE;

typedef enum _H2_AFD_PROPERTY
{
    // Shared Winsock context
    H2_AFD_PROPERTY_SHARED_STATE,
    H2_AFD_PROPERTY_SHARED_ADDRESS_FAMILY,
    H2_AFD_PROPERTY_SHARED_SOCKET_TYPE,
    H2_AFD_PROPERTY_SHARED_PROTOCOL,
    H2_AFD_PROPERTY_SHARED_LOCAL_ADDRESS_LENGTH,
    H2_AFD_PROPERTY_SHARED_REMOTE_ADDRESS_LENGTH,
    H2_AFD_PROPERTY_SHARED_LINGER_ONOFF,
    H2_AFD_PROPERTY_SHARED_LINGER_TIMEOUT,
    H2_AFD_PROPERTY_SHARED_SEND_TIMEOUT,
    H2_AFD_PROPERTY_SHARED_RECEIVE_TIMEOUT,
    H2_AFD_PROPERTY_SHARED_RECEIVE_BUFFER_SIZE,
    H2_AFD_PROPERTY_SHARED_SEND_BUFFER_SIZE,
    H2_AFD_PROPERTY_SHARED_FLAGS,
    H2_AFD_PROPERTY_SHARED_LISTENING,
    H2_AFD_PROPERTY_SHARED_BROADCAST,
    H2_AFD_PROPERTY_SHARED_DEBUG,
    H2_AFD_PROPERTY_SHARED_OOB_INLINE,
    H2_AFD_PROPERTY_SHARED_REUSE_ADDRESSES,
    H2_AFD_PROPERTY_SHARED_EXCLUSIVE_ADDRESS_USE,
    H2_AFD_PROPERTY_SHARED_NON_BLOCKING,
    H2_AFD_PROPERTY_SHARED_DONT_USE_WILDCARD,
    H2_AFD_PROPERTY_SHARED_RECEIVE_SHUTDOWN,
    H2_AFD_PROPERTY_SHARED_SEND_SHUTDOWN,
    H2_AFD_PROPERTY_SHARED_CONDITIONAL_ACCEPT,
    H2_AFD_PROPERTY_SHARED_IS_SANSOCKET,
    H2_AFD_PROPERTY_SHARED_IS_TLI,
    H2_AFD_PROPERTY_SHARED_RIO,
    H2_AFD_PROPERTY_SHARED_RECEIVE_BUFFER_SIZE_SET,
    H2_AFD_PROPERTY_SHARED_SEND_BUFFER_SIZE_SET,
    H2_AFD_PROPERTY_SHARED_CREATION_FLAGS,
    H2_AFD_PROPERTY_SHARED_WSA_FLAG_OVERLAPPED,
    H2_AFD_PROPERTY_SHARED_WSA_FLAG_MULTIPOINT_C_ROOT,
    H2_AFD_PROPERTY_SHARED_WSA_FLAG_MULTIPOINT_C_LEAF,
    H2_AFD_PROPERTY_SHARED_WSA_FLAG_MULTIPOINT_D_ROOT,
    H2_AFD_PROPERTY_SHARED_WSA_FLAG_MULTIPOINT_D_LEAF,
    H2_AFD_PROPERTY_SHARED_WSA_FLAG_ACCESS_SYSTEM_SECURITY,
    H2_AFD_PROPERTY_SHARED_WSA_FLAG_NO_HANDLE_INHERIT,
    H2_AFD_PROPERTY_SHARED_WSA_FLAG_REGISTERED_IO,
    H2_AFD_PROPERTY_SHARED_CATALOG_ENTRY_ID,
    H2_AFD_PROPERTY_SHARED_SERVICE_FLAGS,
    H2_AFD_PROPERTY_SHARED_XP1_CONNECTIONLESS,
    H2_AFD_PROPERTY_SHARED_XP1_GUARANTEED_DELIVERY,
    H2_AFD_PROPERTY_SHARED_XP1_GUARANTEED_ORDER,
    H2_AFD_PROPERTY_SHARED_XP1_MESSAGE_ORIENTED,
    H2_AFD_PROPERTY_SHARED_XP1_PSEUDO_STREAM,
    H2_AFD_PROPERTY_SHARED_XP1_GRACEFUL_CLOSE,
    H2_AFD_PROPERTY_SHARED_XP1_EXPEDITED_DATA,
    H2_AFD_PROPERTY_SHARED_XP1_CONNECT_DATA,
    H2_AFD_PROPERTY_SHARED_XP1_DISCONNECT_DATA,
    H2_AFD_PROPERTY_SHARED_XP1_SUPPORT_BROADCAST,
    H2_AFD_PROPERTY_SHARED_XP1_SUPPORT_MULTIPOINT,
    H2_AFD_PROPERTY_SHARED_XP1_MULTIPOINT_CONTROL_PLANE,
    H2_AFD_PROPERTY_SHARED_XP1_MULTIPOINT_DATA_PLANE,
    H2_AFD_PROPERTY_SHARED_XP1_QOS_SUPPORTED,
    H2_AFD_PROPERTY_SHARED_XP1_INTERRUPT,
    H2_AFD_PROPERTY_SHARED_XP1_UNI_SEND,
    H2_AFD_PROPERTY_SHARED_XP1_UNI_RECV,
    H2_AFD_PROPERTY_SHARED_XP1_IFS_HANDLES,
    H2_AFD_PROPERTY_SHARED_XP1_PARTIAL_MESSAGE,
    H2_AFD_PROPERTY_SHARED_XP1_SAN_SUPPORT_SDP,
    H2_AFD_PROPERTY_SHARED_PROVIDER_FLAGS,
    H2_AFD_PROPERTY_SHARED_PFL_MULTIPLE_PROTO_ENTRIES,
    H2_AFD_PROPERTY_SHARED_PFL_RECOMMENDED_PROTO_ENTRY,
    H2_AFD_PROPERTY_SHARED_PFL_HIDDEN,
    H2_AFD_PROPERTY_SHARED_PFL_MATCHES_PROTOCOL_ZERO,
    H2_AFD_PROPERTY_SHARED_PFL_NETWORKDIRECT_PROVIDER,
    H2_AFD_PROPERTY_SHARED_GROUP_ID,
    H2_AFD_PROPERTY_SHARED_GROUP_TYPE,
    H2_AFD_PROPERTY_SHARED_GROUP_PRIORITY,
    H2_AFD_PROPERTY_SHARED_LAST_ERROR,
    H2_AFD_PROPERTY_SHARED_ASYNC_SELECT_WND,
    H2_AFD_PROPERTY_SHARED_ASYNC_SELECT_SERIAL_NUMBER,
    H2_AFD_PROPERTY_SHARED_ASYNC_SELECTW_MSG,
    H2_AFD_PROPERTY_SHARED_ASYNC_SELECTL_EVENT,
    H2_AFD_PROPERTY_SHARED_DISABLED_ASYNC_SELECT_EVENTS,
    H2_AFD_PROPERTY_SHARED_PROVIDER_ID,

    // Addresses
    H2_AFD_PROPERTY_LOCAL_ADDRESS,
    H2_AFD_PROPERTY_REMOTE_ADDRESS,

    // AFD info classes
    H2_AFD_PROPERTY_AFD_MAX_SEND_SIZE,
    H2_AFD_PROPERTY_AFD_SENDS_PENDING,
    H2_AFD_PROPERTY_AFD_MAX_PATH_SEND_SIZE,
    H2_AFD_PROPERTY_AFD_RECEIVE_WINDOW_SIZE,
    H2_AFD_PROPERTY_AFD_SEND_WINDOW_SIZE,
    H2_AFD_PROPERTY_AFD_CONNECT_TIME,
    H2_AFD_PROPERTY_AFD_GROUP_ID,
    H2_AFD_PROPERTY_AFD_GROUP_TYPE,
    H2_AFD_PROPERTY_AFD_DELIVERY_AVAILABLE,
    H2_AFD_PROPERTY_AFD_PENDED_RECEIVE_REQUESTS,

    // TDI devices
    H2_AFD_PROPERTY_TDI_ADDRESS_DEVICE,
    H2_AFD_PROPERTY_TDI_CONNECTION_DEVICE,

    // Socket-level options
    H2_AFD_PROPERTY_SO_REUSEADDR,
    H2_AFD_PROPERTY_SO_KEEPALIVE,
    H2_AFD_PROPERTY_SO_DONTROUTE,
    H2_AFD_PROPERTY_SO_BROADCAST,
    H2_AFD_PROPERTY_SO_OOBINLINE,
    H2_AFD_PROPERTY_SO_RCVBUF,
    H2_AFD_PROPERTY_SO_MAX_MSG_SIZE,
    H2_AFD_PROPERTY_SO_CONDITIONAL_ACCEPT,
    H2_AFD_PROPERTY_SO_PAUSE_ACCEPT,
    H2_AFD_PROPERTY_SO_COMPARTMENT_ID,
    H2_AFD_PROPERTY_SO_RANDOMIZE_PORT,
    H2_AFD_PROPERTY_SO_PORT_SCALABILITY,
    H2_AFD_PROPERTY_SO_REUSE_UNICASTPORT,
    H2_AFD_PROPERTY_SO_EXCLUSIVEADDRUSE,

    // IP-level options (Raw mode, v4-only)
    H2_AFD_PROPERTY_IP_HDRINCL,
    H2_AFD_PROPERTY_IP_TOS,
    H2_AFD_PROPERTY_IP_TTL,
    H2_AFD_PROPERTY_IP_MULTICAST_IF,
    H2_AFD_PROPERTY_IP_MULTICAST_TTL,
    H2_AFD_PROPERTY_IP_MULTICAST_LOOP,
    H2_AFD_PROPERTY_IP_DONTFRAGMENT,
    H2_AFD_PROPERTY_IP_PKTINFO,
    H2_AFD_PROPERTY_IP_RECVTTL,
    H2_AFD_PROPERTY_IP_RECEIVE_BROADCAST,
    H2_AFD_PROPERTY_IP_RECVIF,
    H2_AFD_PROPERTY_IP_RECVDSTADDR,
    H2_AFD_PROPERTY_IP_IFLIST,
    H2_AFD_PROPERTY_IP_UNICAST_IF,
    H2_AFD_PROPERTY_IP_RECVRTHDR,
    H2_AFD_PROPERTY_IP_RECVTOS,
    H2_AFD_PROPERTY_IP_ORIGINAL_ARRIVAL_IF,
    H2_AFD_PROPERTY_IP_RECVECN,
    H2_AFD_PROPERTY_IP_PKTINFO_EX,
    H2_AFD_PROPERTY_IP_WFP_REDIRECT_RECORDS,
    H2_AFD_PROPERTY_IP_WFP_REDIRECT_CONTEXT,
    H2_AFD_PROPERTY_IP_MTU_DISCOVER,
    H2_AFD_PROPERTY_IP_MTU,
    H2_AFD_PROPERTY_IP_RECVERR,
    H2_AFD_PROPERTY_IP_USER_MTU,

    // IP-level options (Raw mode, v6-only)
    H2_AFD_PROPERTY_IPV6_HDRINCL,
    H2_AFD_PROPERTY_IPV6_UNICAST_HOPS,
    H2_AFD_PROPERTY_IPV6_MULTICAST_IF,
    H2_AFD_PROPERTY_IPV6_MULTICAST_HOPS,
    H2_AFD_PROPERTY_IPV6_MULTICAST_LOOP,
    H2_AFD_PROPERTY_IPV6_DONTFRAG,
    H2_AFD_PROPERTY_IPV6_PKTINFO,
    H2_AFD_PROPERTY_IPV6_HOPLIMIT,
    H2_AFD_PROPERTY_IPV6_PROTECTION_LEVEL,
    H2_AFD_PROPERTY_IPV6_RECVIF,
    H2_AFD_PROPERTY_IPV6_RECVDSTADDR,
    H2_AFD_PROPERTY_IPV6_V6ONLY,
    H2_AFD_PROPERTY_IPV6_IFLIST,
    H2_AFD_PROPERTY_IPV6_UNICAST_IF,
    H2_AFD_PROPERTY_IPV6_RECVRTHDR,
    H2_AFD_PROPERTY_IPV6_RECVTCLASS,
    H2_AFD_PROPERTY_IPV6_RECVECN,
    H2_AFD_PROPERTY_IPV6_PKTINFO_EX,
    H2_AFD_PROPERTY_IPV6_WFP_REDIRECT_RECORDS,
    H2_AFD_PROPERTY_IPV6_WFP_REDIRECT_CONTEXT,
    H2_AFD_PROPERTY_IPV6_MTU_DISCOVER,
    H2_AFD_PROPERTY_IPV6_MTU,
    H2_AFD_PROPERTY_IPV6_RECVERR,
    H2_AFD_PROPERTY_IPV6_USER_MTU,

    // IP-level options (human-readable mode, merged IPv4/IPv6)
    H2_AFD_PROPERTY_IPALL_HDRINCL,
    H2_AFD_PROPERTY_IPALL_TOS,
    H2_AFD_PROPERTY_IPALL_TTL,
    H2_AFD_PROPERTY_IPALL_MULTICAST_IF,
    H2_AFD_PROPERTY_IPALL_MULTICAST_TTL,
    H2_AFD_PROPERTY_IPALL_MULTICAST_LOOP,
    H2_AFD_PROPERTY_IPALL_DONTFRAGMENT,
    H2_AFD_PROPERTY_IPALL_PKTINFO,
    H2_AFD_PROPERTY_IPALL_RECVTTL,
    H2_AFD_PROPERTY_IPALL_RECEIVE_BROADCAST,
    H2_AFD_PROPERTY_IPALL_PROTECTION_LEVEL,
    H2_AFD_PROPERTY_IPALL_RECVIF,
    H2_AFD_PROPERTY_IPALL_RECVDSTADDR,
    H2_AFD_PROPERTY_IPALL_V6ONLY,
    H2_AFD_PROPERTY_IPALL_IFLIST,
    H2_AFD_PROPERTY_IPALL_UNICAST_IF,
    H2_AFD_PROPERTY_IPALL_RECVRTHDR,
    H2_AFD_PROPERTY_IPALL_RECVTOS,
    H2_AFD_PROPERTY_IPALL_ORIGINAL_ARRIVAL_IF,
    H2_AFD_PROPERTY_IPALL_RECVECN,
    H2_AFD_PROPERTY_IPALL_PKTINFO_EX,
    H2_AFD_PROPERTY_IPALL_WFP_REDIRECT_RECORDS,
    H2_AFD_PROPERTY_IPALL_WFP_REDIRECT_CONTEXT,
    H2_AFD_PROPERTY_IPALL_MTU_DISCOVER,
    H2_AFD_PROPERTY_IPALL_MTU,
    H2_AFD_PROPERTY_IPALL_RECVERR,
    H2_AFD_PROPERTY_IPALL_USER_MTU,

    // TCP-level options
    H2_AFD_PROPERTY_TCP_NODELAY,
    H2_AFD_PROPERTY_TCP_EXPEDITED,
    H2_AFD_PROPERTY_TCP_KEEPALIVE,
    H2_AFD_PROPERTY_TCP_MAXSEG,
    H2_AFD_PROPERTY_TCP_MAXRT,
    H2_AFD_PROPERTY_TCP_STDURG,
    H2_AFD_PROPERTY_TCP_NOURG,
    H2_AFD_PROPERTY_TCP_ATMARK,
    H2_AFD_PROPERTY_TCP_NOSYNRETRIES,
    H2_AFD_PROPERTY_TCP_TIMESTAMPS,
    H2_AFD_PROPERTY_TCP_CONGESTION_ALGORITHM,
    H2_AFD_PROPERTY_TCP_DELAY_FIN_ACK,
    H2_AFD_PROPERTY_TCP_MAXRTMS,
    H2_AFD_PROPERTY_TCP_FASTOPEN,
    H2_AFD_PROPERTY_TCP_KEEPCNT,
    H2_AFD_PROPERTY_TCP_KEEPINTVL,
    H2_AFD_PROPERTY_TCP_FAIL_CONNECT_ON_ICMP_ERROR,

    // TCP information
    H2_AFD_PROPERTY_TCP_INFO_STATE,
    H2_AFD_PROPERTY_TCP_INFO_MSS,
    H2_AFD_PROPERTY_TCP_INFO_CONNECTION_TIME,
    H2_AFD_PROPERTY_TCP_INFO_TIMESTAMPS_ENABLED,
    H2_AFD_PROPERTY_TCP_INFO_RTT,
    H2_AFD_PROPERTY_TCP_INFO_MINRTT,
    H2_AFD_PROPERTY_TCP_INFO_BYTES_IN_FLIGHT,
    H2_AFD_PROPERTY_TCP_INFO_CONGESTION_WINDOW,
    H2_AFD_PROPERTY_TCP_INFO_SEND_WINDOW,
    H2_AFD_PROPERTY_TCP_INFO_RECEIVE_WINDOW,
    H2_AFD_PROPERTY_TCP_INFO_RECEIVE_BUFFER,
    H2_AFD_PROPERTY_TCP_INFO_BYTES_OUT,
    H2_AFD_PROPERTY_TCP_INFO_BYTES_IN,
    H2_AFD_PROPERTY_TCP_INFO_BYTES_REORDERED,
    H2_AFD_PROPERTY_TCP_INFO_BYTES_RETRANSMITTED,
    H2_AFD_PROPERTY_TCP_INFO_FAST_RETRANSMIT,
    H2_AFD_PROPERTY_TCP_INFO_DUPLICATE_ACKS_IN,
    H2_AFD_PROPERTY_TCP_INFO_TIMEOUT_EPISODES,
    H2_AFD_PROPERTY_TCP_INFO_SYN_RETRANSMITS,
    H2_AFD_PROPERTY_TCP_INFO_RECEIVER_LIMITED_TRANSITIONS,
    H2_AFD_PROPERTY_TCP_INFO_RECEIVER_LIMITED_TIME,
    H2_AFD_PROPERTY_TCP_INFO_RECEIVER_LIMITED_BYTES,
    H2_AFD_PROPERTY_TCP_INFO_CONGESTION_LIMITED_TRANSITIONS,
    H2_AFD_PROPERTY_TCP_INFO_CONGESTION_LIMITED_TIME,
    H2_AFD_PROPERTY_TCP_INFO_CONGESTION_LIMITED_BYTES,
    H2_AFD_PROPERTY_TCP_INFO_SENDER_LIMITED_TRANSITIONS,
    H2_AFD_PROPERTY_TCP_INFO_SENDER_LIMITED_TIME,
    H2_AFD_PROPERTY_TCP_INFO_SENDER_LIMITED_BYTES,
    H2_AFD_PROPERTY_TCP_INFO_OUT_OF_ORDER_PACKETS,
    H2_AFD_PROPERTY_TCP_INFO_ECN_NEGOTIATED,
    H2_AFD_PROPERTY_TCP_INFO_ECE_ACKS_IN,
    H2_AFD_PROPERTY_TCP_INFO_PTO_EPISODES,

    // UDP-level options
    H2_AFD_PROPERTY_UDP_NOCHECKSUM,
    H2_AFD_PROPERTY_UDP_SEND_MSG_SIZE,
    H2_AFD_PROPERTY_UDP_RECV_MAX_COALESCED_SIZE,

    // Hyper-V level options
    H2_AFD_PROPERTY_HVSOCKET_CONNECT_TIMEOUT,
    H2_AFD_PROPERTY_HVSOCKET_CONTAINER_PASSTHRU,
    H2_AFD_PROPERTY_HVSOCKET_CONNECTED_SUSPEND,
    H2_AFD_PROPERTY_HVSOCKET_HIGH_VTL,

    H2_AFD_PROPERTY_MAX
} H2_AFD_PROPERTY;

typedef struct _H2_AFD_PROPERTY_NAME_PAIR
{
    PCWSTR FriendlyName;
    PCWSTR RawName;
} H2_AFD_PROPERTY_NAME_PAIR;

/**
  * \brief Looks up a name for a socket property.
  *
  * \param[in] Property An index of the property.
  *
  * \return A property name string.
  */
PCWSTR H2AfdGetPropertyName(
    _In_ H2_AFD_PROPERTY Property
)
{
    static H2_AFD_PROPERTY_NAME_PAIR names[H2_AFD_PROPERTY_MAX] = {
        { L"State                       ", L"SOCK_SHARED_INFO.State                    " },
        { L"Address family              ", L"SOCK_SHARED_INFO.AddressFamily            " },
        { L"Socket type                 ", L"SOCK_SHARED_INFO.SocketType               " },
        { L"Protocol                    ", L"SOCK_SHARED_INFO.Protocol                 " },
        { L"Local address length        ", L"SOCK_SHARED_INFO.LocalAddressLength       " },
        { L"Remote address length       ", L"SOCK_SHARED_INFO.RemoteAddressLength      " },
        { L"Linger                      ", L"SOCK_SHARED_INFO.LingerInfo.l_onoff       " },
        { L"Linger timeout              ", L"SOCK_SHARED_INFO.LingerInfo.l_linger      " },
        { L"Send timeout                ", L"SOCK_SHARED_INFO.LingerInfo.SendTimeout   " },
        { L"Receive timeout             ", L"SOCK_SHARED_INFO.ReceiveTimeout           " },
        { L"Receive buffer size         ", L"SOCK_SHARED_INFO.ReceiveBufferSize        " },
        { L"Send buffer size            ", L"SOCK_SHARED_INFO.SendBufferSize           " },
        { L"Flags                       ", L"SOCK_SHARED_INFO.Flags                    " },
        { L" - Listening                ", L" - Listening                              " },
        { L" - Broadcast                ", L" - Broadcast                              " },
        { L" - Debug                    ", L" - Debug                                  " },
        { L" - OOB in line              ", L" - OobInline                              " },
        { L" - Reuse addresses          ", L" - ReuseAddresses                         " },
        { L" - Exclusive address use    ", L" - ExclusiveAddressUse                    " },
        { L" - Non-blocking             ", L" - NonBlocking                            " },
        { L" - Don't use wildcard       ", L" - DontUseWildcard                        " },
        { L" - Receive shutdown         ", L" - ReceiveShutdown                        " },
        { L" - Send shutdown            ", L" - SendShutdown                           " },
        { L" - Conditional accept       ", L" - ConditionalAccept                      " },
        { L" - SAN                      ", L" - IsSANSocket                            " },
        { L" - TLI                      ", L" - fIsTLI                                 " },
        { L" - RIO                      ", L" - Rio                                    " },
        { L" - Receive suffer size set  ", L" - ReceiveBufferSizeSet                   " },
        { L" - Send suffer size set     ", L" - SendBufferSizeSet                      " },
        { L"Creation flags              ", L"SOCK_SHARED_INFO.CreationFlags            " },
        { L" - Overlapped               ", L" - WSA_FLAG_OVERLAPPED                    " },
        { L" - Multipoint control root  ", L" - WSA_FLAG_MULTIPOINT_C_ROOT             " },
        { L" - Multipoint control leaf  ", L" - WSA_FLAG_MULTIPOINT_C_LEAF             " },
        { L" - Multipoint data root     ", L" - WSA_FLAG_MULTIPOINT_D_ROOT             " },
        { L" - Multipoint data leaf     ", L" - WSA_FLAG_MULTIPOINT_D_LEAF             " },
        { L" - Access SACL              ", L" - WSA_FLAG_ACCESS_SYSTEM_SECURITY        " },
        { L" - No handle inherit        ", L" - WSA_FLAG_NO_HANDLE_INHERIT             " },
        { L" - Registered I/O           ", L" - WSA_FLAG_REGISTERED_IO                 " },
        { L"Catalog entry ID            ", L"SOCK_SHARED_INFO.CatalogEntryId           " },
        { L"Service flags               ", L"SOCK_SHARED_INFO.ServiceFlags1            " },
        { L" - Connectionless           ", L" - XP1_CONNECTIONLESS                     " },
        { L" - Guaranteed delivery      ", L" - XP1_GUARANTEED_DELIVERY                " },
        { L" - Guaranteed order         ", L" - XP1_GUARANTEED_ORDER                   " },
        { L" - Message-oriented         ", L" - XP1_MESSAGE_ORIENTED                   " },
        { L" - Pseudo-stream            ", L" - XP1_PSEUDO_STREAM                      " },
        { L" - Graceful close           ", L" - XP1_GRACEFUL_CLOSE                     " },
        { L" - Expedited data           ", L" - XP1_EXPEDITED_DATA                     " },
        { L" - Connect data             ", L" - XP1_CONNECT_DATA                       " },
        { L" - Disconnect data          ", L" - XP1_DISCONNECT_DATA                    " },
        { L" - Broadcast                ", L" - XP1_SUPPORT_BROADCAST                  " },
        { L" - Support multipoint       ", L" - XP1_SUPPORT_MULTIPOINT                 " },
        { L" - Multipoint control plane ", L" - XP1_MULTIPOINT_CONTROL_PLANE           " },
        { L" - Multipoint data plane    ", L" - XP1_MULTIPOINT_DATA_PLANE              " },
        { L" - QoS supported            ", L" - XP1_QOS_SUPPORTED:                     " },
        { L" - Interrupt                ", L" - XP1_INTERRUPT                          " },
        { L" - Unidirectional send      ", L" - XP1_UNI_SEND                           " },
        { L" - Unidirectional receive   ", L" - XP1_UNI_RECV                           " },
        { L" - IFS handles              ", L" - XP1_IFS_HANDLES                        " },
        { L" - Partial message          ", L" - XP1_PARTIAL_MESSAGE                    " },
        { L" - SAN support SDP          ", L" - XP1_SAN_SUPPORT_SDP                    " },
        { L"Provider flags              ", L"SOCK_SHARED_INFO.ProviderFlags            " },
        { L" - Multiple entries         ", L" - PFL_MULTIPLE_PROTO_ENTRIES             " },
        { L" - Recommended entry        ", L" - PFL_RECOMMENDED_PROTO_ENTRY            " },
        { L" - Hidden                   ", L" - PFL_HIDDEN                             " },
        { L" - Matches protocol zero    ", L" - PFL_MATCHES_PROTOCOL_ZERO              " },
        { L" - Network direct           ", L" - PFL_NETWORKDIRECT_PROVIDER             " },
        { L"Group ID                    ", L"SOCK_SHARED_INFO.GroupID                  " },
        { L"Group type                  ", L"SOCK_SHARED_INFO.GroupType                " },
        { L"Group priority              ", L"SOCK_SHARED_INFO.GroupPriority            " },
        { L"Last error                  ", L"SOCK_SHARED_INFO.LastError                " },
        { L"Async select HWND           ", L"SOCK_SHARED_INFO.AsyncSelectWnd64         " },
        { L"Async select serial number  ", L"SOCK_SHARED_INFO.AsyncSelectSerialNumber  " },
        { L"Async select message        ", L"SOCK_SHARED_INFO.AsyncSelectwMsg          " },
        { L"Async select event          ", L"SOCK_SHARED_INFO.AsyncSelectlEvent        " },
        { L"Disabled async select events", L"SOCK_SHARED_INFO.DisabledAsyncSelectEvents" },
        { L"Provider ID                 ", L"SOCK_SHARED_INFO.ProviderId               " },

        { L"Local address               ", L"IOCTL_AFD_GET_ADDRESS                     " },
        { L"Remote address              ", L"IOCTL_AFD_GET_REMOTE_ADDRESS              " },

        { L"Maximum send size           ", L"AFD_MAX_SEND_SIZE                         " },
        { L"Pending sends               ", L"AFD_SENDS_PENDING                         " },
        { L"Maximum path send size      ", L"AFD_MAX_PATH_SEND_SIZE                    " },
        { L"Receive window size         ", L"AFD_RECEIVE_WINDOW_SIZE                   " },
        { L"Send window size            ", L"AFD_SEND_WINDOW_SIZE                      " },
        { L"Connect time                ", L"AFD_CONNECT_TIME                          " },
        { L"Group ID                    ", L"AFD_GROUP_ID_AND_TYPE::GroupID            " },
        { L"Group type                  ", L"AFD_GROUP_ID_AND_TYPE::GroupType          " },
        { L"Delivery available          ", L"AFD_DELIVERY_STATUS::DeliveryAvailable    " },
        { L"Pending receive requests    ", L"AFD_DELIVERY_STATUS::PendedReceiveRequests" },

        { L"TDI address device          ", L"AFD_HANDLE_INFO.TdiAddressHandle          " },
        { L"TDI connection device       ", L"AFD_HANDLE_INFO.TdiConnectionHandle       " },

        { L"Reuse address               ", L"SO_REUSEADDR                              " },
        { L"Keep alive                  ", L"SO_KEEPALIVE                              " },
        { L"Don't route                 ", L"SO_DONTROUTE                              " },
        { L"Broadcast                   ", L"SO_BROADCAST                              " },
        { L"OOB in line                 ", L"SO_OOBINLINE                              " },
        { L"Receive buffer size         ", L"SO_RCVBUF                                 " },
        { L"Maximum message size        ", L"SO_MAX_MSG_SIZE                           " },
        { L"Conditional accept          ", L"SO_CONDITIONAL_ACCEPT                     " },
        { L"Pause accept                ", L"SO_PAUSE_ACCEPT                           " },
        { L"Compartment ID              ", L"SO_COMPARTMENT_ID                         " },
        { L"Randomize port              ", L"SO_RANDOMIZE_PORT                         " },
        { L"Port scalability            ", L"SO_PORT_SCALABILITY                       " },
        { L"Reuse unicast port          ", L"SO_REUSE_UNICASTPORT                      " },
        { L"Exclusive address use       ", L"SO_EXCLUSIVEADDRUSE                       " },

        { L"                            ", L"IP_HDRINCL                                " },
        { L"                            ", L"IP_TOS                                    " },
        { L"                            ", L"IP_TTL                                    " },
        { L"                            ", L"IP_MULTICAST_IF                           " },
        { L"                            ", L"IP_MULTICAST_TTL                          " },
        { L"                            ", L"IP_MULTICAST_LOOP                         " },
        { L"                            ", L"IP_DONTFRAGMENT                           " },
        { L"                            ", L"IP_PKTINFO                                " },
        { L"                            ", L"IP_RECVTTL                                " },
        { L"                            ", L"IP_RECEIVE_BROADCAST                      " },
        { L"                            ", L"IP_RECVIF                                 " },
        { L"                            ", L"IP_RECVDSTADDR                            " },
        { L"                            ", L"IP_IFLIST                                 " },
        { L"                            ", L"IP_UNICAST_IF                             " },
        { L"                            ", L"IP_RECVRTHDR                              " },
        { L"                            ", L"IP_RECVTOS                                " },
        { L"                            ", L"IP_ORIGINAL_ARRIVAL_IF                    " },
        { L"                            ", L"IP_RECVECN                                " },
        { L"                            ", L"IP_PKTINFO_EX                             " },
        { L"                            ", L"IP_WFP_REDIRECT_RECORDS                   " },
        { L"                            ", L"IP_WFP_REDIRECT_CONTEXT                   " },
        { L"                            ", L"IP_MTU_DISCOVER                           " },
        { L"                            ", L"IP_MTU                                    " },
        { L"                            ", L"IP_RECVERR                                " },
        { L"                            ", L"IP_USER_MTU                               " },

        { L"                            ", L"IPV6_HDRINCL                              " },
        { L"                            ", L"IPV6_UNICAST_HOPS                         " },
        { L"                            ", L"IPV6_MULTICAST_IF                         " },
        { L"                            ", L"IPV6_MULTICAST_HOPS                       " },
        { L"                            ", L"IPV6_MULTICAST_LOOP                       " },
        { L"                            ", L"IPV6_DONTFRAG                             " },
        { L"                            ", L"IPV6_PKTINFO                              " },
        { L"                            ", L"IPV6_HOPLIMIT                             " },
        { L"                            ", L"IPV6_PROTECTION_LEVEL                     " },
        { L"                            ", L"IPV6_RECVIF                               " },
        { L"                            ", L"IPV6_RECVDSTADDR                          " },
        { L"                            ", L"IPV6_V6ONLY                               " },
        { L"                            ", L"IPV6_IFLIST                               " },
        { L"                            ", L"IPV6_UNICAST_IF                           " },
        { L"                            ", L"IPV6_RECVRTHDR                            " },
        { L"                            ", L"IPV6_RECVTCLASS                           " },
        { L"                            ", L"IPV6_RECVECN                              " },
        { L"                            ", L"IPV6_PKTINFO_EX                           " },
        { L"                            ", L"IPV6_WFP_REDIRECT_RECORDS                 " },
        { L"                            ", L"IPV6_WFP_REDIRECT_CONTEXT                 " },
        { L"                            ", L"IPV6_MTU_DISCOVER                         " },
        { L"                            ", L"IPV6_MTU                                  " },
        { L"                            ", L"IPV6_RECVERR                              " },
        { L"                            ", L"IPV6_USER_MTU                             " },

        { L"Header included             ", L"                                          " },
        { L"Type-of-service             ", L"                                          " },
        { L"Unicast TTL                 ", L"                                          " },
        { L"Multicast interface         ", L"                                          " },
        { L"Multicast TTL               ", L"                                          " },
        { L"Multicast loopback          ", L"                                          " },
        { L"Don't fragment              ", L"                                          " },
        { L"Receive packet info         ", L"                                          " },
        { L"Receive TTL                 ", L"                                          " },
        { L"Broadcast reception         ", L"                                          " },
        { L"IPv6 protection level       ", L"                                          " },
        { L"Receive arrival interface   ", L"                                          " },
        { L"Receive dest. address       ", L"                                          " },
        { L"IPv6-only                   ", L"                                          " },
        { L"Interface list              ", L"                                          " },
        { L"Unicast interface           ", L"                                          " },
        { L"Receive routing header      ", L"                                          " },
        { L"Receive type-of-service     ", L"                                          " },
        { L"Original arrival interface  ", L"                                          " },
        { L"Receive ECN                 ", L"                                          " },
        { L"Recveive ext. packet info   ", L"                                          " },
        { L"WFP redirect records        ", L"                                          " },
        { L"WFP redirect context        ", L"                                          " },
        { L"MTU discovery               ", L"                                          " },
        { L"Path MTU                    ", L"                                          " },
        { L"Receive ICMP errors         ", L"                                          " },
        { L"Upper MTU bound             ", L"                                          " },

        { L"No delay                    ", L"TCP_NODELAY                               " },
        { L"Expedited data              ", L"TCP_EXPEDITED_1122                        " },
        { L"Keep alive                  ", L"TCP_KEEPALIVE                             " },
        { L"Maximum segment size        ", L"TCP_MAXSEG                                " },
        { L"Retry timeout               ", L"TCP_MAXRT                                 " },
        { L"URG interpretation          ", L"TCP_STDURG                                " },
        { L"No URG                      ", L"TCP_NOURG                                 " },
        { L"At mark                     ", L"TCP_ATMARK                                " },
        { L"No SYN retries              ", L"TCP_NOSYNRETRIES                          " },
        { L"Timestamps                  ", L"TCP_TIMESTAMPS                            " },
        { L"Congestion algorithm        ", L"TCP_CONGESTION_ALGORITHM                  " },
        { L"Delay FIN ACK               ", L"TCP_DELAY_FIN_ACK                         " },
        { L"Retry timeout (precise)     ", L"TCP_MAXRTMS                               " },
        { L"Fast open                   ", L"TCP_FASTOPEN                              " },
        { L"Keep alive count            ", L"TCP_KEEPCNT                               " },
        { L"Keep alive interval         ", L"TCP_KEEPINTVL                             " },
        { L"Fail on ICMP error          ", L"TCP_FAIL_CONNECT_ON_ICMP_ERROR            " },

        { L"TCP state                   ", L"TCP_INFO_v0.State                         " },
        { L"Maximum segment size        ", L"TCP_INFO_v0.Mss                           " },
        { L"Connection time             ", L"TCP_INFO_v0.ConnectionTimeMs              " },
        { L"Timestamps enabled          ", L"TCP_INFO_v0.TimestampsEnabled             " },
        { L"Estimated round-trip        ", L"TCP_INFO_v0.RttUs                         " },
        { L"Minimal round-trip          ", L"TCP_INFO_v0.MinRttUs                      " },
        { L"Bytes in flight             ", L"TCP_INFO_v0.BytesInFlight                 " },
        { L"Congestion window           ", L"TCP_INFO_v0.Cwnd                          " },
        { L"Send window                 ", L"TCP_INFO_v0.SndWnd                        " },
        { L"Receive window              ", L"TCP_INFO_v0.RcvWnd                        " },
        { L"Receive buffer              ", L"TCP_INFO_v0.RcvBuf                        " },
        { L"Bytes sent                  ", L"TCP_INFO_v0.BytesOut                      " },
        { L"Bytes received              ", L"TCP_INFO_v0.BytesIn                       " },
        { L"Bytes reordered             ", L"TCP_INFO_v0.BytesReordered                " },
        { L"Bytes retransmitted         ", L"TCP_INFO_v0.BytesRetrans                  " },
        { L"Fast retransmits            ", L"TCP_INFO_v0.FastRetrans                   " },
        { L"Duplicate ACKs              ", L"TCP_INFO_v0.DupAcksIn                     " },
        { L"Timeout episodes            ", L"TCP_INFO_v0.TimeoutEpisodes               " },
        { L"SYN retransmits             ", L"TCP_INFO_v0.SynRetrans                    " },
        { L"Receiver-limited episodes   ", L"TCP_INFO_v1.SndLimTransRwin               " },
        { L"Receiver-limited time       ", L"TCP_INFO_v1.SndLimTimeRwin                " },
        { L"Receiver-limited bytes      ", L"TCP_INFO_v1.SndLimBytesRwin               " },
        { L"Congestion-limited episodes ", L"TCP_INFO_v1.SndLimTransCwnd               " },
        { L"Congestion-limited time     ", L"TCP_INFO_v1.SndLimTimeCwnd                " },
        { L"Congestion-limited bytes    ", L"TCP_INFO_v1.SndLimBytesCwnd               " },
        { L"Sender-limited episodes     ", L"TCP_INFO_v1.SndLimTransSnd                " },
        { L"Sender-limited time         ", L"TCP_INFO_v1.SndLimTimeSnd                 " },
        { L"Sender-limited bytes        ", L"TCP_INFO_v1.SndLimBytesSnd                " },
        { L"Out-of-order packets        ", L"TCP_INFO_v2.OutOfOrderPktsIn              " },
        { L"ECN negotiated              ", L"TCP_INFO_v2.EcnNegotiated                 " },
        { L"ECE ACKs                    ", L"TCP_INFO_v2.EceAcksIn                     " },
        { L"Probe timeout episodes      ", L"TCP_INFO_v2.PtoEpisodes                   " },

        { L"No checksum                 ", L"UDP_NOCHECKSUM                            " },
        { L"Maximum message size        ", L"UDP_SEND_MSG_SIZE                         " },
        { L"Maximum coalesced size      ", L"UDP_RECV_MAX_COALESCED_SIZE               " },

        { L"Connect timeout             ", L"HVSOCKET_CONNECT_TIMEOUT                  " },
        { L"Container passthru          ", L"HVSOCKET_CONTAINER_PASSTHRU               " },
        { L"Connected suspend           ", L"HVSOCKET_CONNECTED_SUSPEND                " },
        { L"High VTL                    ", L"HVSOCKET_HIGH_VTL                         " },
    };

    if (Property < 0 || Property >= H2_AFD_PROPERTY_MAX)
        return L"";

    return H2RawPrintMode ? names[Property].RawName : names[Property].FriendlyName;
}

/* Property printing */

/**
  * \brief Prints a property value as a string.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyString(
    _In_ H2_AFD_PROPERTY Property,
    _In_ PUNICODE_STRING Value
)
{
    wprintf_s(L"%s: %wZ\r\n", H2AfdGetPropertyName(Property), Value);
}

/**
  * \brief Prints a property value as a boolean.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyBoolean(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG Value
)
{
    if (H2RawPrintMode)
        wprintf_s(L"%s: 0x%X\r\n", H2AfdGetPropertyName(Property), Value);
    else
        wprintf_s(L"%s: %s\r\n", H2AfdGetPropertyName(Property), Value ? L"True" : L"False");
}

/**
  * \brief Prints a property value as a decimal number.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyDecimal(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG Value
)
{
    wprintf_s(L"%s: %d\r\n", H2AfdGetPropertyName(Property), Value);
}

/**
  * \brief Prints a property value as a hexadecimal number.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyHexadecimal(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG64 Value
)
{
    wprintf_s(L"%s: 0x%I64X\r\n", H2AfdGetPropertyName(Property), Value);
}

/**
  * \brief Prints a property value as a number of bytes.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyBytes(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG64 Value
)
{
    if (H2RawPrintMode)
    {
        wprintf_s(L"%s: %I64u bytes\r\n", H2AfdGetPropertyName(Property), Value);
    }
    else
    {
        wprintf_s(L"%s: ", H2AfdGetPropertyName(Property));
        H2PrintByteSize(Value);
        wprintf_s(L"\r\n");
    }
}

typedef enum _H2_TIME_UNIT
{
    H2_TIME_UNIT_US,
    H2_TIME_UNIT_MS,
    H2_TIME_UNIT_SEC,
} H2_TIME_UNIT;

/**
  * \brief Prints a property value as time duration or time ago.
  *
  * \param[in] Property A property index.
  * \param[in] Value A time duration.
  * \param[in] Units A type of units for the Value parameter.
  * \param[in] PrintAsTimeAgo Treats the duration as elapsed in the past from the current moment.
  * \param[in] MaxValueComment An optional string to use in place of ULONG_MAX values.
  */
VOID H2AfdPrintPropertyTime(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG64 Value,
    _In_ H2_TIME_UNIT Units,
    _In_ BOOLEAN PrintAsTimeAgo,
    _In_opt_ PCWSTR MaxValueComment
)
{
    PCWSTR units;
    ULONG64 multiplier;

    switch (Units)
    {
    case H2_TIME_UNIT_US:
        multiplier = TICKS_PER_US;
        units = L"us";
        break;
    case H2_TIME_UNIT_MS:
        multiplier = TICKS_PER_MS;
        units = L"ms";
        break;
    case H2_TIME_UNIT_SEC:
        multiplier = TICKS_PER_SEC;
        units = L"sec";
        break;
    default:
        multiplier = 1;
        units = L"ticks";
    }

    if (H2RawPrintMode)
    {
        wprintf_s(L"%s: %I64u %s\r\n", H2AfdGetPropertyName(Property), Value, units);
    }
    else if (Value == ULONG_MAX)
    {
        wprintf_s(L"%s: %s\r\n", H2AfdGetPropertyName(Property), MaxValueComment ? MaxValueComment : L"Unlimited");
    }
    else
    {
        wprintf_s(L"%s: ", H2AfdGetPropertyName(Property));
        H2PrintTimeSpan(Value * multiplier);

        if (PrintAsTimeAgo)
        {
            wprintf_s(L" ago (");
            H2PrintTimeStamp(((PLARGE_INTEGER)&USER_SHARED_DATA->SystemTime)->QuadPart - Value * multiplier);
            wprintf_s(L")");
        }

        wprintf_s(L"\r\n");
    }
}

/**
  * \brief Prints a property value as a GUID.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyGuid(
    _In_ H2_AFD_PROPERTY Property,
    _In_ PGUID Value
)
{
    wprintf_s(L"%s: ", H2AfdGetPropertyName(Property));
    H2PrintGuid(Value);
    wprintf_s(L"\r\n");
}

/**
  * \brief Prints an error associated with querying a property.
  *
  * \param[in] Property A property index.
  * \param[in] Status An NTSTATUS error.
  */
VOID H2AfdPrintPropertyStatus(
    _In_ H2_AFD_PROPERTY Property,
    _In_ NTSTATUS Status
)
{
    if (H2RawPrintMode)
        wprintf_s(L"%s: (query failed: 0x%0.8X)\r\n", H2AfdGetPropertyName(Property), Status);
    else
        wprintf_s(L"%s: \r\n", H2AfdGetPropertyName(Property));
}

/**
  * \brief Prints a numerical property value that might have an associated string representation.
  *
  * \param[in] Property A property index.
  * \param[in] Value A numeric value.
  * \param[in] ValueString An optional string representation of the value.
  */
VOID H2AfdPrintPropertyKnownValue(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG Value,
    _In_opt_ PCWSTR ValueString
)
{
    if (ValueString && !H2RawPrintMode)
        wprintf_s(L"%s: %s\r\n", H2AfdGetPropertyName(Property), ValueString);
    else
        wprintf_s(L"%s: %s (%d)\r\n", H2AfdGetPropertyName(Property), ValueString ? ValueString : L"<unrecognized>", Value);
}

/**
  * \brief Prints a property value as a socket state.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertySocketState(
    _In_ H2_AFD_PROPERTY Property,
    _In_ SOCKET_STATE Value
)
{
    H2AfdPrintPropertyKnownValue(Property, Value, H2AfdGetSocketStateString(Value, H2RawPrintMode));
}

/**
  * \brief Prints a property value as a socket type.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertySocketType(
    _In_ H2_AFD_PROPERTY Property,
    _In_ LONG Value
)
{
    H2AfdPrintPropertyKnownValue(Property, Value, H2AfdGetSocketTypeString(Value, H2RawPrintMode));
}

/**
  * \brief Prints a property value as an address family.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyAddressFamily(
    _In_ H2_AFD_PROPERTY Property,
    _In_ LONG Value
)
{
    H2AfdPrintPropertyKnownValue(Property, Value, H2AfdGetAddressFamilyString(Value, H2RawPrintMode));
}

/**
  * \brief Prints a property value as a protocol.
  *
  * \param[in] Property A property index.
  * \param[in] AddressFamily An address family for the protocol.
  * \param[in] Value A protocol value to print.
  */
VOID H2AfdPrintPropertyProtocol(
    _In_ H2_AFD_PROPERTY Property,
    _In_ LONG AddressFamily,
    _In_ LONG Value
)
{
    H2AfdPrintPropertyKnownValue(Property, Value, H2AfdGetProtocolString(AddressFamily, Value, H2RawPrintMode));
}

/**
  * \brief Prints a property value as a socket group type.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyGroupType(
    _In_ H2_AFD_PROPERTY Property,
    _In_ AFD_GROUP_TYPE Value
)
{
    H2AfdPrintPropertyKnownValue(Property, Value, H2AfdGetGroupTypeString(Value, H2RawPrintMode));
}

/**
  * \brief Prints a device name property from a file handle.
  *
  * \param[in] Property A property index.
  * \param[in] FileHandle A file handle value.
  */
VOID H2AfdPrintPropertyDeviceName(
    _In_ H2_AFD_PROPERTY Property,
    _In_ HANDLE FileHandle
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    BOOLEAN freeOnSuccess = FALSE;

    switch ((ULONG_PTR)FileHandle)
    {
    case (ULONG_PTR)INVALID_HANDLE_VALUE:
        RtlInitUnicodeString(&deviceName, H2RawPrintMode ? L"INVALID_HANDLE_VALUE" : L"N/A (transport is not TDI)");
        break;
    case NULL:
        RtlInitUnicodeString(&deviceName, H2RawPrintMode ? L"NULL" : L"None");
        break;
    default:
        status = H2AfdFormatDeviceName(FileHandle, &deviceName);
        freeOnSuccess = TRUE;
    }

    if (NT_SUCCESS(status))
    {
        wprintf_s(L"%s: %wZ\r\n", H2AfdGetPropertyName(Property), &deviceName);

        if (freeOnSuccess)
            RtlFreeUnicodeString(&deviceName);
    }
    else
    {
        H2AfdPrintPropertyStatus(Property, status);
    }
}

/**
  * \brief Prints a property value as an interface index (scope ID) or IP.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyInterface(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG Value
)
{
    wprintf_s(L"%s: ", H2AfdGetPropertyName(Property));

    if (Value & 0x000000FF)
    {
        IN_ADDR interfaceIp;
        WCHAR buffer[16];

        // Values with a non-zero first octet identify an interface by IP address
        interfaceIp.S_un.S_addr = Value;
        RtlIpv4AddressToStringW(&interfaceIp, buffer);
        wprintf_s(L"%s", buffer);
    }
    else if (Value)
    {
        // Other values (0.0.0.0/24 addresses) store a big-endian interface index/scope ID
        wprintf_s(L"%%%d", _byteswap_ulong(Value));
    }
    else
    {
        // The zero interface is special
        wprintf_s(L"Default");
    }

    if (H2RawPrintMode)
        wprintf_s(L" (0x%0.8X)", Value);

    wprintf_s(L"\r\n");
}

/**
  * \brief Prints a property value as an IPv6 protection level.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyProtectionLevel(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG Value
)
{
    H2AfdPrintPropertyKnownValue(Property, Value, H2AfdGetProtectionLevelString(Value, H2RawPrintMode));
}

/**
  * \brief Prints a property value as an MTU discovery mode.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyMtuDiscover(
    _In_ H2_AFD_PROPERTY Property,
    _In_ ULONG Value
)
{
    H2AfdPrintPropertyKnownValue(Property, Value, H2AfdGetMtuDiscoveryString(Value, H2RawPrintMode));
}

/**
  * \brief Prints a property value as a TCP state.
  *
  * \param[in] Property A property index.
  * \param[in] Value A value to print.
  */
VOID H2AfdPrintPropertyTcpState(
    _In_ H2_AFD_PROPERTY Property,
    _In_ TCPSTATE Value
)
{
    H2AfdPrintPropertyKnownValue(Property, Value, H2AfdGetTcpStateString(Value, H2RawPrintMode));
}

/* Query-and-print functions */

/**
  * \brief Query the shared Winsock context and print each property from it.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintSharedInfo(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    SOCK_SHARED_INFO SharedInfo;

    if (H2RawPrintMode)
        wprintf_s(L"[--------- IOCTL_AFD_GET_CONTEXT ---------]\r\n");
    else
        wprintf_s(L"[----- Winsock context -----]\r\n");

    if (NT_SUCCESS(status = H2AfdQuerySharedInfo(SocketHandle, &SharedInfo)))
    {
        H2AfdPrintPropertySocketState(H2_AFD_PROPERTY_SHARED_STATE, SharedInfo.State);
        H2AfdPrintPropertyAddressFamily(H2_AFD_PROPERTY_SHARED_ADDRESS_FAMILY, SharedInfo.AddressFamily);
        H2AfdPrintPropertySocketType(H2_AFD_PROPERTY_SHARED_SOCKET_TYPE, SharedInfo.SocketType);
        H2AfdPrintPropertyProtocol(H2_AFD_PROPERTY_SHARED_PROTOCOL, SharedInfo.AddressFamily, SharedInfo.Protocol);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_SHARED_LOCAL_ADDRESS_LENGTH, SharedInfo.LocalAddressLength);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_SHARED_REMOTE_ADDRESS_LENGTH, SharedInfo.RemoteAddressLength);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_LINGER_ONOFF, SharedInfo.LingerInfo.l_onoff);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_SHARED_LINGER_TIMEOUT, SharedInfo.LingerInfo.l_linger, H2_TIME_UNIT_SEC, FALSE, NULL);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_SHARED_SEND_TIMEOUT, SharedInfo.SendTimeout, H2_TIME_UNIT_MS, FALSE, NULL);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_SHARED_RECEIVE_TIMEOUT, SharedInfo.ReceiveTimeout, H2_TIME_UNIT_MS, FALSE, NULL);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_SHARED_RECEIVE_BUFFER_SIZE, SharedInfo.ReceiveBufferSize);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_SHARED_SEND_BUFFER_SIZE, SharedInfo.SendBufferSize);
        H2AfdPrintPropertyHexadecimal(H2_AFD_PROPERTY_SHARED_FLAGS, SharedInfo.Flags);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_LISTENING, SharedInfo.Listening);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_BROADCAST, SharedInfo.Broadcast);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_DEBUG, SharedInfo.Debug);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_OOB_INLINE, SharedInfo.OobInline);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_REUSE_ADDRESSES, SharedInfo.ReuseAddresses);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_EXCLUSIVE_ADDRESS_USE, SharedInfo.ExclusiveAddressUse);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_NON_BLOCKING, SharedInfo.NonBlocking);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_DONT_USE_WILDCARD, SharedInfo.DontUseWildcard);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_RECEIVE_SHUTDOWN, SharedInfo.ReceiveShutdown);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_SEND_SHUTDOWN, SharedInfo.SendShutdown);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_CONDITIONAL_ACCEPT, SharedInfo.ConditionalAccept);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_IS_SANSOCKET, SharedInfo.IsSANSocket);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_IS_TLI, SharedInfo.fIsTLI);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_RIO, SharedInfo.Rio);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_RECEIVE_BUFFER_SIZE_SET, SharedInfo.ReceiveBufferSizeSet);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_SEND_BUFFER_SIZE_SET, SharedInfo.SendBufferSizeSet);
        H2AfdPrintPropertyHexadecimal(H2_AFD_PROPERTY_SHARED_CREATION_FLAGS, SharedInfo.CreationFlags);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_WSA_FLAG_OVERLAPPED, SharedInfo.CreationFlags & WSA_FLAG_OVERLAPPED);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_WSA_FLAG_MULTIPOINT_C_ROOT, SharedInfo.CreationFlags & WSA_FLAG_MULTIPOINT_C_ROOT);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_WSA_FLAG_MULTIPOINT_C_LEAF, SharedInfo.CreationFlags & WSA_FLAG_MULTIPOINT_C_LEAF);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_WSA_FLAG_MULTIPOINT_D_ROOT, SharedInfo.CreationFlags & WSA_FLAG_MULTIPOINT_D_ROOT);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_WSA_FLAG_MULTIPOINT_D_LEAF, SharedInfo.CreationFlags & WSA_FLAG_MULTIPOINT_D_LEAF);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_WSA_FLAG_ACCESS_SYSTEM_SECURITY, SharedInfo.CreationFlags & WSA_FLAG_ACCESS_SYSTEM_SECURITY);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_WSA_FLAG_NO_HANDLE_INHERIT, SharedInfo.CreationFlags & WSA_FLAG_NO_HANDLE_INHERIT);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_WSA_FLAG_REGISTERED_IO, SharedInfo.CreationFlags & WSA_FLAG_REGISTERED_IO);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SHARED_CATALOG_ENTRY_ID, SharedInfo.CatalogEntryId);
        H2AfdPrintPropertyHexadecimal(H2_AFD_PROPERTY_SHARED_SERVICE_FLAGS, SharedInfo.ServiceFlags1);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_CONNECTIONLESS, SharedInfo.ServiceFlags1 & XP1_CONNECTIONLESS);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_GUARANTEED_DELIVERY, SharedInfo.ServiceFlags1 & XP1_GUARANTEED_DELIVERY);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_GUARANTEED_ORDER, SharedInfo.ServiceFlags1 & XP1_GUARANTEED_ORDER);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_MESSAGE_ORIENTED, SharedInfo.ServiceFlags1 & XP1_MESSAGE_ORIENTED);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_PSEUDO_STREAM, SharedInfo.ServiceFlags1 & XP1_PSEUDO_STREAM);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_GRACEFUL_CLOSE, SharedInfo.ServiceFlags1 & XP1_GRACEFUL_CLOSE);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_EXPEDITED_DATA, SharedInfo.ServiceFlags1 & XP1_EXPEDITED_DATA);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_CONNECT_DATA, SharedInfo.ServiceFlags1 & XP1_CONNECT_DATA);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_DISCONNECT_DATA, SharedInfo.ServiceFlags1 & XP1_DISCONNECT_DATA);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_SUPPORT_BROADCAST, SharedInfo.ServiceFlags1 & XP1_SUPPORT_BROADCAST);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_SUPPORT_MULTIPOINT, SharedInfo.ServiceFlags1 & XP1_SUPPORT_MULTIPOINT);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_MULTIPOINT_CONTROL_PLANE, SharedInfo.ServiceFlags1 & XP1_MULTIPOINT_CONTROL_PLANE);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_MULTIPOINT_DATA_PLANE, SharedInfo.ServiceFlags1 & XP1_MULTIPOINT_DATA_PLANE);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_QOS_SUPPORTED, SharedInfo.ServiceFlags1 & XP1_QOS_SUPPORTED);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_INTERRUPT, SharedInfo.ServiceFlags1 & XP1_INTERRUPT);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_UNI_SEND, SharedInfo.ServiceFlags1 & XP1_UNI_SEND);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_UNI_RECV, SharedInfo.ServiceFlags1 & XP1_UNI_RECV);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_IFS_HANDLES, SharedInfo.ServiceFlags1 & XP1_IFS_HANDLES);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_PARTIAL_MESSAGE, SharedInfo.ServiceFlags1 & XP1_PARTIAL_MESSAGE);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_XP1_SAN_SUPPORT_SDP, SharedInfo.ServiceFlags1 & XP1_SAN_SUPPORT_SDP);
        H2AfdPrintPropertyHexadecimal(H2_AFD_PROPERTY_SHARED_PROVIDER_FLAGS, SharedInfo.ProviderFlags);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_PFL_MULTIPLE_PROTO_ENTRIES, SharedInfo.ProviderFlags & PFL_MULTIPLE_PROTO_ENTRIES);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_PFL_RECOMMENDED_PROTO_ENTRY, SharedInfo.ProviderFlags & PFL_RECOMMENDED_PROTO_ENTRY);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_PFL_HIDDEN, SharedInfo.ProviderFlags & PFL_HIDDEN);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_PFL_MATCHES_PROTOCOL_ZERO, SharedInfo.ProviderFlags & PFL_MATCHES_PROTOCOL_ZERO);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SHARED_PFL_NETWORKDIRECT_PROVIDER, SharedInfo.ProviderFlags & PFL_NETWORKDIRECT_PROVIDER);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SHARED_GROUP_ID, SharedInfo.GroupID);
        H2AfdPrintPropertyGroupType(H2_AFD_PROPERTY_SHARED_GROUP_TYPE, SharedInfo.GroupType);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SHARED_GROUP_PRIORITY, SharedInfo.GroupPriority);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SHARED_LAST_ERROR, SharedInfo.LastError);
        H2AfdPrintPropertyHexadecimal(H2_AFD_PROPERTY_SHARED_ASYNC_SELECT_WND, SharedInfo.AsyncSelectWnd64);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SHARED_ASYNC_SELECT_SERIAL_NUMBER, SharedInfo.AsyncSelectSerialNumber);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SHARED_ASYNC_SELECTW_MSG, SharedInfo.AsyncSelectwMsg);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SHARED_ASYNC_SELECTL_EVENT, SharedInfo.AsyncSelectlEvent);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SHARED_DISABLED_ASYNC_SELECT_EVENTS, SharedInfo.DisabledAsyncSelectEvents);
        H2AfdPrintPropertyGuid(H2_AFD_PROPERTY_SHARED_PROVIDER_ID, &SharedInfo.ProviderId);
    }
    else
    {
        for (ULONG i = H2_AFD_PROPERTY_SHARED_STATE; i <= H2_AFD_PROPERTY_SHARED_PROVIDER_ID; i++)
            H2AfdPrintPropertyStatus((H2_AFD_PROPERTY)i, status);
    }

    wprintf_s(L"\r\n");
}

/**
  * \brief Queries and formats a socket address to a string.
  *
  * \param[in] SocketHandle An AFD socket handle.
  * \param[in] Remote Whether the function should return a remote or a local address.
  * \param[in] FormattingFlags A bit masks of flags that control the function's behavior, such as H2_AFD_ADDRESS_SIMPLIFY.
  * \param[out] AddressString A pointer to a UNICODE_STRING that receives the address string. The caller becomes
  *            responsible for freeing the string via RtlFreeUnicodeString.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdQueryFormatAddress(
    _In_ HANDLE SocketHandle,
    _In_ BOOLEAN Remote,
    _In_ ULONG FormattingFlags,
    _Out_ PUNICODE_STRING AddressString
)
{
    NTSTATUS status;
    SOCKADDR_STORAGE address;

    status = H2AfdQueryAddress(SocketHandle, Remote, &address);

    if (!NT_SUCCESS(status))
        return status;

    return H2AfdFormatAddress(&address, FormattingFlags, AddressString);
}

/**
  * \brief Query and print addresses from a socket.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintAddresses(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    UNICODE_STRING addressString;

    if (H2RawPrintMode)
        wprintf_s(L"[--------------- Addresses ---------------]\r\n");
    else
        wprintf_s(L"[-------- Addresses --------]\r\n");

    // Local address
    if (NT_SUCCESS(status = H2AfdQueryFormatAddress(SocketHandle, FALSE, 0, &addressString)))
    {
        H2AfdPrintPropertyString(H2_AFD_PROPERTY_LOCAL_ADDRESS, &addressString);
        RtlFreeUnicodeString(&addressString);
    }
    else
    {
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_LOCAL_ADDRESS, status);
    }

    // Remote address
    if (NT_SUCCESS(status = H2AfdQueryFormatAddress(SocketHandle, TRUE, 0, &addressString)))
    {
        H2AfdPrintPropertyString(H2_AFD_PROPERTY_REMOTE_ADDRESS, &addressString);
        RtlFreeUnicodeString(&addressString);
    }
    else
    {
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_REMOTE_ADDRESS, status);
    }

    wprintf_s(L"\r\n");
}

/**
  * \brief Query AFD info classes and print them as properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintSimpleInfo(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    AFD_INFORMATION info;

    if (H2RawPrintMode)
        wprintf_s(L"[------- IOCTL_AFD_GET_INFORMATION -------]\r\n");
    else
        wprintf_s(L"[---- AFD info classes -----]\r\n");

    // Maximum send size
    if (NT_SUCCESS(status = H2AfdQuerySimpleInfo(SocketHandle, AFD_MAX_SEND_SIZE, &info)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_AFD_MAX_SEND_SIZE, info.Information.Ulong);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_AFD_MAX_SEND_SIZE, status);

    // Pending sends
    if (NT_SUCCESS(status = H2AfdQuerySimpleInfo(SocketHandle, AFD_SENDS_PENDING, &info)))
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_AFD_SENDS_PENDING, info.Information.Ulong);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_AFD_SENDS_PENDING, status);

    // Maximum path send size
    if (NT_SUCCESS(status = H2AfdQuerySimpleInfo(SocketHandle, AFD_MAX_PATH_SEND_SIZE, &info)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_AFD_MAX_PATH_SEND_SIZE, info.Information.Ulong);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_AFD_MAX_PATH_SEND_SIZE, status);

    // Receive window size
    if (NT_SUCCESS(status = H2AfdQuerySimpleInfo(SocketHandle, AFD_RECEIVE_WINDOW_SIZE, &info)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_AFD_RECEIVE_WINDOW_SIZE, info.Information.Ulong);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_AFD_RECEIVE_WINDOW_SIZE, status);

    // Send window size
    if (NT_SUCCESS(status = H2AfdQuerySimpleInfo(SocketHandle, AFD_SEND_WINDOW_SIZE, &info)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_AFD_SEND_WINDOW_SIZE, info.Information.Ulong);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_AFD_SEND_WINDOW_SIZE, status);

    // Connect time
    if (NT_SUCCESS(status = H2AfdQuerySimpleInfo(SocketHandle, AFD_CONNECT_TIME, &info)))
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_AFD_CONNECT_TIME, info.Information.Ulong, H2_TIME_UNIT_SEC, TRUE, L"N/A (not connected)");
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_AFD_CONNECT_TIME, status);

    // Group ID & group type
    if (NT_SUCCESS(status = H2AfdQuerySimpleInfo(SocketHandle, AFD_GROUP_ID_AND_TYPE, &info)))
    {
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_AFD_GROUP_ID, info.Information.GroupInfo.GroupID);
        H2AfdPrintPropertyGroupType(H2_AFD_PROPERTY_AFD_GROUP_TYPE, info.Information.GroupInfo.GroupType);
    }
    else
    {
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_AFD_GROUP_ID, status);
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_AFD_GROUP_TYPE, status);
    }

    wprintf_s(L"\r\n");
}

/**
  * \brief Query and print TDI devices properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintTDIDevices(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    HANDLE tdiHandle;

    if (H2RawPrintMode)
        wprintf_s(L"[-------- IOCTL_AFD_QUERY_HANDLES --------]\r\n");
    else
        wprintf_s(L"[------- TDI devices -------]\r\n");

    // TDI address device
    if (NT_SUCCESS(status = H2AfdQueryTdiHandle(SocketHandle, AFD_QUERY_ADDRESS_HANDLE, &tdiHandle)))
    {
        H2AfdPrintPropertyDeviceName(H2_AFD_PROPERTY_TDI_ADDRESS_DEVICE, tdiHandle);

        if (tdiHandle != INVALID_HANDLE_VALUE && tdiHandle != NULL)
            NtClose(tdiHandle);
    }
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TDI_ADDRESS_DEVICE, status);

    // TDI connection device
    if (NT_SUCCESS(status = H2AfdQueryTdiHandle(SocketHandle, AFD_QUERY_CONNECTION_HANDLE, &tdiHandle)))
    {
        H2AfdPrintPropertyDeviceName(H2_AFD_PROPERTY_TDI_CONNECTION_DEVICE, tdiHandle);

        if (tdiHandle != INVALID_HANDLE_VALUE && tdiHandle != NULL)
            NtClose(tdiHandle);
    }
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TDI_CONNECTION_DEVICE, status);

    wprintf_s(L"\r\n");
}

/**
  * \brief Query and print socket-level option properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintPropertiesSol(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    ULONG option;

    if (H2RawPrintMode)
        wprintf_s(L"[-- IOCTL_AFD_TRANSPORT_IOCTL on SOL_SOCKET --]\r\n");
    else
        wprintf_s(L"[--- Socket-level options --]\r\n");

    // Reuse address
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_REUSEADDR, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_REUSEADDR, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_REUSEADDR, status);

    // Keep alive
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_KEEPALIVE, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_KEEPALIVE, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_KEEPALIVE, status);

    // Don't route
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_DONTROUTE, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_DONTROUTE, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_DONTROUTE, status);

    // Broadcast
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_BROADCAST, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_BROADCAST, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_BROADCAST, status);

    // OOB in line
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_OOBINLINE, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_OOBINLINE, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_OOBINLINE, status);

    // Receive buffer size
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_RCVBUF, &option)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_SO_RCVBUF, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_RCVBUF, status);

    // Maximum message size
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_MAX_MSG_SIZE, &option)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_SO_MAX_MSG_SIZE, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_MAX_MSG_SIZE, status);

    // Conditional accept
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_CONDITIONAL_ACCEPT, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_CONDITIONAL_ACCEPT, status);

    // Pause accept
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_PAUSE_ACCEPT, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_PAUSE_ACCEPT, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_PAUSE_ACCEPT, status);

    // Compartment ID
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_COMPARTMENT_ID, &option)))
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_SO_COMPARTMENT_ID, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_COMPARTMENT_ID, status);

    // Randomize port
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_RANDOMIZE_PORT, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_RANDOMIZE_PORT, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_RANDOMIZE_PORT, status);

    // Port scalability
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_PORT_SCALABILITY, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_PORT_SCALABILITY, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_PORT_SCALABILITY, status);

    // Reuse unicast port
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_REUSE_UNICASTPORT, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_REUSE_UNICASTPORT, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_REUSE_UNICASTPORT, status);

    // Exclusive address use
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_SO_EXCLUSIVEADDRUSE, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_SO_EXCLUSIVEADDRUSE, status);

    wprintf_s(L"\r\n");
}

/**
  * \brief Query and print IP-level option properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintPropertiesIp(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    ULONG option;

    if (H2RawPrintMode)
    {
        wprintf_s(L"[-- IOCTL_AFD_TRANSPORT_IOCTL on IPPROTO_IP --]\r\n");

        // Header included (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_HDRINCL, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_HDRINCL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_HDRINCL, status);

        // Type-of-service (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_TOS, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IP_TOS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_TOS, status);

        // Unicast TTL (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_TTL, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IP_TTL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_TTL, status);

        // Multicast interface (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MULTICAST_IF, &option)))
            H2AfdPrintPropertyInterface(H2_AFD_PROPERTY_IP_MULTICAST_IF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_MULTICAST_IF, status);

        // Multicast TTL (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MULTICAST_TTL, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IP_MULTICAST_TTL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_MULTICAST_TTL, status);

        // Multicast loopback (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MULTICAST_LOOP, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_MULTICAST_LOOP, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_MULTICAST_LOOP, status);

        // Don't fragment (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_DONTFRAGMENT, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_DONTFRAGMENT, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_DONTFRAGMENT, status);

        // Receive packet info (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_PKTINFO, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_PKTINFO, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_PKTINFO, status);

        // Receive TTL (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVTTL, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_RECVTTL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_RECVTTL, status);

        // Broadcast reception (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECEIVE_BROADCAST, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_RECEIVE_BROADCAST, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_RECEIVE_BROADCAST, status);

        // Receive arrival interface (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVIF, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_RECVIF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_RECVIF, status);

        // Receive dest. address (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVDSTADDR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_RECVDSTADDR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_RECVDSTADDR, status);

        // Interface list (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_IFLIST, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_IFLIST, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_IFLIST, status);

        // Unicast interface (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_UNICAST_IF, &option)))
            H2AfdPrintPropertyInterface(H2_AFD_PROPERTY_IP_UNICAST_IF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_UNICAST_IF, status);

        // Receive routing header (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVRTHDR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_RECVRTHDR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_RECVRTHDR, status);

        // Receive type-of-service (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVTOS, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_RECVTOS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_RECVTOS, status);

        // Original arrival interface (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_ORIGINAL_ARRIVAL_IF, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_ORIGINAL_ARRIVAL_IF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_ORIGINAL_ARRIVAL_IF, status);

        // Receive ECN (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVECN, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_RECVECN, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_RECVECN, status);

        // Recveive ext. packet info (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_PKTINFO_EX, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_PKTINFO_EX, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_PKTINFO_EX, status);

        // WFP redirect records (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_WFP_REDIRECT_RECORDS, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_WFP_REDIRECT_RECORDS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_WFP_REDIRECT_RECORDS, status);

        // WFP redirect context (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_WFP_REDIRECT_CONTEXT, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_WFP_REDIRECT_CONTEXT, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_WFP_REDIRECT_CONTEXT, status);

        // MTU discovery (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MTU_DISCOVER, &option)))
            H2AfdPrintPropertyMtuDiscover(H2_AFD_PROPERTY_IP_MTU_DISCOVER, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_MTU_DISCOVER, status);

        // Path MTU (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MTU, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IP_MTU, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_MTU, status);

        // Receive ICMP errors (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVERR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IP_RECVERR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_RECVERR, status);

        // Upper MTU bound (v4-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_USER_MTU, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IP_USER_MTU, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IP_USER_MTU, status);

        wprintf_s(L"\r\n");
        wprintf_s(L"[-- IOCTL_AFD_TRANSPORT_IOCTL on IPPROTO_IPV6 --]\r\n");

        // Header included (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_HDRINCL, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_HDRINCL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_HDRINCL, status);

        // Unicast TTL (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPV6_UNICAST_HOPS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_UNICAST_HOPS, status);

        // Multicast interface (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MULTICAST_IF, &option)))
            H2AfdPrintPropertyInterface(H2_AFD_PROPERTY_IPV6_MULTICAST_IF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_MULTICAST_IF, status);

        // Multicast TTL (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPV6_MULTICAST_HOPS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_MULTICAST_HOPS, status);

        // Multicast loopback (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_MULTICAST_LOOP, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_MULTICAST_LOOP, status);

        // Don't fragment (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_DONTFRAG, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_DONTFRAG, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_DONTFRAG, status);

        // Receive packet info (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_PKTINFO, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_PKTINFO, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_PKTINFO, status);

        // Receive TTL (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_HOPLIMIT, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_HOPLIMIT, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_HOPLIMIT, status);

        // IPv6 protection level (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, &option)))
            H2AfdPrintPropertyProtectionLevel(H2_AFD_PROPERTY_IPV6_PROTECTION_LEVEL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_PROTECTION_LEVEL, status);

        // Receive arrival interface (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVIF, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_RECVIF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_RECVIF, status);

        // Receive dest. address (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVDSTADDR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_RECVDSTADDR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_RECVDSTADDR, status);

        // IPv6-only (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_V6ONLY, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_V6ONLY, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_V6ONLY, status);

        // Interface list (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_IFLIST, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_IFLIST, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_IFLIST, status);

        // Unicast interface (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_UNICAST_IF, &option)))
            H2AfdPrintPropertyInterface(H2_AFD_PROPERTY_IPV6_UNICAST_IF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_UNICAST_IF, status);

        // Receive routing header (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVRTHDR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_RECVRTHDR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_RECVRTHDR, status);

        // Receive type-of-service (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVTCLASS, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_RECVTCLASS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_RECVTCLASS, status);

        // Receive ECN (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVECN, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_RECVECN, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_RECVECN, status);

        // Recveive ext. packet info (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_PKTINFO_EX, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_PKTINFO_EX, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_PKTINFO_EX, status);

        // WFP redirect records (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_WFP_REDIRECT_RECORDS, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_WFP_REDIRECT_RECORDS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_WFP_REDIRECT_RECORDS, status);

        // WFP redirect context (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_WFP_REDIRECT_CONTEXT, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_WFP_REDIRECT_CONTEXT, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_WFP_REDIRECT_CONTEXT, status);

        // MTU discovery (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &option)))
            H2AfdPrintPropertyMtuDiscover(H2_AFD_PROPERTY_IPV6_MTU_DISCOVER, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_MTU_DISCOVER, status);

        // Path MTU (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MTU, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPV6_MTU, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_MTU, status);

        // Receive ICMP errors (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVERR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPV6_RECVERR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_RECVERR, status);

        // Upper MTU bound (v6-only)
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_USER_MTU, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPV6_USER_MTU, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPV6_USER_MTU, status);

        wprintf_s(L"\r\n");
    }
    else
    {
        wprintf_s(L"[----- IP-level options ----]\r\n");

        // Header included
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_HDRINCL, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_HDRINCL, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_HDRINCL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_HDRINCL, status);

        // Type-of-service
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_TOS, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPALL_TOS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_TOS, status);

        // Unicast TTL
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_TTL, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPALL_TTL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_TTL, status);

        // Multicast interface
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MULTICAST_IF, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MULTICAST_IF, &option)))
            H2AfdPrintPropertyInterface(H2_AFD_PROPERTY_IPALL_MULTICAST_IF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_MULTICAST_IF, status);

        // Multicast TTL
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MULTICAST_TTL, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPALL_MULTICAST_TTL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_MULTICAST_TTL, status);

        // Multicast loopback
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MULTICAST_LOOP, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_MULTICAST_LOOP, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_MULTICAST_LOOP, status);

        // Don't fragment
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_DONTFRAGMENT, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_DONTFRAG, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_DONTFRAGMENT, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_DONTFRAGMENT, status);

        // Receive packet info
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_PKTINFO, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_PKTINFO, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_PKTINFO, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_PKTINFO, status);

        // Receive TTL
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVTTL, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_HOPLIMIT, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_RECVTTL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_RECVTTL, status);

        // Broadcast reception
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECEIVE_BROADCAST, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_RECEIVE_BROADCAST, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_RECEIVE_BROADCAST, status);

        // IPv6 protection level
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, &option)))
            H2AfdPrintPropertyProtectionLevel(H2_AFD_PROPERTY_IPALL_PROTECTION_LEVEL, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_PROTECTION_LEVEL, status);

        // Receive arrival interface
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVIF, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVIF, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_RECVIF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_RECVIF, status);

        // Receive dest. address
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVDSTADDR, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVDSTADDR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_RECVDSTADDR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_RECVDSTADDR, status);

        // IPv6-only
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_V6ONLY, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_V6ONLY, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_V6ONLY, status);

        // Interface list
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_IFLIST, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_IFLIST, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_IFLIST, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_IFLIST, status);

        // Unicast interface
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_UNICAST_IF, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_UNICAST_IF, &option)))
            H2AfdPrintPropertyInterface(H2_AFD_PROPERTY_IPALL_UNICAST_IF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_UNICAST_IF, status);

        // Receive routing header
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVRTHDR, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVRTHDR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_RECVRTHDR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_RECVRTHDR, status);

        // Receive type-of-service
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVTOS, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVTCLASS, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_RECVTOS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_RECVTOS, status);

        // Original arrival interface
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_ORIGINAL_ARRIVAL_IF, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_ORIGINAL_ARRIVAL_IF, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_ORIGINAL_ARRIVAL_IF, status);

        // Receive ECN
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVECN, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVECN, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_RECVECN, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_RECVECN, status);

        // Recveive ext. packet info
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_PKTINFO_EX, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_PKTINFO_EX, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_PKTINFO_EX, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_PKTINFO_EX, status);

        // WFP redirect records
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_WFP_REDIRECT_RECORDS, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_WFP_REDIRECT_RECORDS, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_WFP_REDIRECT_RECORDS, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_WFP_REDIRECT_RECORDS, status);

        // WFP redirect context
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_WFP_REDIRECT_CONTEXT, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_WFP_REDIRECT_CONTEXT, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_WFP_REDIRECT_CONTEXT, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_WFP_REDIRECT_CONTEXT, status);

        // MTU discovery
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MTU_DISCOVER, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &option)))
            H2AfdPrintPropertyMtuDiscover(H2_AFD_PROPERTY_IPALL_MTU_DISCOVER, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_MTU_DISCOVER, status);

        // Path MTU
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_MTU, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_MTU, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPALL_MTU, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_MTU, status);

        // Receive ICMP errors
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_RECVERR, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_RECVERR, &option)))
            H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_IPALL_RECVERR, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_RECVERR, status);

        // Upper MTU bound
        if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IP, IP_USER_MTU, &option)) ||
            NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_IPV6, IPV6_USER_MTU, &option)))
            H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_IPALL_USER_MTU, option);
        else
            H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_IPALL_USER_MTU, status);

        wprintf_s(L"\r\n");
    }
}

/**
  * \brief Query and print TCP-level option properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintPropertiesTcp(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    ULONG option;

    if (H2RawPrintMode)
        wprintf_s(L"[-- IOCTL_AFD_TRANSPORT_IOCTL on IPPROTO_TCP --]\r\n");
    else
        wprintf_s(L"[---- TCP-level options ----]\r\n");

    // No delay
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_NODELAY, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_NODELAY, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_NODELAY, status);

    // Expedited data
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_EXPEDITED_1122, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_EXPEDITED, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_EXPEDITED, status);

    // Keep alive
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_KEEPALIVE, &option)))
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_KEEPALIVE, option, H2_TIME_UNIT_SEC, FALSE, NULL);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_KEEPALIVE, status);

    // Maximum segment size
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_MAXSEG, &option)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_MAXSEG, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_MAXSEG, status);

    // Retry timeout
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_MAXRT, &option)))
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_MAXRT, option, H2_TIME_UNIT_SEC, FALSE, NULL);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_MAXRT, status);

    // URG interpretation
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_STDURG, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_STDURG, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_STDURG, status);

    // No URG
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_NOURG, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_NOURG, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_NOURG, status);

    // At mark
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_ATMARK, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_ATMARK, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_ATMARK, status);

    // No SYN retries
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_NOSYNRETRIES, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_NOSYNRETRIES, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_NOSYNRETRIES, status);

    // Timestamps
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_TIMESTAMPS, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_TIMESTAMPS, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_TIMESTAMPS, status);

    // Congestion algorithm
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_CONGESTION_ALGORITHM, &option)))
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_CONGESTION_ALGORITHM, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_CONGESTION_ALGORITHM, status);

    // Delay FIN ACK
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_DELAY_FIN_ACK, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_DELAY_FIN_ACK, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_DELAY_FIN_ACK, status);

    // Retry timeout (precise)
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_MAXRTMS, &option)))
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_MAXRTMS, option, H2_TIME_UNIT_MS, FALSE, NULL);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_MAXRTMS, status);

    // Fast open
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_FASTOPEN, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_FASTOPEN, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_FASTOPEN, status);

    // Keep alive count
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_KEEPCNT, &option)))
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_KEEPCNT, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_KEEPCNT, status);

    // Keep alive interval
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_KEEPINTVL, &option)))
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_KEEPINTVL, option, H2_TIME_UNIT_SEC, FALSE, NULL);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_KEEPINTVL, status);

    // Fail on ICMP error
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_TCP, TCP_FAIL_CONNECT_ON_ICMP_ERROR, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_FAIL_CONNECT_ON_ICMP_ERROR, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_TCP_FAIL_CONNECT_ON_ICMP_ERROR, status);

    wprintf_s(L"\r\n");
}

/**
  * \brief Query and print TCP information properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintPropertiesTcpInfo(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status[3];
    TCP_INFO_v2 tcpInfo;

    if (H2RawPrintMode)
        wprintf_s(L"[-- IOCTL_AFD_TRANSPORT_IOCTL on SIO_TCP_INFO --]\r\n");
    else
        wprintf_s(L"[----- TCP information -----]\r\n");

    // Try v2 first
    status[2] = H2AfdQueryTcpInfo(SocketHandle, 2, &tcpInfo);

    if (NT_SUCCESS(status[2]))
    {
        // Count success for v1 and v0 also
        status[0] = status[1] = status[2];
    }
    else
    {
        // Try v1 next
        status[1] = H2AfdQueryTcpInfo(SocketHandle, 1, &tcpInfo);

        if (NT_SUCCESS(status[1]))
        {
            // Count success for v0 also
            status[0] = status[1];
        }
        else
        {
            // Finally, try v0
            status[0] = H2AfdQueryTcpInfo(SocketHandle, 0, &tcpInfo);
        }
    }

    if (NT_SUCCESS(status[0]))
    {
        // Print v0
        H2AfdPrintPropertyTcpState(H2_AFD_PROPERTY_TCP_INFO_STATE, tcpInfo.State);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_MSS, tcpInfo.Mss);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_INFO_CONNECTION_TIME, tcpInfo.ConnectionTimeMs, H2_TIME_UNIT_MS, TRUE, NULL);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_INFO_TIMESTAMPS_ENABLED, tcpInfo.TimestampsEnabled);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_INFO_RTT, tcpInfo.RttUs, H2_TIME_UNIT_US, FALSE, NULL);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_INFO_MINRTT, tcpInfo.MinRttUs, H2_TIME_UNIT_US, FALSE, NULL);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_BYTES_IN_FLIGHT, tcpInfo.BytesInFlight);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_CONGESTION_WINDOW, tcpInfo.Cwnd);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_SEND_WINDOW, tcpInfo.SndWnd);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_RECEIVE_WINDOW, tcpInfo.RcvWnd);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_RECEIVE_BUFFER, tcpInfo.RcvBuf);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_BYTES_OUT, tcpInfo.BytesOut);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_BYTES_IN, tcpInfo.BytesIn);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_BYTES_REORDERED, tcpInfo.BytesReordered);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_BYTES_RETRANSMITTED, tcpInfo.BytesRetrans);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_FAST_RETRANSMIT, tcpInfo.FastRetrans);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_DUPLICATE_ACKS_IN, tcpInfo.DupAcksIn);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_TIMEOUT_EPISODES, tcpInfo.TimeoutEpisodes);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_SYN_RETRANSMITS, tcpInfo.SynRetrans);
    }
    else
    {
        // Report failed v0
        for (ULONG i = H2_AFD_PROPERTY_TCP_INFO_STATE; i <= H2_AFD_PROPERTY_TCP_INFO_SYN_RETRANSMITS; i++)
            H2AfdPrintPropertyStatus((H2_AFD_PROPERTY)i, status[0]);
    }

    if (NT_SUCCESS(status[1]))
    {
        // Print v1
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_RECEIVER_LIMITED_TRANSITIONS, tcpInfo.SndLimTransRwin);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_INFO_RECEIVER_LIMITED_TIME, tcpInfo.SndLimTimeRwin, H2_TIME_UNIT_MS, FALSE, NULL);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_RECEIVER_LIMITED_BYTES, tcpInfo.SndLimBytesRwin);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_CONGESTION_LIMITED_TRANSITIONS, tcpInfo.SndLimTransCwnd);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_INFO_CONGESTION_LIMITED_TIME, tcpInfo.SndLimTimeCwnd, H2_TIME_UNIT_MS, FALSE, NULL);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_CONGESTION_LIMITED_BYTES, tcpInfo.SndLimBytesCwnd);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_SENDER_LIMITED_TRANSITIONS, tcpInfo.SndLimTransSnd);
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_TCP_INFO_SENDER_LIMITED_TIME, tcpInfo.SndLimTimeSnd, H2_TIME_UNIT_MS, FALSE, NULL);
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_TCP_INFO_SENDER_LIMITED_BYTES, tcpInfo.SndLimBytesSnd);
    }
    else
    {
        // Report failed v1
        for (ULONG i = H2_AFD_PROPERTY_TCP_INFO_RECEIVER_LIMITED_TRANSITIONS; i <= H2_AFD_PROPERTY_TCP_INFO_SENDER_LIMITED_BYTES; i++)
            H2AfdPrintPropertyStatus((H2_AFD_PROPERTY)i, status[1]);
    }

    if (NT_SUCCESS(status[2]))
    {
        // Print v2
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_OUT_OF_ORDER_PACKETS, tcpInfo.OutOfOrderPktsIn);
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_TCP_INFO_ECN_NEGOTIATED, tcpInfo.EcnNegotiated);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_ECE_ACKS_IN, tcpInfo.EceAcksIn);
        H2AfdPrintPropertyDecimal(H2_AFD_PROPERTY_TCP_INFO_PTO_EPISODES, tcpInfo.PtoEpisodes);
    }
    else
    {
        // Report failed v2
        for (ULONG i = H2_AFD_PROPERTY_TCP_INFO_OUT_OF_ORDER_PACKETS; i <= H2_AFD_PROPERTY_TCP_INFO_PTO_EPISODES; i++)
            H2AfdPrintPropertyStatus((H2_AFD_PROPERTY)i, status[2]);
    }

    wprintf_s(L"\r\n");
}

/**
  * \brief Query and print UDP-level option properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintPropertiesUdp(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    ULONG option;

    if (H2RawPrintMode)
        wprintf_s(L"[-- IOCTL_AFD_TRANSPORT_IOCTL on IPPROTO_UDP --]\r\n");
    else
        wprintf_s(L"[---- UDP-level options ----]\r\n");

    // No checksum
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_UDP, UDP_NOCHECKSUM, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_UDP_NOCHECKSUM, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_UDP_NOCHECKSUM, status);

    // Maximum message size
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_UDP, UDP_SEND_MSG_SIZE, &option)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_UDP_SEND_MSG_SIZE, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_UDP_SEND_MSG_SIZE, status);

    // Maximum coalesced size
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, &option)))
        H2AfdPrintPropertyBytes(H2_AFD_PROPERTY_UDP_RECV_MAX_COALESCED_SIZE, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_UDP_RECV_MAX_COALESCED_SIZE, status);

    wprintf_s(L"\r\n");
}

/**
  * \brief Query and print Hyper-V-level option properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintPropertiesHv(
    _In_ HANDLE SocketHandle
)
{
    NTSTATUS status;
    ULONG option;

    if (H2RawPrintMode)
        wprintf_s(L"[-- IOCTL_AFD_TRANSPORT_IOCTL on HV_PROTOCOL_RAW --]\r\n");
    else
        wprintf_s(L"[-- Hyper-V-level options --]\r\n");

    // Connect timeout
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, HV_PROTOCOL_RAW, HVSOCKET_CONNECT_TIMEOUT, &option)))
        H2AfdPrintPropertyTime(H2_AFD_PROPERTY_HVSOCKET_CONNECT_TIMEOUT, option, H2_TIME_UNIT_MS, FALSE, NULL);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_HVSOCKET_CONNECT_TIMEOUT, status);

    // Container passthru
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, HV_PROTOCOL_RAW, HVSOCKET_CONTAINER_PASSTHRU, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_HVSOCKET_CONTAINER_PASSTHRU, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_HVSOCKET_CONTAINER_PASSTHRU, status);

    // Connected suspend
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, HV_PROTOCOL_RAW, HVSOCKET_CONNECTED_SUSPEND, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_HVSOCKET_CONNECTED_SUSPEND, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_HVSOCKET_CONNECTED_SUSPEND, status);

    // High VTL
    if (NT_SUCCESS(status = H2AfdQueryOption(SocketHandle, HV_PROTOCOL_RAW, HVSOCKET_HIGH_VTL, &option)))
        H2AfdPrintPropertyBoolean(H2_AFD_PROPERTY_HVSOCKET_HIGH_VTL, option);
    else
        H2AfdPrintPropertyStatus(H2_AFD_PROPERTY_HVSOCKET_HIGH_VTL, status);
}

/**
  * \brief Query and print all socket properties.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintDetailsSocket(
    _In_ HANDLE SocketHandle,
    _In_ BOOLEAN VerboseMode
)
{
    ULONG option;

    H2RawPrintMode = VerboseMode;
    H2AfdQueryPrintSharedInfo(SocketHandle);
    H2AfdQueryPrintAddresses(SocketHandle);
    H2AfdQueryPrintSimpleInfo(SocketHandle);
    H2AfdQueryPrintTDIDevices(SocketHandle);

    // HACK: hvsocket.sys has a bug that makes connected Hyper-V sockets return
    // STATUS_SUCCESS for all option-querying request. We detect it by issuing a
    // deliberately invalid query. If it succeeds, we know we've hit the bug and
    // cannot display any meaningful option information about the socket.

    if (!NT_SUCCESS(H2AfdQueryOption(SocketHandle, 0xDEAD, 0xDEAD, &option)))
    {
        H2AfdQueryPrintPropertiesSol(SocketHandle);
        H2AfdQueryPrintPropertiesIp(SocketHandle);
        H2AfdQueryPrintPropertiesTcp(SocketHandle);
        H2AfdQueryPrintPropertiesTcpInfo(SocketHandle);
        H2AfdQueryPrintPropertiesUdp(SocketHandle);
        H2AfdQueryPrintPropertiesHv(SocketHandle);
    }
}

/**
  * \brief Query and print a one-line summary of a socket.
  *
  * \param[in] SocketHandle A handle to an AFD socket.
  */
VOID H2AfdQueryPrintSummarySocket(
    _In_ HANDLE SocketHandle
)
{
    SOCK_SHARED_INFO sharedInfo;
    UNICODE_STRING addressString;
    NTSTATUS sharedInfoStatus;
    NTSTATUS addressStatus;
    PCWSTR detail;

    // Query the shared info and the local address
    sharedInfoStatus = H2AfdQuerySharedInfo(SocketHandle, &sharedInfo);
    addressStatus = H2AfdQueryFormatAddress(SocketHandle, FALSE, H2_AFD_ADDRESS_SIMPLIFY, &addressString);

    wprintf_s(L"AFD socket: ");

    if (!NT_SUCCESS(sharedInfoStatus) && !NT_SUCCESS(addressStatus))
    {
        wprintf_s(L"(no details)");
        return;
    }

    if (NT_SUCCESS(sharedInfoStatus))
    {
        // State
        if (detail = H2AfdGetSocketStateString(sharedInfo.State, FALSE))
        {
            wprintf_s(L"%s ", detail);
        }

        // Protocol
        if (detail = H2AfdGetProtocolSummaryString(sharedInfo.AddressFamily, sharedInfo.Protocol))
        {
            wprintf_s(L"%s ", detail);
        }
    }

    if (NT_SUCCESS(addressStatus))
    {
        // Local address
        wprintf_s(L"on %wZ", &addressString);

        // Remote address
        if (NT_SUCCESS(H2AfdQueryFormatAddress(SocketHandle, TRUE, H2_AFD_ADDRESS_SIMPLIFY, &addressString)))
            wprintf_s(L" to %wZ", &addressString);
    }
}

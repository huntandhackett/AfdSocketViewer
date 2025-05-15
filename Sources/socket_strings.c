/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "socket_strings.h"
#include <stdio.h>

/**
  * \brief Looks up a name for a known socket state.
  *
  * \param[in] State The socket state value.
  * \param[in] RawName Whether the function should return a raw (machine-readable) or a human-readable name.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetSocketStateString(
    _In_ SOCKET_STATE State,
    _In_ BOOLEAN RawName
)
{
    switch (State)
    {
    case SocketStateInitializing:
        return RawName ? L"SocketStateInitializing" : L"Initializing";
    case SocketStateOpen:
        return RawName ? L"SocketStateOpen" : L"Open";
    case SocketStateBound:
        return RawName ? L"SocketStateBound" : L"Bound";
    case SocketStateBoundSpecific:
        return RawName ? L"SocketStateBoundSpecific" : L"Bound Specific";
    case SocketStateConnected:
        return RawName ? L"SocketStateConnected" : L"Connected";
    case SocketStateClosing:
        return RawName ? L"SocketStateClosing" : L"Closing";
    default:
        return NULL;
    }
}

/**
  * \brief Looks up a name for a known socket type.
  *
  * \param[in] SocketType The socket type value.
  * \param[in] RawName Whether the function should return a raw (machine-readable) or a human-readable name.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetSocketTypeString(
    _In_ LONG SocketType,
    _In_ BOOLEAN RawName
)
{
    switch (SocketType)
    {
    case SOCK_STREAM:
        return RawName ? L"SOCK_STREAM" : L"Stream";
    case SOCK_DGRAM:
        return RawName ? L"SOCK_DGRAM" : L"Datagram";
    case SOCK_RAW:
        return RawName ? L"SOCK_RAW" : L"Raw";
    case SOCK_RDM:
        return RawName ? L"SOCK_RDM" : L"Reliably-delivered message";
    case SOCK_SEQPACKET:
        return RawName ? L"SOCK_SEQPACKET" : L"Pseudo-stream";
    default:
        return NULL;
    }
}

/**
  * \brief Looks up a name for a known address family.
  *
  * \param[in] AddressFamily The address family value.
  * \param[in] RawName Whether the function should return a raw (machine-readable) or a human-readable name.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetAddressFamilyString(
    _In_ LONG AddressFamily,
    _In_ BOOLEAN RawName
)
{
    switch (AddressFamily)
    {
    case AF_UNSPEC:
        return RawName ? L"AF_UNSPEC" : L"Unspecified";
    case AF_INET:
        return RawName ? L"AF_INET" : L"Internet";
    case AF_INET6:
        return RawName ? L"AF_INET6" : L"Internet v6";
    case AF_BTH:
        return RawName ? L"AF_BTH" : L"Bluetooth";
    case AF_HYPERV:
        return RawName ? L"AF_HYPERV" : L"Hyper-V";
    default:
        return NULL;
    }
}

/**
  * \brief Looks up a name for a known protocol.
  *
  * \param[in] AddressFamily The address family for the protocol value.
  * \param[in] Protocol The protocol value.
  * \param[in] RawName Whether the function should return a raw (machine-readable) or a human-readable name.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetProtocolString(
    _In_ LONG AddressFamily,
    _In_ LONG Protocol,
    _In_ BOOLEAN RawName
)
{
    switch (AddressFamily)
    {
    case AF_INET:
    case AF_INET6:
        switch (Protocol)
        {
        case IPPROTO_ICMP:
            return RawName ? L"IPPROTO_ICMP" : L"ICMP";
        case IPPROTO_IGMP:
            return RawName ? L"IPPROTO_IGMP" : L"IGMP";
        case IPPROTO_TCP:
            return RawName ? L"IPPROTO_TCP" : L"TCP";
        case IPPROTO_UDP:
            return RawName ? L"IPPROTO_UDP" : L"UDP";
        case IPPROTO_RDP:
            return RawName ? L"IPPROTO_RDP" : L"RDP";
        case IPPROTO_ICMPV6:
            return RawName ? L"IPPROTO_ICMPV6" : L"ICMPv6";
        case IPPROTO_PGM:
            return RawName ? L"IPPROTO_PGM" : L"PGM";
        case IPPROTO_L2TP:
            return RawName ? L"IPPROTO_L2TP" : L"L2TP";
        case IPPROTO_SCTP:
            return RawName ? L"IPPROTO_SCTP" : L"SCTP";
        case IPPROTO_RAW:
            return RawName ? L"IPPROTO_RAW" : L"RAW";
        case IPPROTO_RESERVED_IPSEC:
            return RawName ? L"IPPROTO_RESERVED_IPSEC" : L"IPSec";
        }
    case AF_BTH:
        switch (Protocol)
        {
        case BTHPROTO_RFCOMM:
            return RawName ? L"BTHPROTO_RFCOMM" : L"RFCOMM";
        case BTHPROTO_L2CAP:
            return RawName ? L"BTHPROTO_L2CAP" : L"L2CAP";
        }
    case AF_HYPERV:
        switch (Protocol)
        {
        case HV_PROTOCOL_RAW:
            return RawName ? L"HV_PROTOCOL_RAW" : L"RAW";
        }
    }

    return NULL;
}

/**
  * \brief Looks up a summary a known protocol and address family.
  *
  * \param[in] AddressFamily The address family for the protocol value.
  * \param[in] Protocol The protocol value.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetProtocolSummaryString(
    _In_ LONG AddressFamily,
    _In_ LONG Protocol
)
{
    switch (AddressFamily)
    {
    case AF_INET:
        switch (Protocol)
        {
        case IPPROTO_ICMP:
            return L"ICMP";
        case IPPROTO_TCP:
            return L"TCP";
        case IPPROTO_UDP:
            return L"UDP";
        case IPPROTO_RAW:
            return L"RAW/IPv4";
        }
    case AF_INET6:
        switch (Protocol)
        {
        case IPPROTO_ICMPV6:
            return L"ICMP6";
        case IPPROTO_TCP:
            return L"TCP6";
        case IPPROTO_UDP:
            return L"UDP6";
        case IPPROTO_RAW:
            return L"RAW/IPv6";
        }
    case AF_BTH:
        switch (Protocol)
        {
        case BTHPROTO_RFCOMM:
            return L"RFCOMM [Bluetooth]";
        case BTHPROTO_L2CAP:
            return L"L2CAP [Bluetooth]";
        }
    case AF_HYPERV:
        switch (Protocol)
        {
        case HV_PROTOCOL_RAW:
            return L"Hyper-V RAW";
        }
    }

    return NULL;
}

/**
  * \brief Looks up a name for a known socket group type.
  *
  * \param[in] GroupType The socket group type value.
  * \param[in] RawName Whether the function should return a raw (machine-readable) or a human-readable name.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetGroupTypeString(
    _In_ AFD_GROUP_TYPE GroupType,
    _In_ BOOLEAN RawName
)
{
    switch (GroupType)
    {
    case GroupTypeNeither:
        return RawName ? L"GroupTypeNeither" : L"Neither";
    case GroupTypeUnconstrained:
        return RawName ? L"GroupTypeUnconstrained" : L"Unconstrained";
    case GroupTypeConstrained:
        return RawName ? L"GroupTypeConstrained" : L"Constrained";
    default:
        return NULL;
    }
}

/**
  * \brief Looks up a name for a known IPv6 protection level.
  *
  * \param[in] ProtectionLevel The protection level value.
  * \param[in] RawName Whether the function should return a raw (machine-readable) or a human-readable name.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetProtectionLevelString(
    _In_ ULONG ProtectionLevel,
    _In_ BOOLEAN RawName
)
{
    switch (ProtectionLevel)
    {
    case PROTECTION_LEVEL_UNRESTRICTED:
        return RawName ? L"PROTECTION_LEVEL_UNRESTRICTED" : L"Unrestricted";
    case PROTECTION_LEVEL_EDGERESTRICTED:
        return RawName ? L"PROTECTION_LEVEL_EDGERESTRICTED" : L"Edge-restricted";
    case PROTECTION_LEVEL_RESTRICTED:
        return RawName ? L"PROTECTION_LEVEL_RESTRICTED" : L"Restricted";
    case PROTECTION_LEVEL_DEFAULT:
        return RawName ? L"PROTECTION_LEVEL_DEFAULT" : L"Default";
    default:
        return NULL;
    }
}

/**
  * \brief Looks up a name for a known MTU discovery mode.
  *
  * \param[in] MtuDiscover The MTU discovery mode value.
  * \param[in] RawName Whether the function should return a raw (machine-readable) or a human-readable name.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetMtuDiscoveryString(
    _In_ ULONG MtuDiscover,
    _In_ BOOLEAN RawName
)
{
    switch (MtuDiscover)
    {
    case IP_PMTUDISC_NOT_SET:
        return RawName ? L"IP_PMTUDISC_NOT_SET" : L"Not set";
    case IP_PMTUDISC_DO:
        return RawName ? L"IP_PMTUDISC_DO" : L"Perform";
    case IP_PMTUDISC_DONT:
        return RawName ? L"IP_PMTUDISC_DONT" : L"Don't perform";
    case IP_PMTUDISC_PROBE:
        return RawName ? L"IP_PMTUDISC_PROBE" : L"Probe";
    default:
        return NULL;
    }
}

/**
  * \brief Looks up a name for a known TCP state.
  *
  * \param[in] TcpState The TCP state value.
  * \param[in] RawName Whether the function should return a raw (machine-readable) or a human-readable name.
  *
  * \return A string with the name or NULL when the value is not recognized.
  */
_Check_return_
_Maybenull_
PCWSTR H2AfdGetTcpStateString(
    _In_ TCPSTATE TcpState,
    _In_ BOOLEAN RawName
)
{
    switch (TcpState)
    {
    case TCPSTATE_CLOSED:
        return RawName ? L"TCPSTATE_CLOSED" : L"Closed";
    case TCPSTATE_LISTEN:
        return RawName ? L"TCPSTATE_LISTEN" : L"Listen";
    case TCPSTATE_SYN_SENT:
        return RawName ? L"TCPSTATE_SYN_SENT" : L"SYN sent";
    case TCPSTATE_SYN_RCVD:
        return RawName ? L"TCPSTATE_SYN_RCVD" : L"SYN received";
    case TCPSTATE_ESTABLISHED:
        return RawName ? L"TCPSTATE_ESTABLISHED" : L"Established";
    case TCPSTATE_FIN_WAIT_1:
        return RawName ? L"TCPSTATE_FIN_WAIT_1" : L"FIN wait 1";
    case TCPSTATE_FIN_WAIT_2:
        return RawName ? L"TCPSTATE_FIN_WAIT_2" : L"FIN wait 2";
    case TCPSTATE_CLOSE_WAIT:
        return RawName ? L"TCPSTATE_CLOSE_WAIT" : L"Close wait";
    case TCPSTATE_CLOSING:
        return RawName ? L"TCPSTATE_CLOSING" : L"Closing";
    case TCPSTATE_LAST_ACK:
        return RawName ? L"TCPSTATE_LAST_ACK" : L"Last ACK";
    case TCPSTATE_TIME_WAIT:
        return RawName ? L"TCPSTATE_TIME_WAIT" : L"Time wait";
    default:
        return NULL;
    }
}

/**
  * \brief Determines the name of the device associated with a file handle.
  *
  * \param[in] FileHandle A handle to a file on the given device.
  * \param[out] DeviceName A pointer to a UNICODE_STRING that receives the device string. The caller becomes
  *            responsible for freeing the string via RtlFreeUnicodeString.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdFormatDeviceName(
    _In_ HANDLE FileHandle,
    _Out_ PUNICODE_STRING DeviceName
)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;

    union {
        FILE_VOLUME_NAME_INFORMATION VolumeName;
        UCHAR Raw[0x200];
    } buffer;

    // Query the underlying device name
    status = NtQueryInformationFile(
        FileHandle,
        &ioStatusBlock,
        &buffer,
        sizeof(buffer),
        FileVolumeNameInformation
    );

    if (NT_SUCCESS(status))
    {
        UNICODE_STRING localString;

        localString.Buffer = buffer.VolumeName.DeviceName;
        localString.Length = (USHORT)buffer.VolumeName.DeviceNameLength;
        localString.MaximumLength = localString.Length;

        return RtlDuplicateUnicodeString(0, &localString, DeviceName);
    }

    return status;
}


/**
  * \brief Formats a socket address to a string.
  *
  * \param[in] Address The socket address buffer.
  * \param[in] Flags A bit masks of flags that control the function's behavior, such as H2_AFD_ADDRESS_SIMPLIFY.
  * \param[out] AddressString A pointer to a UNICODE_STRING that receives the address string. The caller becomes
  *            responsible for freeing the string via RtlFreeUnicodeString.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdFormatAddress(
    _In_ PSOCKADDR_STORAGE Address,
    _In_ ULONG Flags,
    _Out_ PUNICODE_STRING AddressString
)
{
    NTSTATUS status;
    WCHAR buffer[80] = { 0 };
    ULONG characters = RTL_NUMBER_OF(buffer);

    if (Address->ss_family == AF_INET)
    {
        PSOCKADDR_IN address = (PSOCKADDR_IN)Address;

        // Format an IPv4 address
        status = RtlIpv4AddressToStringExW(
            &address->sin_addr,
            address->sin_port,
            buffer,
            &characters
        );

        if (!NT_SUCCESS(status))
            return status;

        // Don't count the terminating zero
        if (characters > 0)
            characters--;
    }
    else if (Address->ss_family == AF_INET6)
    {
        PSOCKADDR_IN6 address = (PSOCKADDR_IN6)Address;

        // Format an IPv6 address
        status = RtlIpv6AddressToStringExW(
            &address->sin6_addr,
            address->sin6_scope_id,
            address->sin6_port,
            buffer,
            &characters
        );

        if (!NT_SUCCESS(status))
            return status;

        // Don't count the terminating zero
        if (characters > 0)
            characters--;
    }
    else if (Address->ss_family == AF_BTH)
    {
        PSOCKADDR_BTH address = (PSOCKADDR_BTH)Address;

        // Format a Bluetooth address
        characters = swprintf_s(buffer, characters,
            L"(%02X:%02X:%02X:%02X:%02X:%02X):%d",
            (UCHAR)(address->btAddr >> 40),
            (UCHAR)(address->btAddr >> 32),
            (UCHAR)(address->btAddr >> 24),
            (UCHAR)(address->btAddr >> 16),
            (UCHAR)(address->btAddr >> 8),
            (UCHAR)(address->btAddr),
            address->port
        );

        if (characters == ULONG_MAX)
            return STATUS_INSUFFICIENT_RESOURCES;
    }
    else if (Address->ss_family == AF_HYPERV)
    {
        PSOCKADDR_HV address = (PSOCKADDR_HV)Address;
        PCWSTR knownVmId = NULL;
        UNICODE_STRING vmIdPart;
        UNICODE_STRING serviceIdPart;

        // Format a Hyper-V address

        if (Flags & H2_AFD_ADDRESS_SIMPLIFY)
        {
            // Recognize placeholder VmId values
            if (IsEqualGUID(&address->VmId, &HV_GUID_WILDCARD))
                knownVmId = L"{Wildcard}";
            else if (IsEqualGUID(&address->VmId, &HV_GUID_BROADCAST))
                knownVmId = L"{Broadcast}";
            else if (IsEqualGUID(&address->VmId, &HV_GUID_CHILDREN))
                knownVmId = L"{Children}";
            else if (IsEqualGUID(&address->VmId, &HV_GUID_LOOPBACK))
                knownVmId = L"{Loopback}";
            else if (IsEqualGUID(&address->VmId, &HV_GUID_PARENT))
                knownVmId = L"{Parent}";
            else if (IsEqualGUID(&address->VmId, &HV_GUID_SILOHOST))
                knownVmId = L"{Silo host}";
        }

        // Prepare the ServiceId part
        status = RtlStringFromGUID(&address->ServiceId, &serviceIdPart);

        if (!NT_SUCCESS(status))
            return status;

        // Prepare the VmId part
        if (!knownVmId)
        {
            status = RtlStringFromGUID(&address->VmId, &vmIdPart);

            if (!NT_SUCCESS(status))
            {
                RtlFreeUnicodeString(&serviceIdPart);
                return status;
            }
        }
        else
        {
            RtlInitUnicodeString(&vmIdPart, knownVmId);
        }

        // Combine into {VmId}:{ServiceId}
        characters = swprintf_s(buffer, characters, L"%wZ:%wZ", &vmIdPart, &serviceIdPart);

        RtlFreeUnicodeString(&serviceIdPart);

        if (!knownVmId)
            RtlFreeUnicodeString(&vmIdPart);

        if (characters == ULONG_MAX)
            return STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        return STATUS_UNKNOWN_REVISION;
    }

    UNICODE_STRING localString;
    localString.Buffer = buffer;
    localString.Length = (USHORT)(characters * sizeof(WCHAR));
    localString.MaximumLength = sizeof(buffer);

    // Make a copy of the string for the caller
    return RtlDuplicateUnicodeString(0, &localString, AddressString);
}

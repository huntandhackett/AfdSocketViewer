/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _SOCKET_STRINGS_H
#define _SOCKET_STRINGS_H

#include <phnt_windows.h>
#include <phnt.h>
#include "ntafd.h"
#include <mstcpip.h>
#include <ws2bth.h>
#include <hvsocket.h>
#include <ws2ipdef.h>

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetSocketStateString(
    _In_ SOCKET_STATE State,
    _In_ BOOLEAN UseRawNames
);

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetSocketTypeString(
    _In_ LONG SocketType,
    _In_ BOOLEAN UseRawNames
);

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetAddressFamilyString(
    _In_ LONG AddressFamily,
    _In_ BOOLEAN UseRawNames
);

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetProtocolString(
    _In_ LONG AddressFamily,
    _In_ LONG Protocol,
    _In_ BOOLEAN UseRawNames
);

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetProtocolSummaryString(
    _In_ LONG AddressFamily,
    _In_ LONG Protocol
);

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetGroupTypeString(
    _In_ AFD_GROUP_TYPE GroupType,
    _In_ BOOLEAN UseRawNames
);

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetProtectionLevelString(
    _In_ ULONG ProtectionLevel,
    _In_ BOOLEAN UseRawNames
);

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetMtuDiscoveryString(
    _In_ ULONG MtuDiscover,
    _In_ BOOLEAN UseRawNames
);

_Check_return_
_Maybenull_
PCWSTR
NTAPI
H2AfdGetTcpStateString(
    _In_ TCPSTATE TcpState,
    _In_ BOOLEAN UseRawNames
);

NTSTATUS
NTAPI
H2AfdFormatDeviceName(
    _In_ HANDLE FileHandle,
    _Out_ PUNICODE_STRING DeviceName
);

// Simplify parts of the address to make it more human-readable
#define H2_AFD_ADDRESS_SIMPLIFY    0x1

NTSTATUS
NTAPI
H2AfdFormatAddress(
    _In_ PSOCKADDR_STORAGE Address,
    _In_ ULONG Flags,
    _Out_ PUNICODE_STRING AddressString
);

#endif

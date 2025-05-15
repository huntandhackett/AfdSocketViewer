/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _NATIVESOCKET_H
#define _NATIVESOCKET_H

#include <phnt_windows.h>
#include <phnt.h>
#include "ntafd.h"
#include <mstcpip.h>

BOOLEAN
NTAPI
H2AfdIsSocketObjectName(
    _In_ PUNICODE_STRING ObjectName
);

NTSTATUS
NTAPI
H2AfdIsSocketHandle(
    _In_ HANDLE Handle
);

NTSTATUS
NTAPI
H2AfdDeviceIoControl(
    _In_ HANDLE SocketHandle,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_(InBufferSize) PVOID InBuffer,
    _In_ ULONG InBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *BytesReturned) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_opt_ PULONG BytesReturned
);

NTSTATUS
NTAPI
H2AfdQuerySharedInfo(
    _In_ HANDLE SocketHandle,
    _Out_ PSOCK_SHARED_INFO SharedInfo
);

NTSTATUS
NTAPI
H2AfdQuerySimpleInfo(
    _In_ HANDLE SocketHandle,
    _In_ ULONG InformationType,
    _Out_ PAFD_INFORMATION Information
);

NTSTATUS
NTAPI
H2AfdQueryOption(
    _In_ HANDLE SocketHandle,
    _In_ ULONG Level,
    _In_ ULONG OptionName,
    _Out_ PULONG OptionValue
);

NTSTATUS
NTAPI
H2AfdQueryTcpInfo(
    _In_ HANDLE SocketHandle,
    _In_ ULONG TcpInfoVersion,
    _Out_ PTCP_INFO_v2 TcpInfo
);

NTSTATUS
NTAPI
H2AfdQueryTdiHandle(
    _In_ HANDLE SocketHandle,
    _In_ ULONG QueryMode,
    _Out_ PHANDLE TdiHandle
);

NTSTATUS
NTAPI
H2AfdQueryAddress(
    _In_ HANDLE SocketHandle,
    _In_ BOOLEAN Remote,
    _Out_ PSOCKADDR_STORAGE Address
);

#endif

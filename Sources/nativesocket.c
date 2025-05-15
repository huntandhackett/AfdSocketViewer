/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "nativesocket.h"

/**
  * \brief Determines if an object name represents an AFD socket handle.
  *
  * \param[in] ObjectName A native object name.
  *
  * \return Whether the name matches an AFD socket name format.
  */
BOOLEAN H2AfdIsSocketObjectName(
    _In_ PUNICODE_STRING ObjectName
)
{
    static UNICODE_STRING afdDeviceName = RTL_CONSTANT_STRING(AFD_DEVICE_NAME);

    return RtlPrefixUnicodeString(&afdDeviceName, ObjectName, TRUE) &&
        (ObjectName->Length == afdDeviceName.Length ||
        ObjectName->Buffer[afdDeviceName.Length / sizeof(WCHAR)] == OBJ_NAME_PATH_SEPARATOR);
}

/**
  * \brief Determines if a file handle is an AFD socket handle.
  *
  * \param[in] Handle A file handle.
  *
  * \return A successful status if the handle is an AFD socket or an errant status otherwise.
  */
NTSTATUS H2AfdIsSocketHandle(
    _In_ HANDLE Handle
)
{
    static UNICODE_STRING afdDeviceName = RTL_CONSTANT_STRING(AFD_DEVICE_NAME);
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;

    union {
        FILE_VOLUME_NAME_INFORMATION VolumeName;
        UCHAR Raw[sizeof(FILE_VOLUME_NAME_INFORMATION) + sizeof(AFD_DEVICE_NAME) - sizeof(UNICODE_NULL)];
    } Buffer = { 0 };

    // Query the backing device name
    status = NtQueryInformationFile(
        Handle,
        &ioStatusBlock,
        &Buffer,
        sizeof(Buffer),
        FileVolumeNameInformation
    );

    // If the name does not fit into the buffer, it's not AFD
    if (status == STATUS_BUFFER_OVERFLOW)
        return STATUS_NOT_SAME_DEVICE;

    if (!NT_SUCCESS(status))
        return status;

    UNICODE_STRING volumeName = { 0 };

    volumeName.Buffer = Buffer.VolumeName.DeviceName;
    volumeName.Length = (USHORT)Buffer.VolumeName.DeviceNameLength;
    volumeName.MaximumLength = (USHORT)Buffer.VolumeName.DeviceNameLength;

    // Compare the file's device name to AFD
    return RtlEqualUnicodeString(&volumeName, &afdDeviceName, TRUE) ? STATUS_SUCCESS : STATUS_NOT_SAME_DEVICE;
}

/**
  * \brief Issues an IOCTL on an AFD handle and waits for its completion.
  *
  * \param[in] SocketHandle An AFD socket handle.
  * \param[in] IoControlCode I/O control code
  * \param[in] InBuffer Input buffer.
  * \param[in] InBufferSize Input buffer size.
  * \param[out] OutputBuffer Output Buffer.
  * \param[in] OutputBufferSize Output buffer size.
  * \param[out] BytesReturned Optionally set to the number of bytes returned.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdDeviceIoControl(
    _In_ HANDLE SocketHandle,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_(InBufferSize) PVOID InBuffer,
    _In_ ULONG InBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *BytesReturned) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_opt_ PULONG BytesReturned
)
{
    NTSTATUS status;
    HANDLE eventHandle;
    IO_STATUS_BLOCK ioStatusBlock;

    // We cannot wait on the file handle because it might not grant SYNCHRONIZE access.
    // Always use an event instead.

    status = NtCreateEvent(
        &eventHandle,
        EVENT_ALL_ACCESS,
        NULL,
        SynchronizationEvent,
        FALSE
    );

    if (!NT_SUCCESS(status))
        return status;

    status = NtDeviceIoControlFile(
        SocketHandle,
        eventHandle,
        NULL,
        NULL,
        &ioStatusBlock,
        IoControlCode,
        InBuffer,
        InBufferSize,
        OutputBuffer,
        OutputBufferSize
    );

    if (status == STATUS_PENDING)
    {
        NtWaitForSingleObject(eventHandle, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

    NtClose(eventHandle);

    if (BytesReturned)
    {
        *BytesReturned = (ULONG)ioStatusBlock.Information;
    }

    return status;
}

/**
  * \brief Retrieves shared information for an AFD socket.
  *
  * \param[in] SocketHandle An AFD socket handle.
  * \param[out] SharedInfo A buffer with the shared socket information.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdQuerySharedInfo(
    _In_ HANDLE SocketHandle,
    _Out_ PSOCK_SHARED_INFO SharedInfo
)
{
    NTSTATUS status;
    ULONG returnedSize;

    status = H2AfdDeviceIoControl(
        SocketHandle,
        IOCTL_AFD_GET_CONTEXT,
        NULL,
        0,
        SharedInfo,
        sizeof(SOCK_SHARED_INFO),
        &returnedSize
    );

    if (status == STATUS_BUFFER_OVERFLOW)
        return STATUS_SUCCESS;

    if (!NT_SUCCESS(status))
        return status;

    // Shared information is provided by the Win32 level; do a sanity check on the returned size
    return returnedSize < sizeof(SOCK_SHARED_INFO) ? STATUS_NOT_FOUND : status;
}

/**
  * \brief Retrieves simple information for an AFD socket.
  *
  * \param[in] SocketHandle An AFD socket handle.
  * \param[in] InformationType The type of information to query, such as AFD_CONNECT_TIME or AFD_GROUP_ID_AND_TYPE.
  * \param[out] Information Output buffer.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdQuerySimpleInfo(
    _In_ HANDLE SocketHandle,
    _In_ ULONG InformationType,
    _Out_ PAFD_INFORMATION Information
)
{
    Information->InformationType = InformationType;

    return H2AfdDeviceIoControl(
        SocketHandle,
        IOCTL_AFD_GET_INFORMATION,
        Information,
        sizeof(AFD_INFORMATION),
        Information,
        sizeof(AFD_INFORMATION),
        NULL
    );
}

/**
  * \brief Retrieves an ULONG-sized socket option for an AFD socket.
  *
  * \param[in] SocketHandle An AFD socket handle.
  * \param[in] Level A level for the option, such as SOL_SOCKET or IPPROTO_IP.
  * \param[in] OptionName An option identifier within the level, such as SO_REUSEADDR or IP_TTL.
  * \param[out] OptionValue A buffer that receives the option value.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdQueryOption(
    _In_ HANDLE SocketHandle,
    _In_ ULONG Level,
    _In_ ULONG OptionName,
    _Out_ PULONG OptionValue
)
{
    AFD_TL_IO_CONTROL_INFO controlInfo = { 0 };
    controlInfo.Type = TlGetSockOptIoControlType;
    controlInfo.EndpointIoctl = TRUE;
    controlInfo.Level = Level;
    controlInfo.IoControlCode = OptionName;
    *OptionValue = 0;

    return H2AfdDeviceIoControl(
        SocketHandle,
        IOCTL_AFD_TRANSPORT_IOCTL,
        &controlInfo,
        sizeof(AFD_TL_IO_CONTROL_INFO),
        OptionValue,
        sizeof(ULONG),
        NULL
    );
}

/**
  * \brief Retrieves the latest supported TCP_INFO for an AFD socket.
  *
  * \param[in] SocketHandle An AFD socket handle.
  * \param[out] TcpInfo A buffer that receives the TCP information.
  * \param[out] TcpInfoVersion The version of the returned structure.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdQueryTcpInfo(
    _In_ HANDLE SocketHandle,
    _In_ ULONG TcpInfoVersion,
    _Out_ PTCP_INFO_v2 TcpInfo
)
{
    NTSTATUS status;
    AFD_TL_IO_CONTROL_INFO controlInfo = { 0 };

    if (TcpInfoVersion > 2)
        return STATUS_INVALID_PARAMETER;

    static const ULONG tcpInfoSize[] =
    {
        sizeof(TCP_INFO_v0),
        sizeof(TCP_INFO_v1),
        sizeof(TCP_INFO_v2)
    };

    controlInfo.Type = TlSocketIoControlType;
    controlInfo.EndpointIoctl = TRUE;
    controlInfo.IoControlCode = SIO_TCP_INFO;
    controlInfo.InputBuffer = &TcpInfoVersion;
    controlInfo.InputBufferLength = sizeof(LONG);

    RtlZeroMemory(TcpInfo, sizeof(TCP_INFO_v2));

    status = H2AfdDeviceIoControl(
        SocketHandle,
        IOCTL_AFD_TRANSPORT_IOCTL,
        &controlInfo,
        sizeof(AFD_TL_IO_CONTROL_INFO),
        TcpInfo,
        tcpInfoSize[TcpInfoVersion],
        NULL
    );

    return status;
}

/**
  * \brief Opens an address or a connection handle to the underlying device for a TDI socket.
  *
  * \param[in] SocketHandle An AFD socket handle.
  * \param[in] QueryMode A type of the query, either AFD_QUERY_ADDRESS_HANDLE or AFD_QUERY_CONNECTION_HANDLE.
  * \param[out] TdiHandle A pointer to a variable that receives a TDI device handle, NULL (when no handle is available), or INVALID_HANDLE_VALUE (for non-TDI sockets).
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdQueryTdiHandle(
    _In_ HANDLE SocketHandle,
    _In_ ULONG QueryMode,
    _Out_ PHANDLE TdiHandle
)
{
    NTSTATUS status;
    AFD_HANDLE_INFO handles = { 0 };

    if (QueryMode != AFD_QUERY_ADDRESS_HANDLE && QueryMode != AFD_QUERY_CONNECTION_HANDLE)
        return STATUS_INVALID_INFO_CLASS;

    status = H2AfdDeviceIoControl(
        SocketHandle,
        IOCTL_AFD_QUERY_HANDLES,
        &QueryMode,
        sizeof(QueryMode),
        &handles,
        sizeof(handles),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        if (QueryMode == AFD_QUERY_ADDRESS_HANDLE)
            *TdiHandle = handles.TdiAddressHandle;
        else
            *TdiHandle = handles.TdiConnectionHandle;
    }

    return status;
}

/**
  * \brief Determines if we know how to handle a specific address family.
  *
  * \param[in] AddressFamily A socket address family value.
  *
  * \return Whether the address family is supported.
  */
BOOLEAN H2AfdIsSupportedAddressFamily(
    _In_ LONG AddressFamily
)
{
    switch (AddressFamily)
    {
    case AF_INET:
    case AF_INET6:
    case AF_BTH:
    case AF_HYPERV:
        return TRUE;
    default:
        return FALSE;
    }
}

/**
  * \brief Retrieves an address associated with an AFD socket.
  *
  * \param[in] SocketHandle An AFD socket handle.
  * \param[in] Remote Whether the function should return a remote or a local address.
  * \param[out] Address Output buffer.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2AfdQueryAddress(
    _In_ HANDLE SocketHandle,
    _In_ BOOLEAN Remote,
    _Out_ PSOCKADDR_STORAGE Address
)
{
    NTSTATUS status;
    AFD_ADDRESS buffer = { 0 };

    if (Remote)
    {
        // HACK: If the socket has a suitable state but no remote address, the IOCTL can succeed without
        // writing anything to the buffer, yet setting IO_STATUS_BLOCK's Information to a non-zero value.
        // We issue a zero-size query to recognize this scenario.

        if (NT_SUCCESS(H2AfdDeviceIoControl(SocketHandle, IOCTL_AFD_GET_REMOTE_ADDRESS, NULL, 0, NULL, 0, NULL)))
            return STATUS_NOT_FOUND;
    }

    // Retrieve the address
    status = H2AfdDeviceIoControl(
        SocketHandle,
        Remote ? IOCTL_AFD_GET_REMOTE_ADDRESS : IOCTL_AFD_GET_ADDRESS,
        NULL,
        0,
        &buffer,
        sizeof(buffer),
        NULL
    );

    if (!NT_SUCCESS(status))
        return status;

    // Most sockets are TLI; their addresses don't need conversion.
    if (H2AfdIsSupportedAddressFamily(buffer.TliAddress.ss_family))
    {
        *Address = buffer.TliAddress;
        return status;
    }

    // Some sockets (like Bluetooth) use TDI. Verify the header and extarct the socket address.
    if (buffer.TdiAddress.ActivityCount > 0 &&
        buffer.TdiAddress.Address.TAAddressCount >= 1 &&
        buffer.TdiAddress.Address.Address[0].AddressLength <= sizeof(buffer) - RTL_SIZEOF_THROUGH_FIELD(TDI_ADDRESS_INFO, Address.Address[0].AddressType) &&
        H2AfdIsSupportedAddressFamily(buffer.TdiAddress.Address.Address[0].AddressType))
    {
        RtlZeroMemory(Address, sizeof(SOCKADDR_STORAGE));

        // AddressLength covers the length after the AddressType field, while the socket address starts at the AddressType field.
        // See comments in AFD_ADDRESS for details about the layout.
        RtlCopyMemory(
            Address,
            &buffer.TdiAddressUnpacked.EmbeddedAddress,
            buffer.TdiAddress.Address.Address[0].AddressLength + RTL_FIELD_SIZE(TDI_ADDRESS_INFO, Address.Address[0].AddressType)
        );

        return status;
    }

    return STATUS_UNKNOWN_REVISION;
}

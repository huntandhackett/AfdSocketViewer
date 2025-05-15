/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "snapshot_helpers.h"

 /**
   * \brief Enables the debug privilege to help accessing other processes.
   *
   * \return Successful or errant status.
   */
NTSTATUS H2EnableDebugPrivilege(
    VOID
)
{
    BOOLEAN wasEnabled;
    return RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &wasEnabled);
}

/**
  * \brief Opens a handle to a specific process.
  *
  * \param[out] ProcessHandle A variable that receives the handle.
  * \param[in] ProcessId The unique ID of the process to open.
  * \param[in] DesiredAccess An access mask to request.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2OpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess
)
{
    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES objAttr;

    clientId.UniqueProcess = ProcessId;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    return NtOpenProcess(ProcessHandle, DesiredAccess, &objAttr, &clientId);
}

/**
  * \brief Frees a previously allocated process or handle snapshot.
  *
  * \param[in] Buffer A snapshot buffer.
  */
VOID H2Free(
    _Frees_ptr_opt_ _Post_invalid_ PVOID Buffer
)
{
    RtlFreeHeap(RtlProcessHeap(), 0, Buffer);
}

/**
  * \brief Queries variable-size system information.
  *
  * \param[in] InfoClass A system information class.
  * \param[out] Buffer An information buffer. The caller becomes responsible for releasing the buffer via H2Free.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2QuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass,
    _Outptr_ PPVOID Buffer
)
{
    NTSTATUS status;
    PVOID buffer;
    ULONG bufferSize = 0x1000;

    do
    {
        buffer = RtlAllocateHeap(RtlProcessHeap(), 0, bufferSize);

        if (!buffer)
            return STATUS_NO_MEMORY;

        status = NtQuerySystemInformation(
            InfoClass,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (NT_SUCCESS(status))
        {
            *Buffer = buffer;
            break;
        }
        else
        {
            RtlFreeHeap(RtlProcessHeap(), 0, buffer);
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL);

    return status;
}

/**
  * \brief Enumerates all processes on the system.
  *
  * \param[out] Snapshot A process snapshot buffer. The caller becomes responsible for releasing the buffer via H2Free.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2SnapshotProcesses(
    _Outptr_ PSYSTEM_PROCESS_INFORMATION* Snapshot
)
{
    return H2QuerySystemInformation(SystemProcessInformation, Snapshot);
}

/**
  * \brief Enumerates all handle on the system.
  *
  * \param[out] Snapshot A handle snapshot buffer. The caller becomes responsible for releasing the buffer via H2Free.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2SnapshotHandles(
    _Outptr_ PSYSTEM_HANDLE_INFORMATION_EX* Snapshot
)
{
    return H2QuerySystemInformation(SystemExtendedHandleInformation, Snapshot);
}

#define OB_TYPE_INDEX_TABLE_TYPE_OFFSET 2

/**
  * \brief Find a type index of a kernel type by name.
  *
  * \param[in] TypeName The name of the kernel type.
  * \param[out] Index The type's index in the handle snapshot.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2FindKernelTypeIndex(
    _In_ PUNICODE_STRING TypeName,
    _Out_ PULONG Index
)
{
    NTSTATUS status;
    POBJECT_TYPES_INFORMATION buffer;
    POBJECT_TYPE_INFORMATION entry;
    ULONG bufferSize = 0x1000;

    do
    {
        buffer = RtlAllocateHeap(RtlProcessHeap(), 0, bufferSize);

        if (!buffer)
            return STATUS_NO_MEMORY;

        // Enumerate kernel types
        status = NtQueryObject(
            NULL,
            ObjectTypesInformation,
            buffer, 
            bufferSize,
            &bufferSize
        );

        if (NT_SUCCESS(status))
            break;
        else
            RtlFreeHeap(RtlProcessHeap(), 0, buffer);

    } while (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(status))
        return status;

    // Prepare not to find a match
    status = STATUS_NOT_FOUND;

    // Locate the first type
    entry = ALIGN_UP_POINTER((ULONG_PTR)buffer + sizeof(OBJECT_TYPES_INFORMATION), PVOID);

    for (ULONG i = 0; i < buffer->NumberOfTypes; i++)
    {
        if (RtlEqualUnicodeString(&entry->TypeName, TypeName, TRUE))
        {
            // Until Windows 8.1, ObQueryTypeInfo didn't write anything to the TypeIndex field.
            // We can work around this issue by manually calculating the value if necessary.
            // NtQueryObject iterates through ObpObjectTypes, which is zero-based;
            // TypeIndex is an index in ObTypeIndexTable which starts with 2.

            if (entry->TypeIndex)
                *Index = entry->TypeIndex;
            else
                *Index = OB_TYPE_INDEX_TABLE_TYPE_OFFSET + i;

            status = STATUS_SUCCESS;
            break;
        }

        // Advance to the next type
        entry = ALIGN_UP_POINTER((ULONG_PTR)entry + sizeof(OBJECT_TYPE_INFORMATION) + entry->TypeName.MaximumLength, PVOID);
    }

    RtlFreeHeap(RtlProcessHeap(), 0, buffer);
    return status;
}

/**
  * \brief Find a type index of a kernel type by name.
  *
  * \param[in] ProcessID The unique ID of the process.
  * \param[in] ShortOnly Whether the function should return the full image path or a short name.
  * \param[out] ImageName An image name string. The caller becomes responsible for freeing the string via RtlFreeUnicodeString.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2QueryProcessIdImageName(
    _In_ HANDLE ProcessID,
    _In_ BOOLEAN ShortOnly,
    _Out_ PUNICODE_STRING ImageName
)
{
    NTSTATUS status;
    SYSTEM_PROCESS_ID_INFORMATION input;

    input.ImageName.Length = 0;
    input.ImageName.MaximumLength = 0xFFFE;
    input.ImageName.Buffer = RtlAllocateHeap(RtlProcessHeap(), 0, input.ImageName.MaximumLength);
    input.ProcessId = ProcessID;

    if (!input.ImageName.Buffer)
        return STATUS_NO_MEMORY;

    status = NtQuerySystemInformation(
        SystemProcessIdInformation,
        &input,
        sizeof(input),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        UNICODE_STRING imageName = input.ImageName;

        if (ShortOnly)
        {
            // Extract the last path element
            for (SHORT i = imageName.Length / sizeof(WCHAR) - 1; i >= 0; i--)
                if (imageName.Buffer[i] == OBJ_NAME_PATH_SEPARATOR)
                {
                    i++;
                    imageName.Buffer += i;
                    imageName.Length -= i * sizeof(WCHAR);
                    imageName.MaximumLength -= i * sizeof(WCHAR);
                    break;
                }
        }

        status = RtlDuplicateUnicodeString(0, &imageName, ImageName);
    }
    
    RtlFreeHeap(RtlProcessHeap(), 0, input.ImageName.Buffer);
    return status;
}

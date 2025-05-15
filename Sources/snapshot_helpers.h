/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _SNAPSHOT_HELPERS_H
#define _SNAPSHOT_HELPERS_H

#include <phnt_windows.h>
#include <phnt.h>

NTSTATUS
NTAPI
H2EnableDebugPrivilege(
    VOID
);

NTSTATUS
NTAPI
H2OpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess
);

VOID
NTAPI
H2Free(
    _Frees_ptr_opt_ _Post_invalid_ PVOID Buffer
);

NTSTATUS
NTAPI
H2SnapshotProcesses(
    _Outptr_ PSYSTEM_PROCESS_INFORMATION* Snapshot
);

/**
  * \brief Locates the next entry in a process snapshot.
  *
  * \param[in] Process A process in a snapshot.
  *
  * \return The next process in the snapshot or NULL.
  */
_Must_inspect_result_
_Maybenull_
FORCEINLINE
PSYSTEM_PROCESS_INFORMATION H2NextProcess(
    _In_ PSYSTEM_PROCESS_INFORMATION Process
)
{
    if (Process->NextEntryOffset)
        return (PSYSTEM_PROCESS_INFORMATION)RtlOffsetToPointer(Process, Process->NextEntryOffset);
    else
        return NULL;
}

NTSTATUS
NTAPI
H2SnapshotHandles(
    _Outptr_ PSYSTEM_HANDLE_INFORMATION_EX* Snapshot
);

NTSTATUS
NTAPI
H2FindKernelTypeIndex(
    _In_ PUNICODE_STRING TypeName,
    _Out_ PULONG Index
);

NTSTATUS
NTAPI
H2QueryProcessIdImageName(
    _In_ HANDLE ProcessID,
    _In_ BOOLEAN ShortOnly,
    _Out_ PUNICODE_STRING ImageName
);

#endif

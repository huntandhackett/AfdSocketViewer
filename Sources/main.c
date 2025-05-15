/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>
#include <wchar.h>
#include "argument_parsing.h"
#include "snapshot_helpers.h"
#include "printsocket.h"
#include "string_helpers.h"
#include "nativesocket.h"

NTSTATUS wmain(
    _In_ LONG argc,
    _In_ PWSTR argv[]
)
{
    NTSTATUS status;
    H2_ARGUMENTS parsedArguments;
    UNICODE_STRING fileHandleTypeName = RTL_CONSTANT_STRING(L"File");
    ULONG fileHandleTypeIndex;
    PSYSTEM_PROCESS_INFORMATION processSnapshot = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX handleSnapshot = NULL;
    HANDLE processHandle = NULL;
    HANDLE socketHandle = NULL;

    wprintf_s(L"AfdSocketView - a tool for inspecting AFD socket handles by Hunt & Hackett.\r\n\r\n");

    if (!NT_SUCCESS(status = H2ParseArguments(argc, argv, &parsedArguments)))
    {
        wprintf_s(
            L"Usage: AfdSocketView [-p [*|PID|Image name]] [-h [Handle value]] [-v]\r\n"
            L"   -p: selects which process(es) to inspect\r\n"
            L"   -h: show all properties for a specific handle\r\n"
            L"   -v: enable verbose output mode\r\n"
            L"\r\n"
            L"Examples:\r\n"
            L"  AfdSocketView -p * \r\n"
            L"  AfdSocketView -p chrome.exe\r\n"
            L"  AfdSocketView -p 4812 -h 0x2c8 -v\r\n"
        );
        return status;
    }

    // Try to enable the debug privilege to help accessing processes
    if (!NT_SUCCESS(status = H2EnableDebugPrivilege()) && parsedArguments.Verbose)
    {
        wprintf_s(L"Cannot enable the debug privilege: ");
        H2PrintStatusWithDescription(status);
        wprintf_s(L"\r\n\r\n");
    }

    // Enumerate processes unless we were given a PID
    if (!parsedArguments.ProcessId)
    {
        status = H2SnapshotProcesses(&processSnapshot);

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Failed to enumerate processes: ");
            H2PrintStatusWithDescription(status);
            wprintf_s(L"\r\n");
            return status;
        }
    }

    if (parsedArguments.HandleValue)
    {
        PSYSTEM_PROCESS_INFORMATION process = NULL;

        //
        // Inspecting details about a single handle
        //

        // We need to identify the process if we don't have its PID
        if (!parsedArguments.ProcessId)
        {
            PSYSTEM_PROCESS_INFORMATION cursor = processSnapshot;

            do
            {
                // Check each image name for matching the filter
                if (RtlIsNameInExpression(&parsedArguments.ProcessFilter, &cursor->ImageName, TRUE, NULL))
                {
                    if (process)
                    {
                        wprintf_s(L"Cannot inspect the handle: the filter matches more than one process.\r\n");

                        if (parsedArguments.Verbose)
                        {
                            wprintf_s(L"Matching at least %wZ [%zu] and %wZ [%zu].\r\n",
                                &process->ImageName,
                                (ULONG_PTR)process->UniqueProcessId,
                                &cursor->ImageName,
                                (ULONG_PTR)cursor->UniqueProcessId
                            );
                        }

                        status = STATUS_OBJECT_NAME_COLLISION;
                        goto CLEANUP;
                    }

                    process = cursor;
                }
            } while (cursor = H2NextProcess(cursor));

            if (!process)
            {
                wprintf_s(L"No matching processes found.\r\n");
                status = STATUS_NOT_FOUND;
                goto CLEANUP;
            }

            // Use the found PID
            parsedArguments.ProcessId = process->UniqueProcessId;
        }

        // Open the target
        status = H2OpenProcess(&processHandle, parsedArguments.ProcessId, PROCESS_DUP_HANDLE);

        wprintf_s(
            L"Handle 0x%0.4zX of %wZ [%zu]:\r\n",
            (ULONG_PTR)parsedArguments.HandleValue,
            process ? &process->ImageName : &parsedArguments.ProcessFilter,
            (ULONG_PTR)parsedArguments.ProcessId
        );

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Unable to open the process: ");
            H2PrintStatusWithDescription(status);
            wprintf_s(L"\r\n");
            goto CLEANUP;
        }

        // Duplicate the handle from it
        status = NtDuplicateObject(
            processHandle,
            parsedArguments.HandleValue,
            NtCurrentProcess(),
            &socketHandle,
            0,
            0,
            DUPLICATE_SAME_ACCESS
        );

        NtClose(processHandle);
        processHandle = NULL;

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Unable to duplicate the handle: ");
            H2PrintStatusWithDescription(status);
            wprintf_s(L"\r\n");
            goto CLEANUP;
        }

        // Verify it's an AFD socket
        status = H2AfdIsSocketHandle(socketHandle);

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"The handle is not an Ancillary Function Driver socket: ");
            H2PrintStatusWithDescription(status);
            wprintf_s(L"\r\n");
            goto CLEANUP;
        }

        // Print all of its properties
        H2AfdQueryPrintDetailsSocket(socketHandle, parsedArguments.Verbose);
        wprintf_s(L"\r\n");
    }
    else
    {
        //
        // Displaying summary about multiple handles
        //

        // Identify the type index for sockets (file handles)
        status = H2FindKernelTypeIndex(&fileHandleTypeName, &fileHandleTypeIndex);

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Unable to identify file type index: ");
            H2PrintStatusWithDescription(status);
            wprintf_s(L"\r\n");
            goto CLEANUP;
        }

        // Enumerate handles from all processes
        status = H2SnapshotHandles(&handleSnapshot);

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Unable to enumerate handles on the system: ");
            H2PrintStatusWithDescription(status);
            wprintf_s(L"\r\n");
            goto CLEANUP;
        }

        ULONG processesFound = 0;
        PSYSTEM_PROCESS_INFORMATION process = processSnapshot;

        do
        {
            // Either inspect one given PID or all processes with the image names matching the filter
            if (parsedArguments.ProcessId || 
                RtlIsNameInExpression(&parsedArguments.ProcessFilter, &process->ImageName, TRUE, NULL))
            {
                HANDLE pid = parsedArguments.ProcessId ? parsedArguments.ProcessId : process->UniqueProcessId;
                ULONG handlesFound = 0;

                // Try to open the process for inspection
                status = H2OpenProcess(&processHandle, pid, PROCESS_DUP_HANDLE);

                if (NT_SUCCESS(status) || parsedArguments.Verbose || parsedArguments.ProcessId)
                {
                    wprintf_s(L"%wZ [%zu]\r\n", 
                        parsedArguments.ProcessId ? &parsedArguments.ProcessFilter: &process->ImageName, 
                        (ULONG_PTR)pid
                    );
                    processesFound++;
                }

                if (!NT_SUCCESS(status) && (parsedArguments.Verbose || parsedArguments.ProcessId))
                {
                    wprintf_s(L"Unable to open the process: ");
                    H2PrintStatusWithDescription(status);
                    wprintf_s(L"\r\n\r\n");
                }

                if (!NT_SUCCESS(status))
                    continue;

                // Find AFD handle candidates in the process
                for (ULONG i = 0; i < handleSnapshot->NumberOfHandles; i++)
                {
                    if (handleSnapshot->Handles[i].UniqueProcessId == (HANDLE)(ULONG_PTR)pid &&
                        handleSnapshot->Handles[i].ObjectTypeIndex == fileHandleTypeIndex)
                    {
                        PCWSTR failureSite = NULL;

                        // Duplicate the handle from the process
                        status = NtDuplicateObject(
                            processHandle,
                            handleSnapshot->Handles[i].HandleValue,
                            NtCurrentProcess(),
                            &socketHandle,
                            0,
                            0,
                            DUPLICATE_SAME_ACCESS
                        );

                        if (NT_SUCCESS(status))
                        {
                            // Verify the handle belongs to AFD
                            status = H2AfdIsSocketHandle(socketHandle);

                            if (NT_SUCCESS(status))
                            {
                                // Print the socket overview
                                wprintf_s(L"[0x%0.4zX] ", (ULONG_PTR)handleSnapshot->Handles[i].HandleValue);
                                H2AfdQueryPrintSummarySocket(socketHandle);
                                wprintf_s(L"\r\n");
                                handlesFound++;
                            }
                            else if (status == STATUS_NOT_SAME_DEVICE)
                            {
                                // Skip non-AFD files
                                status = STATUS_SUCCESS;
                            }
                            else
                            {
                                failureSite = L"check the file device";
                            }
                        }
                        else
                        {
                            failureSite = L"duplicate the handle";
                        }

                        if (!NT_SUCCESS(status) && parsedArguments.Verbose)
                        {
                            wprintf_s(L"[0x%0.4zX] <Unable to %s>: ", (ULONG_PTR)handleSnapshot->Handles[i].HandleValue, failureSite);
                            H2PrintStatusWithDescription(status);
                            wprintf_s(L"\r\n");
                        }

                        if (socketHandle)
                        {
                            NtClose(socketHandle);
                            socketHandle = NULL;
                        }
                    }
                }

                if (handlesFound == 0)
                    wprintf_s(L"No sockets to display.\r\n");

                wprintf_s(L"\r\n");
            }
        } while (!parsedArguments.ProcessId && (process = H2NextProcess(process)));

        if (!parsedArguments.ProcessId && processesFound == 0)
            wprintf_s(L"No matching processes found.\r\n");
    }

    wprintf_s(L"Complete.\r\n");

CLEANUP:
    if (processSnapshot)
        H2Free(processSnapshot);

    if (handleSnapshot)
        H2Free(handleSnapshot);

    if (processHandle)
        NtClose(processHandle);

    if (socketHandle)
        NtClose(socketHandle);

    H2FreeArguments(&parsedArguments);

    return status;
}

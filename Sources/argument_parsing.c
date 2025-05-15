/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "argument_parsing.h"
#include "string_helpers.h"
#include "snapshot_helpers.h"
#include <wchar.h>

/**
  * \brief Interprets and records command-line arguments.
  *
  * \param[in] argc The number of arguments.
  * \param[in] argv An array of argument strings.
  * \param[out] ParsedArguments A storage for parsed argument values. The caller is responsible for freeing the result via H2FreeArguments.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2ParseArguments(
    _In_ LONG argc,
    _In_ PCWSTR argv[],
    _Out_ PH2_ARGUMENTS ParsedArguments
)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    H2_ARGUMENTS parsedArguments = { 0 };
    ULONG value;

    for (LONG i = 1; i < argc; i++)
    {
        if (lstrcmpW(argv[i], L"-p") == 0)
        {
            if (++i >= argc)
                return STATUS_INVALID_PARAMETER;

            if (NT_SUCCESS(H2ParseInteger(argv[i], &value)))
            {
                // If the process argument parses into an integer, it's a PID.

                if (value == 0)
                    return STATUS_INVALID_CID;
                else
                    parsedArguments.ProcessId = (HANDLE)(ULONG_PTR)value;

                // Lookup the process image name
                if (!NT_SUCCESS(H2QueryProcessIdImageName(parsedArguments.ProcessId, TRUE, &parsedArguments.ProcessFilter)))
                {
                    if (!RtlCreateUnicodeString(&parsedArguments.ProcessFilter, L"Unknown process"))
                        return STATUS_NO_MEMORY;
                }
            }
            else
            {
                UNICODE_STRING filter;

                // Otherwise, it's a filter/process name.
                RtlInitUnicodeString(&filter, argv[i]);
                status = RtlUpcaseUnicodeString(&parsedArguments.ProcessFilter, &filter, TRUE);

                if (!NT_SUCCESS(status))
                    return status;
            }

            status = STATUS_SUCCESS;
        }
        else if (lstrcmpW(argv[i], L"-h") == 0)
        {
            if (++i >= argc)
                return STATUS_INVALID_PARAMETER;

            status = H2ParseInteger(argv[i], &value);

            if (!NT_SUCCESS(status))
                return status;

            // We need a valid value
            if (value == 0)
                return STATUS_INVALID_HANDLE;
            else
                parsedArguments.HandleValue = (HANDLE)(ULONG_PTR)value;

        }
        else if (lstrcmpW(argv[i], L"-v") == 0)
        {
            parsedArguments.Verbose = TRUE;
        }
        else
        {
            // Unrecognized parameter
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (NT_SUCCESS(status))
        *ParsedArguments = parsedArguments;

    return status;
}

/**
  * \brief Releases previously parsed arguments.
  */
VOID H2FreeArguments(
    _Inout_ PH2_ARGUMENTS ParsedArguments
)
{
    if (ParsedArguments->ProcessFilter.Buffer)
    {
        RtlFreeUnicodeString(&ParsedArguments->ProcessFilter);
        memset(&ParsedArguments->ProcessFilter, 0, sizeof(UNICODE_STRING));
    }
}

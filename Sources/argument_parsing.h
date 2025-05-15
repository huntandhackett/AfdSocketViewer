/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _ARGUMENT_PARSING_H
#define _ARGUMENT_PARSING_H

#include <phnt_windows.h>
#include <phnt.h>

typedef struct _H2_ARGUMENTS
{
    UNICODE_STRING ProcessFilter;
    HANDLE ProcessId;
    HANDLE HandleValue;
    BOOLEAN Verbose;
} H2_ARGUMENTS, *PH2_ARGUMENTS;

NTSTATUS
NTAPI
H2ParseArguments(
    _In_ LONG argc,
    _In_ PCWSTR argv[],
    _Out_ PH2_ARGUMENTS ParsedArguments
);

VOID
NTAPI
H2FreeArguments(
    _Inout_ PH2_ARGUMENTS ParsedArguments
);

#endif

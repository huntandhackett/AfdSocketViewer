/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _STRING_HELPERS_H
#define _STRING_HELPERS_H

#include <phnt_windows.h>
#include <phnt.h>

#define NS_PER_TICK                 100ull
#define TICKS_PER_US                 10ull
#define TICKS_PER_MS             10'000ull
#define TICKS_PER_SEC        10'000'000ull
#define TICKS_PER_MIN       600'000'000ull
#define TICKS_PER_HOUR   36'000'000'000ull
#define TICKS_PER_DAY   864'000'000'000ull

VOID
NTAPI
H2PrintTimeSpan(
    _In_ ULONG64 TimeSpan
);

VOID
NTAPI
H2PrintTimeStamp(
    _In_ ULONG64 TimeStamp
);

#define BYTES_PER_KB            1'024ull
#define BYTES_PER_MB        1'048'576ull
#define BYTES_PER_GB    1'073'741'824ull

VOID
NTAPI
H2PrintByteSize(
    _In_ ULONG64 Bytes
);

VOID
NTAPI
H2PrintGuid(
    _In_ PGUID Guid
);

NTSTATUS
NTAPI
H2FindStatusDescription(
    _In_ NTSTATUS Status,
    _Out_ PUNICODE_STRING Message
);

VOID
NTAPI
H2PrintStatusWithDescription(
    _In_ NTSTATUS Status
);

NTSTATUS
NTAPI
H2ParseInteger(
    _In_ PCWSTR String,
    _Out_ PULONG Value
);

#endif _STRING_HELPERS_H

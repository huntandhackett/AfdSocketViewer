/*
 * Copyright (c) 2025 Hunt & Hackett.
 *
 * This project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "string_helpers.h"
#include <wchar.h>
#include <time.h>
#include <ntintsafe.h>

/**
  * \brief Outputs a time duration value to the console.
  *
  * \param[in] TimeSpan The time duration in 100-ns intervals.
  */
VOID H2PrintTimeSpan(
    _In_ ULONG64 TimeSpan
)
{
    if (TimeSpan == 0)
        wprintf_s(L"None");
    else if (TimeSpan < TICKS_PER_MS)
        wprintf_s(L"%I64u us", TimeSpan / TICKS_PER_US);
    else if (TimeSpan < TICKS_PER_SEC)
        wprintf_s(L"%I64u ms", TimeSpan / TICKS_PER_MS);
    else if (TimeSpan < TICKS_PER_MIN)
        wprintf_s(L"%I64u sec", TimeSpan / TICKS_PER_SEC);
    else
    {
        ULONG seconds = (TimeSpan / TICKS_PER_SEC) % 60;
        ULONG minutes = (TimeSpan / TICKS_PER_MIN) % 60;
        ULONG hours = (TimeSpan / TICKS_PER_HOUR) % 24;
        ULONG64 days = TimeSpan / TICKS_PER_DAY;

        if (TimeSpan < TICKS_PER_HOUR)
        {
            if (seconds)
                wprintf_s(L"%u min %u sec", minutes, seconds);
            else
                wprintf_s(L"%u min", minutes);
        }
        else if (TimeSpan < TICKS_PER_DAY)
        {
            if (minutes && seconds)
                wprintf_s(L"%u hours %u min %u sec", hours, minutes, seconds);
            else if (minutes)
                wprintf_s(L"%u hours %u min", hours, minutes);
            else if (seconds)
                wprintf_s(L"%u hours %u sec", hours, seconds);
            else
                wprintf_s(L"%u hours", hours);
        }
        else
        {
            if (hours && minutes)
                wprintf_s(L"%I64u days %u hours %u min", days, hours, minutes);
            else if (hours)
                wprintf_s(L"%I64u days %u hours", days, hours);
            else if (minutes)
                wprintf_s(L"%I64u days %u minutes", days, minutes);
            else
                wprintf_s(L"%I64u days", days);
        }
    }
}

/**
  * \brief Outputs a date and time value to the console.
  *
  * \param[in] TimeStamp A native Windows tume (the number of 100-ns intervals since Jan 1, 1600).
  */
VOID H2PrintTimeStamp(
    _In_ ULONG64 TimeStamp
)
{
    time_t unixTime;
    WCHAR buffer[20] = { 0 };
    PLARGE_INTEGER timeZoneBias;

    // Adjust for the current timezone
    timeZoneBias = (PLARGE_INTEGER)(&USER_SHARED_DATA->TimeZoneBias);
    unixTime = (TimeStamp - timeZoneBias->QuadPart) / TICKS_PER_SEC - SecondsToStartOf1970;

    // Convert to calendar time
    struct tm calendarTime;
    gmtime_s(&calendarTime, &unixTime);

    // Construct the string
    wcsftime(buffer, sizeof(buffer) / sizeof(WCHAR), L"%F %T", &calendarTime);
    wprintf_s(L"%s", buffer);
}

/**
  * \brief Outputs a number of bytes value to the console.
  *
  * \param[in] Bytes The time number of bytes.
  */
VOID H2PrintByteSize(
    _In_ ULONG64 Bytes
)
{
    if (Bytes < BYTES_PER_KB)
        wprintf_s(L"%I64u bytes", Bytes);
    else if (Bytes < BYTES_PER_KB * 10 && (Bytes % BYTES_PER_KB != 0))
        wprintf_s(L"%0.2f KiB", (float)(Bytes * 100 / BYTES_PER_KB) / 100);
    else if (Bytes < BYTES_PER_KB * 100 && (Bytes % BYTES_PER_KB != 0))
        wprintf_s(L"%0.1f KiB", (float)(Bytes * 10 / BYTES_PER_KB) / 10);
    else if (Bytes < BYTES_PER_MB)
        wprintf_s(L"%I64u KiB", Bytes / BYTES_PER_KB);
    else if (Bytes < BYTES_PER_MB * 10 && (Bytes % BYTES_PER_MB != 0))
        wprintf_s(L"%0.2f MiB", (float)(Bytes * 100 / BYTES_PER_MB) / 100);
    else if (Bytes < BYTES_PER_MB * 100 && (Bytes % BYTES_PER_MB != 0))
        wprintf_s(L"%0.1f MiB", (float)(Bytes * 10 / BYTES_PER_MB) / 10);
    else if (Bytes < BYTES_PER_GB)
        wprintf_s(L"%I64u MiB", Bytes / BYTES_PER_MB);
    else if (Bytes < BYTES_PER_GB * 10 && (Bytes % BYTES_PER_GB != 0))
        wprintf_s(L"%0.2f GiB", (float)(Bytes * 100 / BYTES_PER_GB) / 100);
    else if (Bytes < BYTES_PER_GB * 100 && (Bytes % BYTES_PER_GB != 0))
        wprintf_s(L"%0.1f GiB", (float)(Bytes * 10 / BYTES_PER_GB) / 10);
    else
        wprintf_s(L"%I64u GiB", Bytes / BYTES_PER_GB);
}

/**
  * \brief Outputs a GUID to the console.
  *
  * \param[in] Guid The GUID value.
  */
VOID H2PrintGuid(
    _In_ PGUID Guid
)
{
    wprintf_s(L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        Guid->Data1,
        Guid->Data2,
        Guid->Data3,
        Guid->Data4[0],
        Guid->Data4[1],
        Guid->Data4[2],
        Guid->Data4[3],
        Guid->Data4[4],
        Guid->Data4[5],
        Guid->Data4[6],
        Guid->Data4[7]
    );
}

/**
  * \brief Looks up a description for an NTSTATUS error.
  *
  * \param[in] Status An NTSTATUS value.
  * \param[out] Message A pointer to a UNICODE_STRING that will point to the status description stored in the resources.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2FindStatusDescription(
    _In_ NTSTATUS Status,
    _Out_ PUNICODE_STRING Message
)
{
    NTSTATUS status;
    UNICODE_STRING dllName;
    PVOID dllBase;
    PMESSAGE_RESOURCE_ENTRY messageEntry;
    WCHAR lastChar;

    // Choose the source of message description depending on whether
    // the status holds a packed Win32 error code or not.

    if (NT_NTWIN32(Status))
        RtlInitUnicodeString(&dllName, L"kernel32.dll");
    else
        RtlInitUnicodeString(&dllName, L"ntdll.dll");

    // Locate the DLL
    status = LdrGetDllHandle(NULL, NULL, &dllName, &dllBase);

    if (!NT_SUCCESS(status))
        return status;

    // Locate the message in the DLL's message table resource
    status = RtlFindMessage(
        dllBase,
        (ULONG)(ULONG_PTR)RT_MESSAGETABLE,
        0,
        NT_NTWIN32(Status) ? WIN32_FROM_NTSTATUS(Status) : (ULONG)Status,
        &messageEntry
    );

    if (!NT_SUCCESS(status))
        return status;

    // We only support unicode message resources
    if (!(messageEntry->Flags & MESSAGE_RESOURCE_UNICODE))
        return STATUS_NOT_SUPPORTED;

    // Point the result to the read-only buffer in the resources
    Message->Buffer = (PWSTR)messageEntry->Text;
    Message->MaximumLength = messageEntry->Length - FIELD_OFFSET(MESSAGE_RESOURCE_ENTRY, Text);
    Message->Length = Message->MaximumLength - sizeof(UNICODE_NULL);

    // Optionally, trim the "{Error name}\r\n" prefix that appears in some descriptions
    if (Message->Length > sizeof(WCHAR) &&
        Message->Buffer[0] == L'{')
        for (USHORT prefixEnd = 3; prefixEnd < Message->Length / sizeof(WCHAR); prefixEnd++)
            if (Message->Buffer[prefixEnd - 2] == L'}' &&
                Message->Buffer[prefixEnd - 1] == L'\r' &&
                Message->Buffer[prefixEnd] == L'\n')
            {
                // Move the start of the string so it skips the prefix
                prefixEnd++;
                Message->Buffer += prefixEnd;
                Message->Length -= prefixEnd * sizeof(WCHAR);
                Message->MaximumLength -= prefixEnd * sizeof(WCHAR);
                break;
            }

    // Optionally, trim the trailing new lines and spaces
    while (Message->Length >= sizeof(WCHAR) && 
        (lastChar = Message->Buffer[Message->Length / sizeof(WCHAR) - 1],
        (lastChar == L'\r' || lastChar == L'\n' || lastChar == L' ' || lastChar == L'\t' || lastChar == L'\0')))
        Message->Length -= sizeof(WCHAR);

    return STATUS_SUCCESS;
}

/**
  * \brief Outputs an NTSTATUS value with its description to the console.
  *
  * \param[in] Status An NTSTATUS value.
  */
VOID H2PrintStatusWithDescription(
    _In_ NTSTATUS Status
)
{
    UNICODE_STRING message;

    if (NT_SUCCESS(H2FindStatusDescription(Status, &message)))
        wprintf_s(L"0x%0.8X (%wZ)", Status, &message);
    else
        wprintf_s(L"0x%0.8X (no description available)", Status);
}

/**
  * \brief Converts a decimal or hexadecimal string to a number.
  *
  * \param[in] String The string with the textual representation of a number.
  * \param[in] Value An variable the receives the parsed value.
  *
  * \return Successful or errant status.
  */
NTSTATUS H2ParseInteger(
    _In_ PCWSTR String,
    _Out_ PULONG Value
)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    ULONG accumulated = 0;
    ULONG current;
    BOOLEAN isHex;

    isHex = String[0] == L'0' && (String[1] == L'x' || String[1] == L'X');

    for (ULONG i = isHex ? 2 : 0; String[i]; i++)
    {
        status = RtlUIntMult(accumulated, isHex ? 16 : 10, &accumulated);

        if (!NT_SUCCESS(status))
            return status;

        if (String[i] >= L'0' && String[i] <= L'9')
            current = String[i] - L'0';
        else if (isHex && String[i] >= L'a' && String[i] <= L'f')
            current = String[i] - L'a' + 0xa;
        else if (isHex && String[i] >= L'A' && String[i] <= L'F')
            current = String[i] - L'A' + 0xA;
        else
            return STATUS_INVALID_PARAMETER;

        status = RtlUIntAdd(accumulated, current, &accumulated);

        if (!NT_SUCCESS(status))
            return status;
    }

    if (NT_SUCCESS(status))
        *Value = accumulated;

    return status;
}

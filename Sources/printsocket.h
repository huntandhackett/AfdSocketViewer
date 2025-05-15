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

#ifndef _PRINTSOCKET_H
#define _PRINTSOCKET_H

VOID
NTAPI
H2AfdQueryPrintDetailsSocket(
    _In_ HANDLE SocketHandle,
    _In_ BOOLEAN VerboseMode
);

VOID
NTAPI
H2AfdQueryPrintSummarySocket(
    _In_ HANDLE SocketHandle
);

#endif

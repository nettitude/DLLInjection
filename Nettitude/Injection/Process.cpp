/*
Copyright (c) 2015, Nettitude
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
* Neither the name of Nettitude nor the
names of its contributors may be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL NETTITUDE BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "Process.h"
#include <TlHelp32.h>


extern "C"
BOOL Inject_GetProcessIdFromProcessName
(
IN CONST LPSTR pszProcessName,
OUT LPDWORD pdwProcessId
)
{
    BOOL bRet = FALSE;

    if (pszProcessName &&
        pdwProcessId)
    {

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hSnapshot)
        {
            PROCESSENTRY32 processEntry = { 0 };
            processEntry.dwSize = sizeof(PROCESSENTRY32);

            BOOL bEntry = Process32First(hSnapshot, &processEntry);

            while (bEntry)
            {
                if (_stricmp(processEntry.szExeFile, pszProcessName) == 0)
                {
                    *pdwProcessId = processEntry.th32ProcessID;
                    bEntry = FALSE;
                    bRet = TRUE;
                }
                else
                {
                    bEntry = Process32Next(hSnapshot, &processEntry);
                }
            }

            CloseHandle(hSnapshot);
        }
    }

    return bRet;
}

extern "C"
BOOL Inject_OpenProcessById
(
IN DWORD dwProcessId,
OUT LPHANDLE pHandle
)
{
    BOOL bRet = FALSE;

    if (pHandle)
    {
        *pHandle = OpenProcess( PROCESS_CREATE_THREAD |
                                PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_OPERATION |
                                PROCESS_VM_WRITE |
                                PROCESS_VM_READ,
                                FALSE,
                                dwProcessId
                                );

        bRet = (*pHandle) ? TRUE : FALSE;
    }

    return bRet;
}

extern "C"
BOOL Inject_OpenProcessByName
(
IN CONST LPSTR pszProcessName,
OUT LPHANDLE pHandle
)
{
    BOOL bRet = FALSE;

    if (pszProcessName &&
        pHandle)
    {
        DWORD dwProcessId = 0;

        if (Inject_GetProcessIdFromProcessName(pszProcessName, &dwProcessId))
        {
            bRet = Inject_OpenProcessById(dwProcessId, pHandle);
        }
    }

    return bRet;
}

extern "C"
BOOL Inject_OpenAnyThreadInProcessByName
(
IN CONST LPSTR pszProcessName,
OUT LPHANDLE pProcess,
OUT LPHANDLE pThread
)
{
    BOOL bRet = FALSE;
 
    if (pszProcessName &&
        pThread && 
        pProcess)
    {

        if (Inject_OpenProcessByName(pszProcessName, pProcess))
        {

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

            if (hSnapshot)
            {
                THREADENTRY32 thEntry = { 0 };
                thEntry.dwSize = sizeof(THREADENTRY32);
                DWORD processId = GetProcessId(*pProcess);
                DWORD threadId = 0xFFFFFFFF;
                BOOL bEntry = Thread32First(hSnapshot, &thEntry);



                //try and open any thread
                while(bEntry)
                {
                    if (processId == thEntry.th32OwnerProcessID)
                    {
                        //locate smallest thread Id and hope that this
                        //is the main thread of the application
                        if (thEntry.th32ThreadID < threadId)
                        {
                            threadId = thEntry.th32ThreadID;
                        }
                    }

                    if ( bEntry )
                    {
                        bEntry = Thread32Next(hSnapshot, &thEntry);
                    }
                }

                if (threadId != 0xFFFFFFFF)
                {
                    //all access is probably a bit much
                    *pThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);

                    if (*pThread)
                    {
                        bRet = TRUE;
                        bEntry = FALSE;
                    }
                }

                if (bRet == FALSE)
                {
                    CloseHandle(*pProcess);
                    *pProcess = NULL;
                    *pThread = NULL;
                }

                CloseHandle(hSnapshot);
            }
        }
    }

    return bRet;
}
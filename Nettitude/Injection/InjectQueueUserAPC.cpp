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

#include "InjectQueueUserAPC.h"
#include "Process.h"
#include "SeDebugPrivilege.h"
#include <TlHelp32.h>


BOOL Inject_QueueUserAPCByName
(
IN CONST LPSTR pszProcessName,
IN CONST LPSTR pszDllPath
)
{
    BOOL bRet = FALSE;
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;

    if (pszProcessName &&
        pszDllPath)
    {

        if (Inject_OpenProcessByName(pszProcessName, &hProcess))
        {
            //add one to the length for the NULL terminator        
            CONST SIZE_T fileNameLength = strlen(pszDllPath) + 1;

            if (fileNameLength && fileNameLength < MAX_PATH)
            {

                LPVOID pProcessMem = VirtualAllocEx(hProcess,
                    NULL,
                    fileNameLength,
                    MEM_COMMIT,
                    PAGE_READWRITE);

                if (pProcessMem)
                {
                    //copy filename into remote process memory
                    if (WriteProcessMemory(hProcess,
                        pProcessMem,
                        pszDllPath,
                        fileNameLength,
                        NULL))
                    {
                        HMODULE hKernel32 = GetModuleHandle("Kernel32.dll");

                        if (hKernel32)
                        {
                            void* pLoadLib = GetProcAddress(hKernel32, "LoadLibraryA");

                            if (pLoadLib)
                            {
                                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

                                if (hSnapshot)
                                {
                                    THREADENTRY32 thEntry = { 0 };
                                    thEntry.dwSize = sizeof(THREADENTRY32);
                                    DWORD processId = GetProcessId(hProcess);
                                    BOOL bEntry = Thread32First(hSnapshot, &thEntry);

                                    //try and open any thread
                                    while (bEntry)
                                    {
                                        if (processId == thEntry.th32OwnerProcessID)
                                        {

                                            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);

                                            //
                                            // Use QueueUserAPC...
                                            //
                                            //
                                            // The downside with this method is that it requires the thread to become
                                            // alertable, whereby it calls SleepEx, WaitForSingleObject etc.
                                            // so we take a punt and inject into every single thread 
                                            //
                                            // an alternative is to SetThreadContext and point EIP at SleepEx
                                            // which will possibly/probably kill the thread
                                            //
                                            if (hThread && QueueUserAPC((PAPCFUNC)pLoadLib, hThread, ((ULONG_PTR)pProcessMem)))
                                            {

                                                bRet = TRUE;
                                            }

                                            CloseHandle(hThread);

                                        }

                                        bEntry = Thread32Next(hSnapshot, &thEntry);
                                    }

                                    CloseHandle(hSnapshot);

                                }
                            }
                        }
                    }
                }
            }
        }
    }
        return bRet;
}
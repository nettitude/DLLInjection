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

#include "InjectNTCreateThreadEx.h"
#include "Process.h"
#include "SeDebugPrivilege.h"

struct NtCreateThreadExBuffer
{
    ULONG Size;
    ULONG Unknown1;
    ULONG Unknown2;
    PULONG Unknown3;
    ULONG Unknown4;
    ULONG Unknown5;
    ULONG Unknown6;
    PULONG Unknown7;
    ULONG Unknown8;
};

//
// Obtain NTCreateThreadEx function pointer
//
typedef NTSTATUS(WINAPI *fpNtCreateThreadEx)
(
OUT PHANDLE hThread,
IN ACCESS_MASK DesiredAccess,
IN LPVOID ObjectAttributes,
IN HANDLE ProcessHandle,
IN LPTHREAD_START_ROUTINE lpStartAddress,
IN LPVOID lpParameter,
IN BOOL CreateSuspended,
IN ULONG StackZeroBits,
IN ULONG SizeOfStackCommit,
IN ULONG SizeOfStackReserve,
OUT LPVOID lpBytesBuffer
);





static BOOL Inject_NTCreateThreadEx(HANDLE hProcess, CONST LPSTR pszDllPath)
{
    BOOL                   bRet = FALSE;
    fpNtCreateThreadEx     pNtCreateThreadEx = NULL;
    HMODULE                hNtDLL = GetModuleHandle("Ntdll.dll");
    NtCreateThreadExBuffer ntbuffer = { 0 };

    if (hNtDLL)
    {
        pNtCreateThreadEx =
            (fpNtCreateThreadEx)GetProcAddress(hNtDLL, "NtCreateThreadEx");
    }
       
    LARGE_INTEGER temp1 = { 0 };
    LARGE_INTEGER temp2 = { 0 };

    ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
    ntbuffer.Unknown1 = 0x10003;
    ntbuffer.Unknown2 = 0x8;
    ntbuffer.Unknown3 = (DWORD*)&temp2;
    ntbuffer.Unknown4 = 0;
    ntbuffer.Unknown5 = 0x10004;
    ntbuffer.Unknown6 = 4;
    ntbuffer.Unknown7 = (DWORD*)&temp1;
    ntbuffer.Unknown8 = 0;


    if (pNtCreateThreadEx && hProcess)
    {
        //add one to the length for the NULL terminator        
        CONST SIZE_T fileNameLength = strlen(pszDllPath) + 1;

        if (fileNameLength && fileNameLength<MAX_PATH)
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
                            //
                            // Create a remote thread starting at LoadLibrary
                            //
                            HANDLE hThread = NULL;
                            
                            pNtCreateThreadEx(&hThread,
                                0x1FFFFF,
                                NULL,
                                hProcess,
                                (LPTHREAD_START_ROUTINE)pLoadLib,
                                pProcessMem,
                                FALSE,
                                NULL,
                                NULL,
                                NULL,
                                &ntbuffer
                                );


                            if (hThread)
                            {
                                DWORD dwExitCode = 0;

                                //wait for the thread to complete
                                WaitForSingleObject(hThread, INFINITE);
                                GetExitCodeThread(hThread, &dwExitCode);

                                //LoadLibrary returns a module handle on success
                                //or NULL on failure, check this value.
                                if (dwExitCode != NULL)
                                {
                                    bRet = TRUE;
                                }
                            }
                        }
                    }
                }

                //release memory in remote process
                VirtualFreeEx(hProcess, pProcessMem, fileNameLength, MEM_RELEASE);
            }
        }
    }

    return bRet;
}

extern "C"
BOOL Inject_NTCreateThreadExByName(CONST LPSTR pszProcessName, CONST LPSTR pszDllPath)
{
    BOOL bRet = FALSE;
    HANDLE hProcess = NULL;

    if (pszDllPath)
    {
        if (Inject_SetDebugPrivilege())
        {
            if (Inject_OpenProcessByName(pszProcessName, &hProcess))
            {
                bRet = Inject_NTCreateThreadEx(hProcess, pszDllPath);

                CloseHandle(hProcess);
            }
        }
    }
    return bRet;
}

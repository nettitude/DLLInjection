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

#include <windows.h>
#include <stdio.h>
#include "Injector.h"


struct InjectionType
{
    enum Enum
    {
        INJECT_CREATEREMOTETHREAD,
        INJECT_NTCREATETHREADEX,
        INJECT_QUEUEUSERAPC,
    };
};


CHAR                g_szProcessName[MAX_PATH] = { 0 };
CHAR                g_szDLLPath[MAX_PATH] = { 0 };
InjectionType::Enum g_InjectType = InjectionType::INJECT_CREATEREMOTETHREAD;


void PrintHelp()
{
    fprintf(stderr, "DLL Injector (c) Nettitude Limited 2014\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "Injector <switch> <parameters>\n\n");
    fprintf(stderr, "switches:\n");
    fprintf(stderr, "    -crt         Uses CreateRemoteThread\n");
    fprintf(stderr, "    -ntcrt       Uses NTCreateThreadEx\n");
    fprintf(stderr, "    -apc         Uses QueueUserAPC\n");
    fprintf(stderr, "parameters:\n");
    fprintf(stderr, "    -crt <processname> <dllpath>\n");
    fprintf(stderr, "    -ntcrt <processname> <dllpath>\n");
    fprintf(stderr, "    -apc <processname> <dllpath>\n");
    fprintf(stderr, "example:\n");
    fprintf(stderr, "injector.exe -crt calc.exe C:\\temp\\hook.dll\n");
    fprintf(stderr, "\n\nNOTE: The full path to the DLL must be specified\n");
}


BOOL ProcessArguments(int argc, char** argv)
{
    BOOL bRet = FALSE;

    //strip file name
    const int argCount = argc-1;

    if (argc > 3)
    {
        if (_stricmp(argv[1], "-crt") == 0)
        {
            strncpy_s(g_szProcessName, argv[2], MAX_PATH - 1);
            strncpy_s(g_szDLLPath, argv[3], MAX_PATH - 1);
            bRet = TRUE;
            g_InjectType = InjectionType::INJECT_CREATEREMOTETHREAD;
        }
        else if (_stricmp(argv[1], "-ntcrt") == 0)
        {
            strncpy_s(g_szProcessName, argv[2], MAX_PATH - 1);
            strncpy_s(g_szDLLPath, argv[3], MAX_PATH - 1);
            bRet = TRUE;
            g_InjectType = InjectionType::INJECT_NTCREATETHREADEX;
        }
        else if (_stricmp(argv[1], "-apc") == 0)
        {
            strncpy_s(g_szProcessName, argv[2], MAX_PATH - 1);
            strncpy_s(g_szDLLPath, argv[3], MAX_PATH - 1);
            bRet = TRUE;
            g_InjectType = InjectionType::INJECT_QUEUEUSERAPC;
        }
    }


    if ( FALSE == bRet )
    {
        PrintHelp();
    }

    return bRet;
}



int main(int argc, char** argv)
{
    int ret = -1;

    if (ProcessArguments(argc, argv))
    {

        switch (g_InjectType)
        {
            case InjectionType::INJECT_CREATEREMOTETHREAD:
            {
                if (Inject_CreateRemoteThreadByName(g_szProcessName, g_szDLLPath))
                {
                    fprintf(stdout, "Inject CreateRemoteThread OK\n");
                }
                else
                {
                    fprintf(stderr, "Inject CreateRemoteThread Error 0x%.8X\n", GetLastError() );
                }
            }
            break;
            case InjectionType::INJECT_NTCREATETHREADEX:
            {
                if (Inject_NTCreateThreadExByName(g_szProcessName, g_szDLLPath))
                {
                    fprintf(stdout, "Inject NTCreateThreadEx OK\n");
                }
                else
                {
                    fprintf(stderr, "Inject NTCreateThreadEx Error 0x%.8X\n", GetLastError());
                }
            }
            break;
            case InjectionType::INJECT_QUEUEUSERAPC:
            {
                if (Inject_QueueUserAPCByName(g_szProcessName, g_szDLLPath))
                {
                    fprintf(stdout, "Inject QueueUserAPC OK\n");
                }
                else
                {
                    fprintf(stderr, "Inject QueueUserAPC Error 0x%.8X\n", GetLastError());
                }
            }
            break;
        default:
            fprintf(stderr, "Unknown injection type\n");
            break;
        }

    }

    return ret;
}




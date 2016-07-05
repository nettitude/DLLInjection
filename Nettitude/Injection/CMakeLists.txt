project( Injection )

set( SOURCE     InjectQueueUserAPC.h 
                InjectQueueUserAPC.cpp
                InjectCreateRemoteThread.h
                InjectCreateRemoteThread.cpp
                InjectNTCreateThreadEx.h
                InjectNTCreateThreadEx.cpp
                SeDebugPrivilege.h
                SeDebugPrivilege.cpp 
                Process.h 
                Process.cpp 
                Injection.h )

add_library( ${PROJECT_NAME} STATIC ${SOURCE} )
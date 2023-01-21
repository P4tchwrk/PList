#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>

/*
TODO :
- Enlever les .exe
*/

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL ListProcessThreads( DWORD dwOwnerPID, INT searched_process_pid);
BOOL GeneralProcessInfos(char* searched_exec);

int main(int argc, char *argv[])
{
    HANDLE hProcess=GetCurrentProcess();
    HANDLE hToken;

    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        //if(!SetPrivilege(hToken, SE_SECURITY_NAME, TRUE))
        if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
        {
            printf("Error setting privileges");
        }
        else
            printf("New privileges activated\n");
        
        CloseHandle(hToken);
    }
    else
        printf("Error getting process token");

    /////////////////Parse args/////////////////
    char *searched_exec = NULL;
    BOOL thread_search = FALSE;
    int searched_thread_id;
    
    for(int i=1; i< argc; i++) // Evite le nom de fichier en entree
    {
        if(argv[i] == "-h")
        {
            printf("Help page : ");
        }
        else if(!strcmp(argv[i], "-d"))
        {
            thread_search = TRUE;
            if(i+1<argc)
                searched_thread_id = atoi(argv[i+1]);
            else
                searched_thread_id = -1;
            printf("Searched thread id : %d\n", searched_thread_id);
        }
        else
        {
            searched_exec = argv[i];
        }
            
    }
    
    //////////////////////////////////////////// End parse args    

    if(thread_search)   // Launch different functions
    {
        ListProcessThreads(searched_thread_id, searched_thread_id);
        //if(ShowThreadInfos(searched_thread_id))
        //    printf("Error : %d\n", GetLastError());
        
        return 0;
    }
    else
    {
        if(GeneralProcessInfos(searched_exec))
            printf("Error\n");
        return 0;
    }
    
    return 0;
}

BOOL GeneralProcessInfos(char* searched_exec)
{
    /////////////////////Create snapshot
    
    DWORD self_process_id = 0;
    HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, self_process_id);
    if(hsnapshot == NULL)
    {
        printf("Erreur de la snapshot\n");
        return 1;
    }

    PROCESSENTRY32 process;
    process.dwSize = sizeof( PROCESSENTRY32 );
    
    HEAPLIST32 process_heap;
    process_heap.dwSize =  sizeof(HEAPLIST32);
    if(!Heap32ListFirst(hsnapshot, &process_heap))  // On met tous les heaps dans une liste
    {
        printf("Erreur dans la liste de heap\n");
    }
    if(!Process32First(hsnapshot, &process)) // Get le premier process
    {        
        printf("Erreur dans la liste de process\n");
        return 1;
    }
    //////////////////////
    // Formatage
    int max_len = 0;
    do
    {
        if(strlen(process.szExeFile) > max_len)
            max_len = strlen(process.szExeFile);
    }while(Process32Next(hsnapshot, &process));

    printf("<Exe>");
    for(int i=0; i<max_len/5; i++)
        printf("\t");
    printf("<Pid>\t<Pri>\t<Thrds>\t<Hnd>\t<Priv>\t\t\t\t<CPU Time>\t\t<Elapsed Time>\n");    // Top of the returned tab
    /////////////////////

    Process32First(hsnapshot, &process);
    HANDLE memory_handle;
    LPFILETIME start_time = malloc(sizeof(LPFILETIME));
    LPFILETIME end_time = malloc(sizeof(LPFILETIME));
    LPFILETIME kernel_time;
    LPFILETIME user_time;
    FILETIME raw_time_to_print;
    SYSTEMTIME time_to_print;
    HANDLE process_handle;
    BOOL valid;
    PDWORD hndCount;
    PROCESS_MEMORY_COUNTERS memCount;
    int rep;
    int j;
    
    char *process_name;
    do                      /// On parcourt les process
    {
        process_name = process.szExeFile;
        if(searched_exec != NULL && strcmp(searched_exec, process_name) || process.th32ProcessID == 0)
            continue;
        
        printf(process.szExeFile); // Exe
        for(int i=0; i<max_len/5-(strlen(process.szExeFile)/8); i++)    // Pour que tout soit aligné
        {
            printf("\t");
        }
        
        printf("%u",process.th32ProcessID); // Pid
        printf("\t%d", process.cntThreads); // Thrs nbr
        printf("\t%d", process.pcPriClassBase); // Pri
        ////////////////// Open a handle for more infos
        process_handle = NULL;
        process_handle = OpenProcess(  PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_READ,
                            FALSE, process.th32ProcessID);
        if(process_handle == NULL)  // Test error on handle
        {
            //printf("\tError : %d", GetLastError());
            //printf("\tErreur lors de la création du handle");
        }
        else
        {
        //////////////////////////// Hnd   
            if(GetProcessHandleCount(process_handle,&hndCount))
                printf("\t%d", hndCount);
            else
                printf("\t0");  // Au cas ou on set a zero
        ///////////////////////// Priv
            memCount.cb = sizeof(PROCESS_MEMORY_COUNTERS);
            if(GetProcessMemoryInfo(process_handle, &memCount, sizeof(PROCESS_MEMORY_COUNTERS)))
            {
                printf("\t%d",memCount.PagefileUsage);
                rep = 1;
                j = 0;
                while(rep < memCount.PagefileUsage)
                {
                    rep = rep*10;
                    j += 1; // j le nombre de caracs dans la chaine
                }
                for(int i=0; i<2-j/8; i++)    // This shit only to align content
                {
                    printf("\t");
                }
            }
            else
                printf("\t0");
        //////////////////////// Process times        
            
            if(!GetProcessTimes(process_handle, &start_time, &end_time, &kernel_time, &user_time) == 0) // if no error
            {
                if(LocalFileTimeToFileTime(&raw_time_to_print, &kernel_time))
                    if(FileTimeToSystemTime(&raw_time_to_print, &time_to_print))
                        printf("\t\t%d:%d:%d.%d", time_to_print.wHour, time_to_print.wMinute, time_to_print.wSecond, time_to_print.wMilliseconds);    // CPU Time

                end_time = end_time-start_time;
                if(LocalFileTimeToFileTime(&raw_time_to_print, &end_time))
                    if(FileTimeToSystemTime(&raw_time_to_print, &time_to_print))
                        printf("\t\t%d:%d:%d.%d", time_to_print.wHour, time_to_print.wMinute, time_to_print.wSecond, time_to_print.wMilliseconds);  // Elapsed Time
            }
            CloseHandle(process_handle);
            //////////////////
        }
        printf("\n");
        // Get thread id
    }while(Process32Next(hsnapshot, &process));
}

BOOL ListProcessThreads( DWORD dwOwnerPID, INT searched_process_pid) // When option -d is present
{ 
  HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
  THREADENTRY32 te32; 
  // Take a snapshot of all running threads  
  hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
  if( hThreadSnap == INVALID_HANDLE_VALUE ) 
    return(FALSE); 
  // Fill in the size of the structure before using it. 
  te32.dwSize = sizeof(THREADENTRY32); 
  // Retrieve information about the first thread,
  // and exit if unsuccessful
  if( !Thread32First( hThreadSnap, &te32 ) ) 
  {
    printf("Error");
    CloseHandle(hThreadSnap);          // clean the snapshot object
    return(FALSE);
  }
  // Now walk the thread list of the system,
  // and display information about each thread
  // associated with the specified process
  BOOL tab_inited = FALSE;
  HANDLE hThread;
  CONTEXT threadContext;
  LPFILETIME start_time;
  LPFILETIME end_time;
  LPFILETIME kernel_time;
  LPFILETIME user_time;
  FILETIME raw_time_to_print;
  SYSTEMTIME time_to_print;
  do 
  { 
    if( te32.th32OwnerProcessID == dwOwnerPID )
    {
        if(searched_process_pid == te32.th32OwnerProcessID)
        {
            if(!tab_inited)
            {
                printf("<Tid>\t<Pri>\t\t<Cswtch>\t<State>\t\t<User Time>\t\t<Kernel Time>\t\t<Elapsed Time>\n");
                tab_inited = TRUE;
            }
            // infos dans te32
            printf("%d\t", te32.th32ThreadID);
            printf("%d\t", te32.tpBasePri);
            //printf("%d\t", te32.cntUsage);
            hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_DIRECT_IMPERSONATION, FALSE, te32.th32ThreadID);
            // Le thread doit nous appartenir (d'ou l'impersonate) et etre suspend pour get le context
            if(hThread == NULL)
            {
                printf("Erreur de récupération du handle thread\n");
            }
            else
            {
                //////////////// Cswtch
                SuspendThread(hThread);
                if(GetThreadContext(hThread, &threadContext))
                    printf("\t%d",threadContext.ContextFlags);
                else
                {
                    printf("Error: %d\n", GetLastError());
                    printf("Pas de thread context");
                }
                ResumeThread(hThread);
                /////////////
                ///// State
                printf("\t\tMISS");
                //////A remplir
                /////////////
                ///// Times
                if(GetThreadTimes(hThread, &start_time, &end_time, &kernel_time, &user_time)) // if no error
                {
                    if(LocalFileTimeToFileTime(&raw_time_to_print, &user_time))
                        if(FileTimeToSystemTime(&raw_time_to_print, &time_to_print))
                            printf("\t\t%d:%d:%d.%d", time_to_print.wHour, time_to_print.wMinute, time_to_print.wSecond, time_to_print.wMilliseconds);    // user Time
                    if(LocalFileTimeToFileTime(&raw_time_to_print, &kernel_time))
                        if(FileTimeToSystemTime(&raw_time_to_print, &time_to_print))
                            printf("\t\t%d:%d:%d.%d", time_to_print.wHour, time_to_print.wMinute, time_to_print.wSecond, time_to_print.wMilliseconds);    // kernel Time
                    
                    end_time = end_time-start_time; // elapsed here
                    if(LocalFileTimeToFileTime(&raw_time_to_print, &user_time))
                        if(FileTimeToSystemTime(&raw_time_to_print, &time_to_print))
                            printf("\t\t\t%d:%d:%d.%d", time_to_print.wHour, time_to_print.wMinute, time_to_print.wSecond, time_to_print.wMilliseconds);    // elapsed Time
                    //////////////
                    CloseHandle(hThread);
                }
            }
            printf("\n");
        }
    }
  } while( Thread32Next(hThreadSnap, &te32 ) ); 

  CloseHandle( hThreadSnap );
  return( TRUE );
}


BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    LUID luid;
    BOOL bRet=FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        DWORD temp_;
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet=(GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}
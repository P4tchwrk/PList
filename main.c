#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>

/*
TODO :
- Creer des handles ou trouver un moyen pour get les times
*/

int main(int argc, char *argv[])
{
    /////////////////Parse args/////////////////
    char *searched_exec = NULL;
    BOOL thread_search = FALSE;
    int searched_thread_id;
    
    for(int i=1; i< argc; i++) // Evite le nom de fichier
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
    if(thread_search)
        printf("Thread search");
    
    //////////////////////////////////////////// End parse args
    
    /////////////////////Create snapshot
    
    DWORD self_process_id = 0;
    HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, self_process_id);
    if(hsnapshot == NULL)
    {
        printf("Erreur de la snapshot");
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
        printf("Erreur dans la liste de process");
        return 1;
    }
    
    //////////////////////End create snapshot
        
    // Formatage
    int max_len = 0;
    do
    {
        if(strlen(process.szExeFile) > max_len)
            max_len = strlen(process.szExeFile);
    }while(Process32Next(hsnapshot, &process));
    /////////////////////
    Process32First(hsnapshot, &process);
    PROCESS_MEMORY_COUNTERS process_memory;
    HANDLE memory_handle;
    LPFILETIME start_time;
    LPFILETIME end_time;
    LPFILETIME kernel_time;
    LPFILETIME user_time;
    
    printf("<Exe>");
    for(int i=0; i<max_len/5; i++)
        printf("\t");
    
    BOOL tab_inited = FALSE;
    char *process_name;

    do
    {
        // Parse arg
        if(thread_search)
        {
            ListProcessThreads(process.th32ProcessID, searched_thread_id);
        }
        else
        {
            if(!tab_inited)
            {
                printf("<Pid>\t<Pri>\t<Thdrs>\t<Dwsize>\n");    // Top of the returned tab
                tab_inited = TRUE;
            }
            process_name = process.szExeFile;
            if(searched_exec != NULL && strcmp(searched_exec, process_name))
                continue;
            
            printf(process.szExeFile); // Exe
            for(int i=0; i<max_len/5-(strlen(process.szExeFile)/8); i++)    // Pour que tout soit aligné
            {
                printf("\t");
            }
            
            printf("%u",process.th32ProcessID); // Pid
            printf("\t%d", process.cntThreads); // Thrs
            printf("\t%d", process.pcPriClassBase); // Pri
            printf("\n");
            // Get thread id
        }
    }while(Process32Next(hsnapshot, &process));
    return 0;
}

BOOL ListProcessThreads( DWORD dwOwnerPID, INT searched_process_pid) // When option -d is present
{ 
  HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
  THREADENTRY32 te32; 
 
  // Take a snapshot of all running threads  
  hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
  if( hThreadSnap == INVALID_HANDLE_VALUE ) 
    return( FALSE ); 
 
  // Fill in the size of the structure before using it. 
  te32.dwSize = sizeof(THREADENTRY32); 
 
  // Retrieve information about the first thread,
  // and exit if unsuccessful
  if( !Thread32First( hThreadSnap, &te32 ) ) 
  {
    printf("Error");
    CloseHandle( hThreadSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the thread list of the system,
  // and display information about each thread
  // associated with the specified process
  BOOL tab_inited = FALSE;
  do 
  { 
    if( te32.th32OwnerProcessID == dwOwnerPID )
    {
        if(searched_process_pid == te32.th32OwnerProcessID)
        {
            if(!tab_inited)
            {
                printf("<Tid>\t<Pri>\t<Cswtch>\t<State>\t<User Time>\t<Kernel Time>\t<Elapsed Time>\n");
                tab_inited = TRUE;
            }
            // infos dans te32

            printf("%d\t", te32.th32ThreadID);
            printf("%d\t", te32.tpBasePri);
            printf("%d\t", te32.cntUsage);
            
            //if(GetThreadTimes())
            printf("\n");
            printf("PID : %d\n", te32.th32OwnerProcessID);
        }
        

    }
  } while( Thread32Next(hThreadSnap, &te32 ) ); 

  CloseHandle( hThreadSnap );
  return( TRUE );
}

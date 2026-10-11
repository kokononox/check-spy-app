/* OWN fixture only, intentional handled breakpoint inside our asm DLL. No network/credentials. */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
typedef int (*CALLER)(void);
int main(int argc,char **argv){
 HMODULE dll;FILE *f;HANDLE h;CALLER caller;FARPROC cc,br,ret;
 if(argc!=4)return 2;
 dll=LoadLibraryA(argv[1]);if(!dll)return 3;
 caller=(CALLER)GetProcAddress(dll,"OwnCaller");cc=GetProcAddress(dll,"OwnCC");br=GetProcAddress(dll,"OwnCCBreak");ret=GetProcAddress(dll,"OwnReturnLabel");
 if(!caller||!cc||!br||!ret)return 4;
 if(fopen_s(&f,argv[2],"w"))return 5;
 fprintf(f,"{\"ExceptionRVA\":%llu,\"CallerReturnRVA\":%llu,\"ExpectedCandidateRVA\":%llu,\"SlotOffset\":48}",(unsigned long long)((uintptr_t)br-(uintptr_t)dll),(unsigned long long)((uintptr_t)ret-(uintptr_t)dll),(unsigned long long)((uintptr_t)cc-(uintptr_t)dll));fclose(f);
 __try{caller();}__except(EXCEPTION_EXECUTE_HANDLER){
  h=CreateFileA(argv[3],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);
 }
 Sleep(90000);FreeLibrary(dll);return 0;
}

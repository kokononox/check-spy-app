/* OWN synthetic fixture: deliberately raises a handled AV record before observation. No invalid memory access/network. */
#include <windows.h>
#include <stdio.h>
int main(int argc,char **argv){
 HMODULE module;HANDLE f;char handled[MAX_PATH];ULONG_PTR info[2]={1,0x42};
 if(argc!=3)return 2;
 module=LoadLibraryA(argv[1]);if(!module)return 3;
 __try{RaiseException(EXCEPTION_ACCESS_VIOLATION,0,2,info);}
 __except(EXCEPTION_EXECUTE_HANDLER){
  _snprintf_s(handled,sizeof(handled),_TRUNCATE,"%s.handled",argv[2]);
  f=CreateFileA(handled,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
  if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);
 }
 Sleep(90000);FreeLibrary(module);return 0;
}

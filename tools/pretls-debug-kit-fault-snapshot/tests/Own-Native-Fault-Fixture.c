/* OWN test only: a raised, handled synthetic AV record; no invalid memory dereference, credentials or network. */
#include <windows.h>
#include <stdio.h>
int main(int argc,char **argv){
 DWORD started=GetTickCount(); char handled[MAX_PATH]; HANDLE file;
 ULONG_PTR information[2]={8,0x42};
 if(argc!=2)return 2;
 while(GetFileAttributesA(argv[1])==INVALID_FILE_ATTRIBUTES){
  if(GetTickCount()-started>90000)return 3;
  Sleep(50);
 }
 __try{RaiseException(EXCEPTION_ACCESS_VIOLATION,0,2,information);}
 __except(EXCEPTION_EXECUTE_HANDLER){
  _snprintf_s(handled,sizeof(handled),_TRUNCATE,"%s.handled",argv[1]);
  file=CreateFileA(handled,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
  if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
 }
 Sleep(60000);
 return 0;
}

/* OWN local-file test only: loads our DLL, signals ready, waits. No network/credentials. */
#include <windows.h>
int main(int argc,char **argv){
 HMODULE module;HANDLE f;DWORD start;
 if(argc!=3)return 2;
 module=LoadLibraryA(argv[1]);if(!module)return 3;
 f=CreateFileA(argv[2],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
 if(f==INVALID_HANDLE_VALUE)return 4;CloseHandle(f);
 start=GetTickCount();while(GetTickCount()-start<90000)Sleep(50);
 FreeLibrary(module);return 0;
}

; OWN fixture only. Standard x64 unwind, one static callback slot. No network/credentials.
.code
PUBLIC OwnCaller, OwnCC, OwnCCBreak, OwnReturnLabel
OwnCC PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
OwnCCBreak LABEL BYTE
 int 3
 add rsp,28h
 ret
OwnCC ENDP
OwnCaller PROC FRAME
 sub rsp,58h
 .allocstack 58h
 .endprolog
 lea rax,OwnCC
 mov qword ptr [rsp+30h],rax
 call qword ptr [rsp+30h]
OwnReturnLabel LABEL BYTE
 mov eax,7
 add rsp,58h
 ret
OwnCaller ENDP
END

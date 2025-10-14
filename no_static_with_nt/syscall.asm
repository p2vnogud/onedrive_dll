EXTERN wNtCreateUserProcess:DWORD
EXTERN sysAddrNtCreateUserProcess:QWORD

.CODE

NtCreateUserProcess PROC
	mov r10, rcx
	mov eax, wNtCreateUserProcess
	jmp QWORD PTR [sysAddrNtCreateUserProcess]
NtCreateUserProcess ENDP

END
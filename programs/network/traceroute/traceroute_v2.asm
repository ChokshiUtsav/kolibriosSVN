2;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                                 ;;
;; Copyright (C) KolibriOS team 2010-2015. All rights reserved.    ;;
;; Distributed under terms of the GNU General Public License       ;;
;;                                                                 ;;
;;  traceroute.asm - ICMP based packet path tracer utility         ;;
;;                                                                 ;;
;;  Written by Utsav_Chokshi		                               ;;
;;                                                                 ;;
;;          GNU GENERAL PUBLIC LICENSE                             ;;
;;             Version 2, June 1991                                ;;
;;                                                                 ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Header of Application : Remains same for all programs          ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
format binary as ""

BUFFERSIZE      = 1500
IDENTIFIER      = 0x1337

use32
org     0x0

	db      'MENUET01'      ; signature
	dd      1               ; header version
	dd      START           ; entry point
	dd      I_END           ; initialized size
	dd      IM_END+0x1000   ; required memory
	dd      IM_END+0x1000   ; stack pointer
	dd      params          ; parameters
	dd      0               ; path

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Including needed libraries                                     ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

include '../../proc32.inc'
include '../../macros.inc'
purge mov,add,sub
include '../../dll.inc'
include '../../struct.inc'
include '../../network.inc'

include 'icmp.inc'
include 'ip.inc'


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; One time activity : Allocating heap space, loading libraries and intializaing console ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

START:
; init heap
        mcall   68, 11
        test    eax, eax
        jz      exit
; load libraries
        stdcall dll.Load, @IMPORT
        test    eax, eax
        jnz     exit
; initialize console
        push    1
        call    [con_start]
        push    title
        push    250
        push    80
        push    25
        push    80
        call    [con_init]
        push    str_welcome
        call    [con_write_asciiz]	

; expand payload to 65504 bytes
; movsd moves double word at address ESI to EDI

        mov     edi, icmp_packet.data+32
        mov     ecx, 65504/32-1
  .expand_payload:
        mov     esi, icmp_packet.data
        movsd
        movsd
        movsd
        movsd
        movsd
        movsd
        movsd
        movsd
        dec     ecx
        jnz     .expand_payload

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Main : Loop for handling one traceroute request               ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

main:
; write prompt
        push    str_prompt
        call    [con_write_asciiz]

; read string
        mov     esi, params
        push    1024
        push    esi
        call    [con_gets]

; check for exit
        test    eax, eax
        jz      exit
        cmp     byte [esi], 10
        jz      exit

; delete terminating '\n'
        push    esi
	@@:
        lodsb
        test    al, al
        jnz     @b
        mov     [esi-2], al
        pop     esi

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Parses parameters - address , -w and -l options for given request ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

parse_param:
; parameters defaults
        mov     [count], 1 
        mov     [size], 32
        mov     [ttl], 1
        mov     [timeout], 500

; Check if any additional parameters were given
        mov     esi, params
        mov     ecx, 1024
  .addrloop:
        lodsb
        test    al, al
        jz      .resolve
        cmp     al, ' '
        jne     .addrloop
        mov     byte[esi-1], 0
        jmp     .param

  .param_loop:
        lodsb
        test    al, al
        jz      .resolve
        cmp     al, ' '
        jne     .invalid
  .param:
        lodsb
        cmp     al, '-'
        jne     .invalid
        lodsb
        cmp     al, 'w'
        jne     @f
        call    ascii_to_dec
        test    ebx, ebx
        jz      .invalid
        mov     [timeout], ebx
        jmp     .param_loop
  @@:
        ; implement more parameters here

  .invalid:
        push    str13
        call    [con_write_asciiz]
        jmp     main

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Resolving an URL to IP address                              ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;        

; resolve name
.resolve:
        push    esp     ; reserve stack place
        push    esp     ; fourth parameter
        push    0       ; third parameter
        push    0       ; second parameter
        push    params  ; first parameter
        call    [getaddrinfo]
        pop     esi
; test for error
        test    eax, eax
        jnz     fail

; convert IP address to decimal notation
        mov     eax, [esi+addrinfo.ai_addr]
        mov     eax, [eax+sockaddr_in.sin_addr]
        mov     [sockaddr1.ip], eax
        push    eax
        call    [inet_ntoa]
; write result
        mov     [ip_ptr], eax
        push    eax

; free allocated memory
        push    esi
        call    [freeaddrinfo]

        push    str4
        call    [con_write_asciiz]

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Creating socket and connecting to destination IP address  ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;  create socket

        mcall   socket, AF_INET4, SOCK_RAW, IPPROTO_ICMP
        cmp     eax, -1
        jz      sockerror
        mov     [socketnum], eax

;  connect to destination IP address with socket created above

        mcall   connect, [socketnum], sockaddr1, 18
        cmp     eax, -1
        je      sockerror

;  print intial information

push    str3
call    [con_write_asciiz]

push    [ip_ptr]
call    [con_write_asciiz]

push    str3b
call    [con_write_asciiz]

push    [size]
push    str3c
call    [con_printf]
add     esp, 2*4  

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Mainloop : Loop for handling one packet sent                    ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

mainloop:
        ; Checking user has pressed close button or not?
        call    [con_get_flags]
        test    eax, 0x200                      ; con window closed?
        jnz     exit_now

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Preparing and Sending packet                           ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ; Preparing a packet to send with given ttl
        pushd   [ttl]
        pushd   4                               ; length of option
        pushd   IP_TTL
        pushd   IPPROTO_IP
        mcall   setsockopt, [socketnum], esp
        add     esp, 16
        cmp     eax, -1
        je      sockerror
        mcall   40, EVM_STACK

        ; Sending a packet prepared
        mcall   26, 10                          ; Get high precision timer count
        mov     [time_reference], eax
        mov     esi, [size]
        add     esi, sizeof.ICMP_header
        xor     edi, edi
        mcall   send, [socketnum], icmp_packet
        cmp     eax, -1
        je      sockerror

        ; Waiting for reply
        mcall   23, [timeout]
        mcall   26, 10                          ; Get high precision timer count
        
        ; Calculating time taken
        sub     eax, [time_reference]
        jz      @f
        xor     edx, edx
        mov     ebx, 100000
        div     ebx
        cmp     edx, 50000
        jb      @f
        inc     eax
  @@:
        mov     [time_reference], eax

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Receiving Reply                            ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Receive reply
        mcall   recv, [socketnum], buffer_ptr, BUFFERSIZE, MSG_DONTWAIT
        cmp     eax, -1
        je      .no_response
        test    eax, eax
        jz      sockerror
; IP header length
        movzx   esi, byte[buffer_ptr]
        and     esi, 0xf
        shl     esi, 2
; Check packet length
        sub     eax, esi
        sub     eax, sizeof.ICMP_header
        jb      .invalid
        mov     [recvd], eax

; make esi point to ICMP packet header
        add     esi, buffer_ptr

; we have a response, print all details related to HOP (sender's IP Address)
        push    esi
        mov     eax, [buffer_ptr + IPv4_header.SourceAddress]
        rol     eax, 16
        movzx   ebx, ah
        push    ebx
        movzx   ebx, al
        push    ebx
        shr     eax, 16
        movzx   ebx, ah
        push    ebx
        movzx   ebx, al
        push    ebx
        push    [time_reference]
        push    [count]
        push    str11
        call    [con_printf]
        add     esp, 5*4
        pop     esi

; What kind of response is it?
        cmp     [esi + ICMP_header.Type], ICMP_ECHOREPLY
        je      .echo_reply
        cmp     [esi + ICMP_header.Type], ICMP_TIMXCEED
        je      .ttl_exceeded
        jmp     .invalid

  .echo_reply:
        push    str4
        call    [con_write_asciiz]
        jmp main

  .ttl_exceeded:
        jmp     .continue

; Invalid reply
  .invalid:
        jmp     .continue

; Timeout!
  .no_response:
        dec [count]

; Sending more packets based on count
  .continue:
        inc     [icmp_packet.seq]
        inc     [count]
        cmp     [count], 30
        je      .newreq
; wait a second before sending next request
        mcall   5, 100
        inc     [ttl]
        jmp     mainloop

; Prompts user for next input
  .newreq:
        jmp     main

; DNS error
fail:
        push    str5
        call    [con_write_asciiz]
        jmp     main

; Socket error
sockerror:
        push    str6
        call    [con_write_asciiz]
        jmp     main


; Finally.. exit!
exit:
        push    1
        call    [con_exit]
exit_now:
        mcall   -1

ascii_to_dec:

        lodsb
        cmp     al, ' '
        jne     .fail

        xor     eax, eax
        xor     ebx, ebx
  .loop:
        lodsb
        test    al, al
        jz      .done
        cmp     al, ' '
        je      .done
        sub     al, '0'
        jb      .fail
        cmp     al, 9
        ja      .fail
        lea     ebx, [ebx*4+ebx]
        lea     ebx, [ebx*2+eax]
        jmp     .loop
  .fail:
        xor     ebx, ebx
  .done:
        dec     esi
        ret



; data
title   db      'Traceroute Utility(v1.0)',0

str_welcome db  'Please enter the hostname or IP-address of the host you want to trace the route for,',10
            db  'or just press enter to exit.',10,10
            db  'Options:',10
            db  ' -w time-out   Time-out in hundredths of a second.',10,0

str_prompt  db  10,'> ',0

str3    db      'Tracing route to  ',0
str3b   db      10,'over maximum of 30 hops',10,0
str3c   db      ' with %u data bytes',10,0


str4    db      10,0
str5    db      'Name resolution failed.',10,0
str6    db      'Socket error.',10,0
str13   db      'Invalid parameter(s)',10,0

str11   db       10,'%d : %d : %u.%u.%u.%u',0

str8    db      'Timeout',10,0
str9    db      'miscompare at offset %u.',10,0
str10   db      'invalid reply.',10,0
str14   db      'TTL expired.',10,0


sockaddr1:
        dw AF_INET4
.port   dw 0
.ip     dd 0
        rb 10

time_reference  dd ?
ip_ptr          dd ?
count           dd ?
size            dd ?
ttl             dd 1
timeout         dd ?
recvd           dd ?    ; received number of bytes in last packet

stats:
        .tx     dd ?
        .rx     dd ?
        .time   dd ?

; import
align 4
@IMPORT:

library network, 'network.obj', console, 'console.obj'
import  network,        \
        getaddrinfo,    'getaddrinfo',  \
        freeaddrinfo,   'freeaddrinfo', \
        inet_ntoa,      'inet_ntoa'

import  console,        \
        con_start,      'START',        \
        con_init,       'con_init',     \
        con_write_asciiz,       'con_write_asciiz',     \
        con_printf,       'con_printf',     \
        con_exit,       'con_exit',     \
        con_gets,       'con_gets',\
        con_cls,        'con_cls',\
        con_getch2,     'con_getch2',\
        con_set_cursor_pos, 'con_set_cursor_pos',\
        con_get_flags,  'con_get_flags'

socketnum       dd ?

icmp_packet     db ICMP_ECHO    ; type
                db 0            ; code
                dw 0            ; checksum
 .id            dw IDENTIFIER   ; identifier
 .seq           dw 0x0000       ; sequence number
 .data          db 'abcdefghijklmnopqrstuvwxyz012345'

I_END:
                rb 65504-32

params          rb 1024
buffer_ptr:     rb BUFFERSIZE

IM_END:
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                                 ;;
;; Copyright (C) KolibriOS team 2010-2015. All rights reserved.    ;;
;; Distributed under terms of the GNU General Public License       ;;
;;                                                                 ;;
;;  VNC client for KolibriOS                                       ;;
;;                                                                 ;;
;;  Written by hidnplayr@kolibrios.org                             ;;
;;                                                                 ;;
;;          GNU GENERAL PUBLIC LICENSE                             ;;
;;             Version 2, June 1991                                ;;
;;                                                                 ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

format binary as ""

__DEBUG__       = 1
__DEBUG_LEVEL__ = 2

BITS_PER_PIXEL  = 8            ; 8, 16 24

use32

        org     0x0

        db      "MENUET01"      ; 8 byte id
        dd      0x01            ; header version
        dd      START           ; start of code
        dd      I_END           ; size of image
        dd      IM_END          ; memory for app
        dd      IM_END          ; esp
        dd      0x0, 0x0        ; I_Param , I_Path

include "../../macros.inc"
include "../../debug-fdo.inc"
include "../../proc32.inc"
include "../../dll.inc"
include "../../struct.inc"
include "../../develop/libraries/box_lib/trunk/box_lib.mac"
include "../../network.inc"

struct  pixel_format
        bpp             db ?
        depth           db ?
        big_endian      db ?
        true_color      db ?
        red_max         dw ?
        green_max       dw ?
        blue_max        dw ?
        red_shift       db ?
        green_shift     db ?
        blue_shift      db ?
        padding         rb 3
ends

struct  framebuffer
        width           dw ?
        height          dw ?
        pixelformat     pixel_format
        name_length     dd ?
        name            rb 256
ends

xpos                    = 4
ypos                    = 21

TIMEOUT                 = 5             ; timeout in seconds

RECEIVE_BUFFER_SIZE     = 8*1024*1024   ; 8 Mib

STATUS_INITIAL          = 0
STATUS_CONNECTING       = 1
STATUS_REQ_LOGIN        = 2
STATUS_LOGIN            = 3
STATUS_CONNECTED        = 4
STATUS_CLOSED           = 5

STATUS_DISCONNECTED     = 10
STATUS_DNS_ERR          = 11
STATUS_SOCK_ERR         = 12
STATUS_CONNECT_ERR      = 13
STATUS_PROTO_ERR        = 14
STATUS_SECURITY_ERR     = 15
STATUS_LIB_ERR          = 16
STATUS_THREAD_ERR       = 17
STATUS_LOGIN_FAILED     = 18

BYTES_PER_PIXEL = (BITS_PER_PIXEL + 7) / 8

include "keymap.inc"
include "gui.inc"
include "network.inc"
include "raw.inc"
include "copyrect.inc"
include "rre.inc"
include "des.inc"

START:

        mcall   68, 11                  ; init heap

; Load libraries
        stdcall dll.Load, @IMPORT
        test    eax, eax
        jz      @f
        mov     [status], STATUS_LIB_ERR
  @@:

; Present the user with the GUI and wait for network connection
        call    draw_gui

; Create main window
        mcall   71, 1, name             ; reset window caption (add server name)

        mov     edx, dword[screen]
        movzx   esi, dx
        shr     edx, 16
        add     edx, 2*xpos
        add     esi, ypos+xpos
        mcall   67, 10, 10              ; resize the window

        mcall   40, EVM_MOUSE + EVM_MOUSE_FILTER + EVM_KEY + EVM_REDRAW + EVM_BUTTON

        mcall   66, 1, 1                ; Switch keyboard to scancode mode

        call    generate_keymap

redraw:
        mcall   12, 1

        mov     ebx, dword[screen]
        movzx   ecx, bx
        shr     ebx, 16
        mov     edx, 0x74ffffff
        mov     edi, name
        mcall   0                       ; draw window

        mcall   12, 2

draw_framebuffer:
        mcall   7, framebuffer_data, dword[screen], 0
        mov     [update_framebuffer], 0

mainloop:
        cmp     [status], STATUS_CONNECTED
        jne     draw_gui
        cmp     [update_framebuffer], 0
        jne     draw_framebuffer

        mcall   23, 10                  ; Check for event with 0,1s timeout

        dec     eax
        jz      redraw
        dec     eax
        jz      key
        dec     eax
        jz      button
        sub     eax, 3
        jz      mouse
        jmp     mainloop

key:
        mcall   66, 3
        mov     ebx, eax        ; get modifier keys

        mcall   2               ; get key scancode
        cmp     ah, 224         ; extended keycode?
        je      .extended

        xor     al, al
        test    ah, 0x80        ; key up?
        jnz     @f
        inc     al
  @@:
        mov     byte[KeyEvent.down], al

        movzx   eax, ah

        test    ebx, 100000b    ; alt?
        jz      .no_alt
        mov     ax, [keymap_alt+eax*2]
        jmp     .key
  .no_alt:

        test    ebx, 11b        ; shift?
        jz      .no_shift
        mov     ax, [keymap_shift+eax*2]
        jmp     .key
  .no_shift:

        test    ebx, 10000000b  ; numlock ?
        jz      .no_numlock
        cmp     al, 71
        jb      .no_numlock
        cmp     al, 83
        ja      .no_numlock
        mov     ah, [keymap_numlock+eax-71]
        xor     al, al
        jmp     .key

  .extended:                    ; extended keys always use regular keymap
        mcall   2
        shr     eax, 8
        jz      mainloop
  .no_numlock:
        mov     ax, [keymap+eax*2]
  .key:
        test    ax, ax
        jz      mainloop
        mov     word[KeyEvent.key+2], ax
        DEBUGF  1, "Sending key: 0x%x\n", ax
        mcall   send, [socketnum], KeyEvent, 8, 0
        jmp     mainloop



mouse:
;        DEBUGF  1, "Sending pointer event\n"

        mcall   37, 1           ; get mouse pos
        bswap   eax
        mov     [PointerEvent.x], ax
        shr     eax, 16
        mov     [PointerEvent.y], ax

        mcall   37, 2           ; get mouse buttons
        test    al, 00000010b   ; test if right button was pressed  (bit 1 in kolibri)
        jz      @f
        add     al, 00000010b   ; in RFB protocol it is bit 2, so if we add bit 2 again, we"ll get bit 3 and bit 1 will remain the same
      @@:
        mov     [PointerEvent.mask], al

        mcall   send, [socketnum], PointerEvent, 6, 0
        jmp     mainloop

button:
        mcall   17              ; get id
        mov     [status], STATUS_CLOSED
        mcall   close, [socketnum]
        mcall   -1


; DATA AREA

include_debug_strings

keymap_numlock:
        db      '7', '8', '9', '-'
        db      '4', '5', '6', '+'
        db      '1', '2', '3'
        db      '0', '.'

HandShake               db "RFB 003.003", 10

ClientInit              db 0            ; not shared

SetPixelFormat32        db 0            ; setPixelformat
                        db 0, 0, 0      ; padding
.bpp                    db 32           ; bits per pixel
.depth                  db 32           ; depth
.big_endian             db 0            ; big-endian flag
.true_color             db 1            ; true-colour flag
.red_max                db 0, 255       ; red-max
.green_max              db 0, 255       ; green-max
.blue_max               db 0, 255       ; blue-max
.red_shif               db 0            ; red-shift
.green_shift            db 8            ; green-shift
.blue_shift             db 16           ; blue-shift
                        db 0, 0, 0      ; padding

SetPixelFormat24        db 0            ; setPixelformat
                        db 0, 0, 0      ; padding
.bpp                    db 24           ; bits per pixel
.depth                  db 24           ; depth
.big_endian             db 0            ; big-endian flag
.true_color             db 1            ; true-colour flag
.red_max                db 0, 255       ; red-max
.green_max              db 0, 255       ; green-max
.blue_max               db 0, 255       ; blue-max
.red_shift              db 16           ; red-shift
.green_shift            db 8            ; green-shift
.blue_shift             db 0            ; blue-shift
                        db 0, 0, 0      ; padding

SetPixelFormat16        db 0            ; setPixelformat
                        db 0, 0, 0      ; padding
.bpp                    db 16           ; bits per pixel
.depth                  db 16           ; depth
.big_endian             db 0            ; big-endian flag
.true_color             db 1            ; true-colour flag
.red_max                db 0, 31        ; red-max
.green_max              db 0, 63        ; green-max
.blue_max               db 0, 31        ; blue-max
.red_shift              db 11           ; red-shift
.green_shift            db 5            ; green-shift
.blue_shift             db 0            ; blue-shift
                        db 0, 0, 0      ; padding

SetPixelFormat8         db 0            ; setPixelformat
                        db 0, 0, 0      ; padding
.bpp                    db 8            ; bits per pixel
.depth                  db 8            ; depth
.big_endian             db 0            ; big-endian flag
.true_color             db 1            ; true-colour flag
.red_max                db 0, 7         ; red-max
.green_max              db 0, 7         ; green-max
.blue_max               db 0, 3         ; blue-max
.red_shift              db 0            ; red-shift
.green_shift            db 3            ; green-shift
.blue_shift             db 6            ; blue-shift
                        db 0, 0, 0      ; padding

SetEncodings            db 2            ; setEncodings
                        db 0            ; padding
                        db 0, 3         ; number of encodings
                        db 0, 0, 0, 1   ; Copyrect encoding
                        db 0, 0, 0, 2   ; RRE
                        db 0, 0, 0, 0   ; raw encoding
;                        db 0, 0, 0, 5   ; HexTile
;                        db 0, 0, 0, 15  ; TRLE
;                        db 0, 0, 0, 16  ; ZRLE
  .length = $ - SetEncodings

FramebufferUpdateRequest        db 3
.inc                            db 0    ; incremental
.x                              dw 0
.y                              dw 0
.width                          dw 0
.height                         dw 0

KeyEvent                db 4            ; keyevent
.down                   db 0            ; down-flag
                        dw 0            ; padding
.key                    dd 0            ; key

PointerEvent            db 5            ; pointerevent
.mask                   db 0            ; button-mask
.x                      dw 0            ; x-position
.y                      dw 0            ; y-position


sockaddr1:
                dw AF_INET4
.port           dw 0x0c17               ; 5900
.ip             dd 0
                rb 10

beep            db 0x85, 0x25, 0x85, 0x40, 0

status                  dd STATUS_INITIAL
update_gui              dd 0
mouse_dd                dd 0
update_framebuffer      dd 0

URLbox          edit_box 235, 70, 20, 0xffffff, 0x6f9480, 0, 0, 0, 65535, serveraddr, mouse_dd, ed_focus, 0, 0
USERbox         edit_box 215, 90, 10, 0xffffff, 0x6f9480, 0, 0, 0, 127, username, mouse_dd, ed_focus, 0, 0
PASSbox         edit_box 215, 90, 30, 0xffffff, 0x6f9480, 0, 0, 0, 127, password, mouse_dd, ed_pass, 0, 0

serverstr       db "server:"
userstr         db "username:"
passstr         db "password:"
connectstr      db "Connect"
loginstr        db "Log in"
loginstr_e:

sz_err_disconnected     db "Server closed connection unexpectedly.", 0
sz_err_dns              db "Could not resolve hostname.", 0
sz_err_sock             db "Could not open socket.", 0
sz_err_connect          db "Could not connect to the server.", 0
sz_err_proto            db "A protocol error has occured.", 0
sz_err_security         db "Server requested an unsupported security type.", 0
sz_err_library          db "Could not load needed libraries.", 0
sz_err_thread           db "Could not create thread.", 0
sz_err_login_failed     db "Login failed.", 0

err_msg         dd sz_err_disconnected
                dd sz_err_dns
                dd sz_err_sock
                dd sz_err_connect
                dd sz_err_proto
                dd sz_err_security
                dd sz_err_library
                dd sz_err_thread
                dd sz_err_login_failed

; import
align 4
@IMPORT:

library network,                "network.obj",\
        box_lib,                "box_lib.obj",\
        archiver,               "archiver.obj"

import  network,\
        getaddrinfo,            "getaddrinfo",  \
        freeaddrinfo,           "freeaddrinfo", \
        inet_ntoa,              "inet_ntoa"

import  box_lib,\
        edit_box_draw,          "edit_box",\
        edit_box_key,           "edit_box_key",\
        edit_box_mouse,         "edit_box_mouse",\
        scrollbar_v_draw,       "scrollbar_v_draw",\
        scrollbar_v_mouse,      "scrollbar_v_mouse",\
        scrollbar_h_draw,       "scrollbar_h_draw",\
        scrollbar_h_mouse,      "scrollbar_h_mouse"

import  archiver,\
        deflate_unpack,         "deflate_unpack"

name                    db "VNC viewer "
.dash                   db 0, " "

I_END:

servername              rb 64+1

socketnum               dd ?
datapointer             dd ?

rectangles              dw ?

rectangle:
.x                      dd ?
.y                      dd ?
.width                  dd ?
.height                 dd ?

subrectangles           dd ?

subrectangle:
.x                      dd ?
.y                      dd ?
.width                  dd ?
.height                 dd ?

screen:                 ; Remote screen resolution
.height                 dw ?
.width                  dw ?

keymap                  rw 128
keymap_shift            rw 128
keymap_alt              rw 128
username                rb 128
password                rb 128
keys                    rd 32*2         ; DES keys for VNC authentication

serveraddr              rb 65536
receive_buffer          rb RECEIVE_BUFFER_SIZE
framebuffer_data        rb 1280*1024*3  ; framebuffer

                        rb 0x1000
thread_stack:
                        rb 0x1000
IM_END:



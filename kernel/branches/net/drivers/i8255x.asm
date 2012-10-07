;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                                 ;;
;; Copyright (C) KolibriOS team 2004-2012. All rights reserved.    ;;
;; Distributed under terms of the GNU General Public License       ;;
;;                                                                 ;;
;; i8255x (Intel eepro 100) driver for KolibriOS                   ;;
;;                                                                 ;;
;;    Written by hidnplayr@kolibrios.org                           ;;
;;                                                                 ;;
;;          GNU GENERAL PUBLIC LICENSE                             ;;
;;             Version 2, June 1991                                ;;
;;                                                                 ;;
;;                                                                 ;;
;; Good read about how to program this family of devices:          ;;
;; http://www.intel.com/design/network/manuals/8255x_opensdm.htm   ;;
;;                                                                 ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


format MS COFF

        API_VERSION             =   0x01000100
        DRIVER_VERSION          =   5

        MAX_DEVICES             =   16

        DEBUG                   =   1
        __DEBUG__               =   1
        __DEBUG_LEVEL__         =   1

include 'proc32.inc'
include 'imports.inc'
include 'fdo.inc'
include 'netdrv.inc'

public START
public service_proc
public version

virtual at ebx

        device:

        ETH_DEVICE

        .io_addr        dd ?
        .pci_bus        db ?
        .pci_dev        db ?
        .irq_line       db ?

        .rx_buffer      dd ?
        .tx_buffer      dd ?

        .ee_bus_width   dd ?

                        rb 0x100 - (($ - device) and 0xff)

        rxfd:
        .status         dw ?
        .command        dw ?
        .link           dd ?
        .rx_buf_addr    dd ?
        .count          dw ?
        .size           dw ?
        .packet         dd ?

                        rb 0x100 - (($ - device) and 0xff)

        txfd:
        .status         dw ?
        .command        dw ?
        .link           dd ?
        .tx_desc_addr   dd ?
        .count          dd ?
        .tx_buf_addr0   dd ?
        .tx_buf_size0   dd ?
        .tx_buf_addr1   dd ?
        .tx_buf_size1   dd ?

                        rb 0x100 - (($ - device) and 0xff)

        confcmd:
        .status:        dw ?
        .command:       dw ?
        .link:          dd ?
        .data           rb 64

                        rb 0x100 - (($ - device) and 0xff)

        lstats:
        tx_good_frames          dd ?
        tx_coll16_errs          dd ?
        tx_late_colls           dd ?
        tx_underruns            dd ?
        tx_lost_carrier         dd ?
        tx_deferred             dd ?
        tx_one_colls            dd ?
        tx_multi_colls          dd ?
        tx_total_colls          dd ?

        rx_good_frames          dd ?
        rx_crc_errs             dd ?
        rx_align_errs           dd ?
        rx_resource_errs        dd ?
        rx_overrun_errs         dd ?
        rx_colls_errs           dd ?
        rx_runt_errs            dd ?

        sizeof.device_struct = $ - device

end virtual


; Serial EEPROM

EE_SK           =   1 shl 0   ; serial clock
EE_CS           =   1 shl 1   ; chip select
EE_DI           =   1 shl 2   ; data in
EE_DO           =   1 shl 3   ; data out

EE_READ         =   110b
EE_WRITE        =   101b
EE_ERASE        =   111b

; The SCB accepts the following controls for the Tx and Rx units:

CU_START        =   0x0010
CU_RESUME       =   0x0020
CU_STATSADDR    =   0x0040
CU_SHOWSTATS    =   0x0050   ; Dump statistics counters.
CU_CMD_BASE     =   0x0060   ; Base address to add to add CU commands.
CU_DUMPSTATS    =   0x0070   ; Dump then reset stats counters.

RX_START        =   0x0001
RX_RESUME       =   0x0002
RX_ABORT        =   0x0004
RX_ADDR_LOAD    =   0x0006
RX_RESUMENR     =   0x0007
INT_MASK        =   0x0100
DRVR_INT        =   0x0200   ; Driver generated interrupt

CmdIASetup      =   0x0001
CmdConfigure    =   0x0002
CmdTx           =   0x0004 ;;;;
CmdTxFlex       =   0x0008 ;;;
Cmdsuspend      =   0x4000


reg_scb_status  =   0
reg_scb_cmd     =   2
reg_scb_ptr     =   4
reg_port        =   8
reg_eeprom_ctrl =   12
reg_eeprom      =   14
reg_mdi_ctrl    =   16


macro delay {
        push    eax
        in      eax, dx
        in      eax, dx
        in      eax, dx
        in      eax, dx
        in      eax, dx
        in      eax, dx
        in      eax, dx
        in      eax, dx
        in      eax, dx
        in      eax, dx
        pop     eax
}

section '.flat' code readable align 16

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                        ;;
;; proc START             ;;
;;                        ;;
;; (standard driver proc) ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

proc START stdcall, state:dword

        cmp [state], 1
        jne .exit

  .entry:

        DEBUGF 1,"Loading %s driver\n", my_service
        stdcall RegService, my_service, service_proc
        ret

  .fail:
  .exit:
        xor eax, eax
        ret

endp


;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                        ;;
;; proc SERVICE_PROC      ;;
;;                        ;;
;; (standard driver proc) ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align 4
proc service_proc stdcall, ioctl:dword

        mov     edx, [ioctl]
        mov     eax, [IOCTL.io_code]

;------------------------------------------------------

        cmp     eax, 0 ;SRV_GETVERSION
        jne     @F

        cmp     [IOCTL.out_size], 4
        jl      .fail
        mov     eax, [IOCTL.output]
        mov     [eax], dword API_VERSION

        xor     eax, eax
        ret

;------------------------------------------------------
  @@:
        cmp     eax, 1 ;SRV_HOOK
        jne     .fail

        cmp     [IOCTL.inp_size], 3               ; Data input must be at least 3 bytes
        jl      .fail

        mov     eax, [IOCTL.input]
        cmp     byte [eax], 1                           ; 1 means device number and bus number (pci) are given
        jne     .fail                                   ; other types arent supported for this card yet

; check if the device is already listed

        mov     esi, device_list
        mov     ecx, [devices]
        test    ecx, ecx
        jz      .firstdevice

;        mov     eax, [IOCTL.input]                      ; get the pci bus and device numbers
        mov     ax , [eax+1]                            ;
  .nextdevice:
        mov     ebx, [esi]
        cmp     ax , word [device.pci_bus]              ; compare with pci and device num in device list (notice the usage of word instead of byte)
        je      .find_devicenum                         ; Device is already loaded, let's find it's device number
        add     esi, 4
        loop    .nextdevice


; This device doesnt have its own eth_device structure yet, lets create one
  .firstdevice:
        cmp     [devices], MAX_DEVICES                  ; First check if the driver can handle one more card
        jae     .fail

        allocate_and_clear ebx, sizeof.device_struct, .fail      ; Allocate the buffer for device structure

; Fill in the direct call addresses into the struct

        mov     [device.reset], reset
        mov     [device.transmit], transmit
        mov     [device.get_MAC], read_mac
        mov     [device.set_MAC], MAC_write
        mov     [device.unload], unload
        mov     [device.name], my_service

; save the pci bus and device numbers

        mov     eax, [IOCTL.input]
        mov     cl, [eax+1]
        mov     [device.pci_bus], cl
        mov     cl, [eax+2]
        mov     [device.pci_dev], cl

; Now, it's time to find the base io addres of the PCI device

        find_io [device.pci_bus], [device.pci_dev], [device.io_addr]

; We've found the io address, find IRQ now

        find_irq [device.pci_bus], [device.pci_dev], [device.irq_line]

        DEBUGF  2,"Hooking into device, dev:%x, bus:%x, irq:%x, addr:%x\n",\
        [device.pci_dev]:1,[device.pci_bus]:1,[device.irq_line]:1,[device.io_addr]:4

        allocate_and_clear [device.rx_buffer], (4096), .err
        allocate_and_clear [device.tx_buffer], (4096), .err

; Ok, the eth_device structure is ready, let's probe the device

        call    probe                                                   ; this function will output in eax
        test    eax, eax
        jnz     .err                                                    ; If an error occured, exit

        mov     eax, [devices]                                          ; Add the device structure to our device list
        mov     [device_list+4*eax], ebx                                ; (IRQ handler uses this list to find device)
        inc     [devices]                                               ;


        mov     [device.type], NET_TYPE_ETH
        call    NetRegDev

        cmp     eax, -1
        je      .err

        ret

; If the device was already loaded, find the device number and return it in eax

  .find_devicenum:
        DEBUGF  2,"Trying to find device number of already registered device\n"
        call    NetPtrToNum                                             ; This kernel procedure converts a pointer to device struct in ebx
                                                                        ; into a device number in edi
        mov     eax, edi                                                ; Application wants it in eax instead
        DEBUGF  2,"Kernel says: %u\n", eax
        ret

; If an error occured, remove all allocated data and exit (returning -1 in eax)

  .err:
        stdcall KernelFree, [device.rx_buffer]
        stdcall KernelFree, [device.tx_buffer]
        stdcall KernelFree, ebx

  .fail:
        or      eax, -1
        ret

;------------------------------------------------------
endp





;;/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\;;
;;                                                                        ;;
;;        Actual Hardware dependent code starts here                      ;;
;;                                                                        ;;
;;/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\;;


unload:
        ; TODO: (in this particular order)
        ;
        ; - Stop the device
        ; - Detach int handler
        ; - Remove device from local list (device_list)
        ; - call unregister function in kernel
        ; - Remove all allocated structures and buffers the card used

        or      eax,-1

ret


;-------------
;
; Probe
;
;-------------

align 4
probe:

        DEBUGF  1,"Probing i8255x\n"

        make_bus_master [device.pci_bus], [device.pci_dev]

;---------------------------
; First, identify the device

        movzx   ecx, [device.pci_bus]
        movzx   edx, [device.pci_dev]
        stdcall PciRead32, ecx ,edx ,0                                ; get device/vendor id

        DEBUGF  1,"Vendor_id=0x%x\n", ax

        cmp     ax, 0x8086
        jne     .notfound
        shr     eax, 16

        DEBUGF  1,"Device_id=0x%x\n", ax

        mov     ecx, DEVICE_IDs
        mov     edi, device_id_list
        repne   scasw
        jne     .notfound
        jmp     .found

  .notfound:
        DEBUGF  1,"ERROR: Unsupported device!\n"
        or      eax, -1
        ret

  .found:

        call    ee_get_width
        call    MAC_read_eeprom

        ;;; TODO: detect phy



;----------
;
;  Reset
;
;----------

align 4
reset:

;---------------
; reset the card

        set_io  0
        set_io  reg_port
        xor     eax, eax        ; Software Reset
        out     dx, eax

        mov     esi, 10
        call    Sleep           ; Give the card time to warm up.

;---------------------------------
; Tell device where to store stats

        lea     eax, [lstats]
        GetRealAddr
        set_io  reg_scb_ptr
        out     dx, eax

        mov     ax, INT_MASK + CU_STATSADDR
        set_io  reg_scb_cmd
        out     dx, ax
        call    cmd_wait

;-----------------
; Set CU base to 0

        xor     eax, eax
        set_io  reg_scb_ptr
        out     dx, eax

        mov     ax, INT_MASK + RX_ADDR_LOAD
        set_io  reg_scb_cmd
        out     dx, ax
        call    cmd_wait

;---------------------
; build rxfd structure

        mov     ax, 0x0001
        mov     [rxfd.status], ax
        mov     ax, 0x0000
        mov     [rxfd.command], ax

        lea     eax, [rxfd.status]
        GetRealAddr
        mov     [rxfd.link], eax

        lea     eax, [device.rx_buffer]
        GetRealAddr
        mov     [rxfd.rx_buf_addr], eax

        xor     ax, ax
        mov     [rxfd.count], ax

        mov     ax, 1528
        mov     [rxfd.size], ax

;-------------------------------
; Set ptr to first command block

        set_io  reg_scb_ptr
        lea     eax, [rxfd]
        GetRealAddr
        out     dx, eax

        set_io  reg_scb_cmd
        mov     ax, INT_MASK + RX_START
        out     dx, ax
        call    cmd_wait

;-------------------
; start the receiver

        mov     [rxfd.status], 0
        mov     [rxfd.command], 0xc000

        set_io  reg_scb_ptr
        lea     eax, [rxfd]
        GetRealAddr
        out     dx, eax

        set_io  reg_scb_cmd
        mov     ax, INT_MASK + RX_START
        out     dx, ax
        call    cmd_wait

;-----------------
; set CU base to 0

        set_io  reg_scb_ptr
        xor     eax, eax
        out     dx, eax

        set_io  reg_scb_cmd
        mov     ax, INT_MASK + CU_CMD_BASE
        out     dx, ax
        call    cmd_wait

;--------------------
; Set TX Base address

; First, set up confcmd values

        mov     [txfd.command], CmdIASetup
        mov     [txfd.status], 0
        lea     eax, [confcmd]
        GetRealAddr
        mov     [txfd.link], eax

        mov     word [confcmd.command], Cmdsuspend + CmdConfigure
        mov     word [confcmd.status], 0
        lea     eax, [txfd]
        GetRealAddr
        mov     [confcmd.link], eax

        mov     byte [confcmd.data + 1], 0x88  ; fifo of 8 each
        mov     byte [confcmd.data + 4], 0
        mov     byte [confcmd.data + 5], 0x80
        mov     byte [confcmd.data + 15], 0x48
        mov     byte [confcmd.data + 19], 0x80
        mov     byte [confcmd.data + 21], 0x05


; CU start

;        lea     eax, [txfd]
;        GetRealAddr
        set_io  0
        set_io  reg_scb_ptr
        out     dx, eax

        mov     ax, INT_MASK + CU_START
        set_io  reg_scb_cmd
        out     dx, ax
        call    cmd_wait

; wait for thing to start

;  drp004:
;
;        cmp     [txfd.status], 0
;        jz      drp004

; Indicate that we have successfully reset the card


;;; enable interrupts

        xor     eax, eax

        ret





;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                         ;;
;; Transmit                                ;;
;;                                         ;;
;; In: buffer pointer in [esp+4]           ;;
;;     size of buffer in [esp+8]           ;;
;;     pointer to device structure in ebx  ;;
;;                                         ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align 4
transmit:

        DEBUGF  1,"Transmitting packet, buffer:%x, size:%u\n",[esp+4],[esp+8]
        mov     eax, [esp+4]
        DEBUGF  1,"To: %x-%x-%x-%x-%x-%x From: %x-%x-%x-%x-%x-%x Type:%x%x\n",\
        [eax+00]:2,[eax+01]:2,[eax+02]:2,[eax+03]:2,[eax+04]:2,[eax+05]:2,\
        [eax+06]:2,[eax+07]:2,[eax+08]:2,[eax+09]:2,[eax+10]:2,[eax+11]:2,\
        [eax+13]:2,[eax+12]:2

        cmp     dword [esp+8], 1500
        jg      .error                          ; packet is too long
        cmp     dword [esp+8], 60
        jl      .error                          ; packet is too short

        set_io  0
        in      ax, dx
        and     ax, 0xfc00
        out     dx, ax

        mov     [txfd.status], 0
        mov     [txfd.command], Cmdsuspend + CmdTx + CmdTxFlex
        lea     eax, [txfd]
        GetRealAddr
        mov     [txfd.link], eax
        mov     [txfd.count], 0x02208000
        lea     eax, [txfd.tx_buf_addr0]
        GetRealAddr
        mov     [txfd.tx_desc_addr], eax

        mov     eax, [esp+4]
        mov     [txfd.tx_buf_addr0], eax
        mov     eax, [esp+8]
        mov     [txfd.tx_buf_size0], eax

        ; Copy the buffer address and size in
        mov     [txfd.tx_buf_addr1], 0
        mov     [txfd.tx_buf_size1], 0

        lea     eax, [txfd]
        GetRealAddr
        set_io  reg_scb_ptr
        out     dx, eax

        mov     ax, INT_MASK + CU_START
        set_io  reg_scb_cmd
        out     dx, ax

        call    cmd_wait

        in      ax, dx

  .I8t_001:
        cmp     [txfd.status], 0
        je      .I8t_001

        in      ax, dx

  .finish:
        xor     eax, eax
        ret     8

  .error:
        stdcall KernelFree, [esp+4]
        or      eax, -1
        ret     8

;;;;;;;;;;;;;;;;;;;;;;;
;;                   ;;
;; Interrupt handler ;;
;;                   ;;
;;;;;;;;;;;;;;;;;;;;;;;

align 4
int_handler:

        DEBUGF  1,"\n%s int\n", my_service

; find pointer of device wich made IRQ occur

        mov     ecx, [devices]
        test    ecx, ecx
        jz      .nothing
        mov     esi, device_list
  .nextdevice:
        mov     ebx, [esi]

        set_io  0
        set_io  reg_scb_status
        in      ax, dx
        out     dx, ax                              ; send it back to ACK
        test    ax, ax
        jnz     .got_it
  .continue:
        add     esi, 4
        dec     ecx
        jnz     .nextdevice
  .nothing:
        ret                                         ; If no device was found, abort (The irq was probably for a device, not registered to this driver)

  .got_it:

        DEBUGF  1,"Device: %x Status: %x ", ebx, ax

       ;;; receive

        cmp     [rxfd.status], 0
        je      .nodata

        mov     [rxfd.status], 0
        mov     [rxfd.command], 0xc000

        set_io  reg_scb_ptr
        lea     eax, [rxfd.status]
        GetRealAddr
        out     dx, eax

        set_io  reg_scb_cmd
        mov     ax, INT_MASK + RX_START
        out     dx, ax

        call    cmd_wait

        movzx   ecx, [rxfd.count]
        and     ecx, 0x3fff

        stdcall KernelAlloc, ecx        ; Allocate a buffer to put packet into
        push    ecx
        push    eax

        lea     esi, [device.rx_buffer]

  .copy:
        shr     ecx, 1
        jnc     .nb
        movsb
  .nb:
        shr     ecx, 1
        jnc     .nw
        movsw
  .nw:
        jz      .nd
        rep     movsd
  .nd:

        jmp     Eth_input

  .nodata:
  .fail:

        ret




align 4
cmd_wait:

        in      al, dx
        test    al, al
        jnz     cmd_wait

        ret






align 4
ee_read:        ; esi = address to read

        set_io  0
        set_io  reg_eeprom

;-----------------------------------------------------
; Prepend start bit + read opcode to the address field
; and shift it to the very left bits of esi

        mov     ecx, 32
        sub     ecx, [device.ee_bus_width]
        shl     esi, cl
        or      esi, EE_READ shl 28

        mov     ecx, [device.ee_bus_width]
        add     ecx, 3

;-----------------------
; Write this to the chip

  .loop:
        mov     eax, EE_CS
        shl     esi, 1
        jnc     @f
        or      eax, EE_DI
       @@:
        out     dx , eax
        delay

        or      eax, EE_SK
        out     dx , eax
        delay

        loop    .loop

;------------------------------
; Now read the data from eeprom

        xor     esi, esi
        mov     ecx, 16

  .loop2:
        mov     eax, EE_CS + EE_SK
        out     dx , eax
        delay

        in      eax, dx
        test    eax, EE_DO
        jz      @f
        inc     esi
       @@:
        shl     esi, 1

        mov     eax, EE_CS
        out     dx , eax
        delay

        loop    .loop2

;-----------------------
; de-activate the eeprom

        xor     eax, eax
        out     dx, eax


        DEBUGF  1,"data=%x\n", esi
        ret



align 4
ee_write:       ; esi = address to write to, di = data

        set_io  0
        set_io  reg_eeprom

;-----------------------------------------------------
; Prepend start bit + write opcode to the address field
; and shift it to the very left bits of esi

        mov     ecx, 32
        sub     ecx, [device.ee_bus_width]
        shl     esi, cl
        or      esi, EE_WRITE shl 28

        mov     ecx, [device.ee_bus_width]
        add     ecx, 3

;-----------------------
; Write this to the chip

  .loop:
        mov     eax, EE_CS
        shl     esi, 1
        jnc     @f
        or      eax, EE_DI
       @@:
        out     dx , eax
        delay

        or      eax, EE_SK
        out     dx , eax
        delay

        loop    .loop

;-----------------------------
; Now write the data to eeprom

        mov     ecx, 16

  .loop2:
        mov     eax, EE_CS
        shl     di , 1
        jnc     @f
        or      eax, EE_DI
       @@:
        out     dx , eax
        delay

        or      eax, EE_SK
        out     dx , eax
        delay

        loop    .loop2

;-----------------------
; de-activate the eeprom

        xor     eax, eax
        out     dx, eax


        ret



align 4
ee_get_width:

        set_io  0
        set_io  reg_eeprom

        mov     si, EE_READ shl 12
        xor     ecx, ecx
  .loop:
        mov     ax, EE_CS
        out     dx, ax
        delay

        or      ax, EE_SK
        out     dx, ax
        delay

        inc     ecx

        in      ax, dx
        test    ax, EE_DO
        jnz     .loop

        mov     [device.ee_bus_width], ecx
        DEBUGF  1,"ee width=%u\n", ecx


;-----------------------
; de-activate the eeprom

        xor     eax, eax
        out     dx, eax

        ret



; cx = phy addr
; dx = phy reg addr

; ax = data

align 4
mdio_read:

        shl     ecx, 21                 ; PHY addr
        shl     edx, 16                 ; PHY reg addr

        mov     eax, ecx
        or      eax, edx
        or      eax, 10b shl 26         ; read opcode

        set_io  0
        set_io  reg_mdi_ctrl
        out     dx, eax

  .wait:
        delay
        in      eax, dx
        test    eax, 1 shl 28           ; ready bit
        jz      .wait

        ret

; ax = data
; cx = phy addr
; dx = phy reg addr

; ax = data

align 4
mdio_write:

        and     eax, 0xffff

        shl     ecx, 21                 ; PHY addr
        shl     edx, 16                 ; PHY reg addr

        or      eax, ecx
        or      eax, edx
        or      eax, 01b shl 26         ; write opcode

        set_io  0
        set_io  reg_mdi_ctrl
        out     dx, eax

  .wait:
        delay
        in      eax, dx
        test    eax, 1 shl 28           ; ready bit
        jz      .wait

        ret

read_mac:

        ret



align 4
MAC_read_eeprom:

        mov     esi, 0
        call    ee_read

        mov     esi, 1
        call    ee_read

        mov     esi, 14
        call    ee_read

        mov     esi, 5
        call    ee_read


        ret


align 4
MAC_write:

;;;;

        ret




; End of code

align 4                                         ; Place all initialised data here

devices       dd 0                              ; number of currently running devices
version       dd (DRIVER_VERSION shl 16) or (API_VERSION and 0xFFFF)
my_service    db 'i8255x',0                     ; max 16 chars include zero
devicename    db 'Intel Etherexpress pro/100',0


device_id_list:

        dw 0x1029
        dw 0x1030
        dw 0x1031
        dw 0x1032
        dw 0x1033
        dw 0x1034
        dw 0x1038
        dw 0x1039
        dw 0x103A
        dw 0x103B
        dw 0x103C
        dw 0x103D
        dw 0x103E
        dw 0x1050
        dw 0x1051
        dw 0x1052
        dw 0x1053
        dw 0x1054
        dw 0x1055
        dw 0x1056
        dw 0x1057
        dw 0x1059
        dw 0x1064
        dw 0x1065
        dw 0x1066
        dw 0x1067
        dw 0x1068
        dw 0x1069
        dw 0x106A
        dw 0x106B
        dw 0x1091
        dw 0x1092
        dw 0x1093
        dw 0x1094
        dw 0x1095
        dw 0x10fe
        dw 0x1209
        dw 0x1229
        dw 0x2449
        dw 0x2459
        dw 0x245D
        dw 0x27DC

DEVICE_IDs = ($ - device_id_list) / 2

mac_82557_D100_A  = 0
mac_82557_D100_B  = 1
mac_82557_D100_C  = 2
mac_82558_D101_A4 = 4
mac_82558_D101_B0 = 5
mac_82559_D101M   = 8
mac_82559_D101S   = 9
mac_82550_D102    = 12
mac_82550_D102_C  = 13
mac_82551_E       = 14
mac_82551_F       = 15
mac_82551_10      = 16
mac_unknown       = 0xFF

phy_100a     = 0x000003E0
phy_100c     = 0x035002A8
phy_82555_tx = 0x015002A8
phy_nsc_tx   = 0x5C002000
phy_82562_et = 0x033002A8
phy_82562_em = 0x032002A8
phy_82562_ek = 0x031002A8
phy_82562_eh = 0x017002A8
phy_82552_v  = 0xd061004d
phy_unknown  = 0xFFFFFFFF


include_debug_strings                           ; All data wich FDO uses will be included here

section '.data' data readable writable align 16 ; place all uninitialized data place here

device_list   rd MAX_DEVICES                    ; This list contains all pointers to device structures the driver is handling


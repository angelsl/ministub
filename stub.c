/* SPDX-License-Identifier: LGPL-2.1+ */
/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * systemd stub.c:
 * systemd linux.c:
 * systemd disk.c:
 * Copyright (C) 2015 Kay Sievers <kay@vrfy.org>
 *
 * systemd util.c:
 * Copyright (C) 2012-2013 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2012 Harald Hoyer <harald@redhat.com>
 *
 * systemd graphics.c:
 * Copyright (C) 2012-2013 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2012 Harald Hoyer <harald@redhat.com>
 * Copyright (C) 2013 Intel Corporation
 *   Authored by Joonas Lahtinen <joonas.lahtinen@linux.intel.cDOom>
 *
 */

#include <Uefi.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <Guid/GlobalVariable.h>

#include "ed25519/ed25519.h"

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define DEBUG_PLN() Print(L"Error at " STRINGIZE(__LINE__) L"\n")

extern __attribute__((aligned(16))) unsigned char pubkey;
extern unsigned char pubkey_end;

static const EFI_GUID loader_guid = {0x4a67b082, 0x0a4c, 0x41cf, {0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f}};

#define SETUP_MAGIC 0x53726448 /* "HdrS" */
struct SetupHeader {
    UINT8 boot_sector[0x01f1];
    UINT8 setup_secs;
    UINT16 root_flags;
    UINT32 sys_size;
    UINT16 ram_size;
    UINT16 video_mode;
    UINT16 root_dev;
    UINT16 signature;
    UINT16 jump;
    UINT32 header;
    UINT16 version;
    UINT16 su_switch;
    UINT16 setup_seg;
    UINT16 start_sys;
    UINT16 kernel_ver;
    UINT8 loader_id;
    UINT8 load_flags;
    UINT16 movesize;
    UINT32 code32_start;
    UINT32 ramdisk_start;
    UINT32 ramdisk_len;
    UINT32 bootsect_kludge;
    UINT16 heap_end;
    UINT8 ext_loader_ver;
    UINT8 ext_loader_type;
    UINT32 cmd_line_ptr;
    UINT32 ramdisk_max;
    UINT32 kernel_alignment;
    UINT8 relocatable_kernel;
    UINT8 min_alignment;
    UINT16 xloadflags;
    UINT32 cmdline_size;
    UINT32 hardware_subarch;
    UINT64 hardware_subarch_data;
    UINT32 payload_offset;
    UINT32 payload_length;
    UINT64 setup_data;
    UINT64 pref_address;
    UINT32 init_size;
    UINT32 handover_offset;
} __attribute__((packed));

#ifdef __x86_64__
typedef VOID (*handover_f)(VOID *image, EFI_SYSTEM_TABLE *table, struct SetupHeader *setup);
static inline VOID linux_efi_handover(EFI_HANDLE image, struct SetupHeader *setup) {
    handover_f handover;

    asm volatile("cli");
    handover = (handover_f)((UINTN)setup->code32_start + 512 + setup->handover_offset);
    handover(image, gST, setup);
}
#else
typedef VOID (*handover_f)(VOID *image, EFI_SYSTEM_TABLE *table, struct SetupHeader *setup) __attribute__((regparm(0)));
static inline VOID linux_efi_handover(EFI_HANDLE image, struct SetupHeader *setup) {
    handover_f handover;

    handover = (handover_f)((UINTN)setup->code32_start + setup->handover_offset);
    handover(image, gST, setup);
}
#endif

static EFI_STATUS linux_exec(EFI_HANDLE *image, CHAR8 *cmdline, UINTN cmdline_len, UINTN linux_addr, UINTN initrd_addr,
                             UINTN initrd_size, BOOLEAN secure) {
    struct SetupHeader *image_setup;
    struct SetupHeader *boot_setup;
    EFI_PHYSICAL_ADDRESS addr;
    EFI_STATUS err;

    image_setup = (struct SetupHeader *)(linux_addr);
    if (image_setup->signature != 0xAA55 || image_setup->header != SETUP_MAGIC)
        return EFI_LOAD_ERROR;

    if (image_setup->version < 0x20b || !image_setup->relocatable_kernel)
        return EFI_LOAD_ERROR;

    addr = 0x3fffffff;
    err = gBS->AllocatePages(AllocateMaxAddress, EfiLoaderData, EFI_SIZE_TO_PAGES(0x4000), &addr);
    if (EFI_ERROR(err))
        return err;
    boot_setup = (struct SetupHeader *)(UINTN)addr;
    gBS->SetMem(boot_setup, 0x4000, 0);
    gBS->CopyMem(boot_setup, image_setup, sizeof(struct SetupHeader));
    boot_setup->loader_id = 0xff;

    if (secure) {
        /* set secure boot flag in linux kernel zero page, see
           - Documentation/x86/zero-page.txt
           - arch/x86/include/uapi/asm/bootparam.h
           - drivers/firmware/efi/libstub/secureboot.c
           in the linux kernel source tree
           Possible values: 0 (unassigned), 1 (undetected), 2 (disabled), 3
           (enabled)
        */
        boot_setup->boot_sector[0x1ec] = 3;
    }

    boot_setup->code32_start = (UINT32)linux_addr + (image_setup->setup_secs + 1) * 512;

    if (cmdline) {
        addr = 0xA0000;
        err = gBS->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                EFI_SIZE_TO_PAGES(cmdline_len + 1), &addr);
        if (EFI_ERROR(err))
            return err;
        gBS->CopyMem((VOID *)(UINTN)addr, cmdline, cmdline_len);
        ((CHAR8 *)addr)[cmdline_len] = 0;
        boot_setup->cmd_line_ptr = (UINT32)addr;
    }

    boot_setup->ramdisk_start = (UINT32)initrd_addr;
    boot_setup->ramdisk_len = (UINT32)initrd_size;

    linux_efi_handover(image, boot_setup);
    return EFI_LOAD_ERROR;
}

static EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, CHAR16 *name, CHAR8 *buf, UINTN size, BOOLEAN persistent) {
    UINT32 flags;

    flags = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    if (persistent)
        flags |= EFI_VARIABLE_NON_VOLATILE;

    return gRT->SetVariable(name, (EFI_GUID *)vendor, flags, size, buf);
}

static EFI_STATUS efivar_set(CHAR16 *name, CHAR16 *value, BOOLEAN persistent) {
    return efivar_set_raw(&loader_guid, name, (CHAR8 *)value, value ? (StrLen(value) + 1) * sizeof(CHAR16) : 0,
                          persistent);
}

static EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, CHAR16 *name, CHAR8 **buffer, UINTN *size) {
    CHAR8 *buf;
    UINTN l;
    EFI_STATUS err;

    l = sizeof(CHAR16 *) * 1024;
    err = gBS->AllocatePool(EfiLoaderData, l, (VOID **) &buf);
    if (EFI_ERROR(err)) {
        return err;
    }
    if (!buf)
        return EFI_OUT_OF_RESOURCES;

    err = gRT->GetVariable(name, (EFI_GUID *)vendor, NULL, &l, buf);
    if (!EFI_ERROR(err)) {
        *buffer = buf;
        if (size)
            *size = l;
    } else
        gBS->FreePool(buf);
    return err;
}

static EFI_STATUS graphics_mode(BOOLEAN on) {
#define EFI_CONSOLE_CONTROL_PROTOCOL_GUID {0xf42f7782, 0x12e, 0x4c12, {0x99, 0x56, 0x49, 0xf9, 0x43, 0x4, 0xf7, 0x21}}
    struct _EFI_CONSOLE_CONTROL_PROTOCOL;

    typedef enum {
        EfiConsoleControlScreenText,
        EfiConsoleControlScreenGraphics,
        EfiConsoleControlScreenMaxValue,
    } EFI_CONSOLE_CONTROL_SCREEN_MODE;

    typedef EFI_STATUS(EFIAPI * EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE)(struct _EFI_CONSOLE_CONTROL_PROTOCOL * This,
                                                                       EFI_CONSOLE_CONTROL_SCREEN_MODE * Mode,
                                                                       BOOLEAN * UgaExists, BOOLEAN * StdInLocked);

    typedef EFI_STATUS(EFIAPI * EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE)(struct _EFI_CONSOLE_CONTROL_PROTOCOL * This,
                                                                       EFI_CONSOLE_CONTROL_SCREEN_MODE Mode);

    typedef EFI_STATUS(EFIAPI * EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STD_IN)(struct _EFI_CONSOLE_CONTROL_PROTOCOL * This,
                                                                          CHAR16 * Password);

    typedef struct _EFI_CONSOLE_CONTROL_PROTOCOL {
        EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE GetMode;
        EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE SetMode;
        EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STD_IN LockStdIn;
    } EFI_CONSOLE_CONTROL_PROTOCOL;

    EFI_GUID ConsoleControlProtocolGuid = EFI_CONSOLE_CONTROL_PROTOCOL_GUID;
    EFI_CONSOLE_CONTROL_PROTOCOL *ConsoleControl = NULL;
    EFI_CONSOLE_CONTROL_SCREEN_MODE new;
    EFI_CONSOLE_CONTROL_SCREEN_MODE current;
    BOOLEAN uga_exists;
    BOOLEAN stdin_locked;
    EFI_STATUS err;

    err = gBS->LocateProtocol(&ConsoleControlProtocolGuid, NULL, (VOID **)&ConsoleControl);
    if (EFI_ERROR(err))
        /* console control protocol is nonstandard and might not exist. */
        return err == EFI_NOT_FOUND ? EFI_SUCCESS : err;

    /* check current mode */
    err = ConsoleControl->GetMode(ConsoleControl, &current, &uga_exists, &stdin_locked);
    if (EFI_ERROR(err))
        return err;

    /* do not touch the mode */
    new = on ? EfiConsoleControlScreenGraphics : EfiConsoleControlScreenText;
    if (new == current)
        return EFI_SUCCESS;

    err = ConsoleControl->SetMode(ConsoleControl, new);

    /* some firmware enables the cursor when switching modes */
    gST->ConOut->EnableCursor(gST->ConOut, FALSE);

    return err;
}

static EFI_STATUS disk_get_part_uuid(EFI_HANDLE *handle, CHAR16 uuid[37]) {
    EFI_DEVICE_PATH *device_path;
    EFI_STATUS r = EFI_NOT_FOUND;

    /* export the device path this image is started from */
    device_path = DevicePathFromHandle(handle);
    if (device_path) {
        EFI_DEVICE_PATH *path = device_path;

        for (; !IsDevicePathEnd(path); path = NextDevicePathNode(path)) {
            HARDDRIVE_DEVICE_PATH *drive;

            if (DevicePathType(path) != MEDIA_DEVICE_PATH)
                continue;
            if (DevicePathSubType(path) != MEDIA_HARDDRIVE_DP)
                continue;
            drive = (HARDDRIVE_DEVICE_PATH *)path;
            if (drive->SignatureType != SIGNATURE_TYPE_GUID)
                continue;

            UnicodeSPrint(uuid, 37, L"%g", (EFI_GUID *)&drive->Signature);
            r = EFI_SUCCESS;
            break;
        }
    }

    return r;
}

static VOID path_normalise(IN OUT CHAR16 *path) {
    UINTN src = 0, dst = 0;

    if (!path || !path[0]) {
        return;
    }

    while (path[src]) {
        if ((path[src] == L'/') || (path[src] == L'\\')) {
            if (dst == 0) {
                src++;
            } else {
                path[dst++] = L'\\';
                do {
                    src++;
                } while ((path[src] == L'/') || (path[src] == L'\\'));
            }
        } else {
            path[dst++] = path[src++];
        }
    }

    if ((dst > 0) && (path[dst - 1] == L'\\')) {
        dst--;
    }

    path[dst] = L'\0';

    if (path[0] == L'\0') {
        path[0] = L'\\';
        path[1] = L'\0';
    }
}

static VOID path_basename(IN OUT CHAR16 *path) {
    INTN last_slash_plus_1 = -1;
    UINTN cur = 0;

    if (!path || !path[0]) {
        return;
    }

    CHAR16 cur_char;
    while ((cur_char = path[cur++])) {
        if (cur_char == L'\\' || cur_char == L'/') {
            last_slash_plus_1 = cur;
        }
    }

    if (last_slash_plus_1 > -1) {
        path[last_slash_plus_1] = L'\0';
    }
}

static EFI_STATUS open_current_dir(IN EFI_HANDLE image, IN EFI_LOADED_IMAGE *loaded_image, OUT EFI_FILE_PROTOCOL **cur_dir) {
    EFI_DEVICE_PATH_PROTOCOL *cur_path = loaded_image->FilePath;
    while (!IsDevicePathEndType(cur_path) && (DevicePathType(cur_path) != 4 || DevicePathSubType(cur_path) != 4)) {
        cur_path = NextDevicePathNode(cur_path);
    }
    if (IsDevicePathEndType(cur_path)) {
        DEBUG_PLN();
        return EFI_INVALID_PARAMETER;
    }

    EFI_STATUS err;

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *vol = NULL;
    err = gBS->OpenProtocol(loaded_image->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&vol, image, NULL,
                            EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        return err;
    }

    EFI_FILE_PROTOCOL *vol_root = NULL;
    err = vol->OpenVolume(vol, &vol_root);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        return err;
    }

    CHAR16 *file_path = ConvertDevicePathToText(cur_path, FALSE, FALSE);
    path_normalise(file_path);
    path_basename(file_path);

    err = vol_root->Open(vol_root, cur_dir, file_path, EFI_FILE_MODE_READ, 0);
    gBS->FreePool(file_path);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        return err;
    }

    return EFI_SUCCESS;
}

struct ReadImageResult {
    UINT64 vmlinuz_size;
    UINT64 initrd_size;
    UINT64 cmdline_size;
    unsigned char sig[64];
    void *vmlinuz;
    void *initrd;
    void *cmdline;
} __attribute__((packed));

static EFI_STATUS image_read(IN EFI_FILE_PROTOCOL *dir, IN CHAR16 *name, IN OUT struct ReadImageResult *out) {
    EFI_STATUS err;

    EFI_FILE_PROTOCOL *file = NULL;
    err = dir->Open(dir, &file, name, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        return err;
    }

    UINTN read_size = 3*sizeof(UINT64);
    err = file->Read(file, &read_size, out);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        return err;
    }
    if (read_size < 3*sizeof(UINT64)) {
        DEBUG_PLN();
        return EFI_END_OF_FILE;
    }

    EFI_PHYSICAL_ADDRESS vmlinuz_addr = 0x3fffffff;
    EFI_PHYSICAL_ADDRESS data_addr = 0x3fffffff;
    UINTN vmlinuz_pages = EFI_SIZE_TO_PAGES(out->vmlinuz_size);
    UINTN data_pages = EFI_SIZE_TO_PAGES(out->initrd_size + out->cmdline_size);

    err = gBS->AllocatePages(AllocateMaxAddress, EfiLoaderCode, vmlinuz_pages, &vmlinuz_addr);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        return err;
    }
    err = gBS->AllocatePages(AllocateMaxAddress, EfiLoaderData, data_pages, &data_addr);
    if (EFI_ERROR(err)) {
        gBS->FreePages(vmlinuz_addr, vmlinuz_pages);
        DEBUG_PLN();
        return err;
    }

    out->vmlinuz = (void *)(UINTN) vmlinuz_addr;
    out->initrd = (void *)(UINTN) data_addr;
    out->cmdline = (void *)(UINTN) (data_addr + out->initrd_size);

    read_size = out->vmlinuz_size;
    err = file->Read(file, &read_size, out->vmlinuz);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        goto fail;
    }
    if (read_size < out->vmlinuz_size) {
        DEBUG_PLN();
        err = EFI_END_OF_FILE;
        goto fail;
    }

    read_size = out->initrd_size + out->cmdline_size;
    err = file->Read(file, &read_size, out->initrd);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        goto fail;
    }
    if (read_size < out->initrd_size + out->cmdline_size) {
        DEBUG_PLN();
        err = EFI_END_OF_FILE;
        goto fail;
    }

    read_size = sizeof(out->sig);
    _Static_assert(sizeof(out->sig) == 64, "test");
    err = file->Read(file, &read_size, out->sig);
    if (EFI_ERROR(err)) {
        DEBUG_PLN();
        goto fail;
    }
    if (read_size < sizeof(out->sig)) {
        DEBUG_PLN();
        err = EFI_END_OF_FILE;
        goto fail;
    }

    file->Close(file);
    return EFI_SUCCESS;

fail:
    file->Close(file);
    gBS->FreePages(data_addr, data_pages);
    gBS->FreePages(vmlinuz_addr, vmlinuz_pages);
    return err;
}

EFI_STATUS EFIAPI efi_main(IN EFI_HANDLE image, IN EFI_SYSTEM_TABLE *sys_table) {
    EFI_LOADED_IMAGE *loaded_image;
    CHAR8 *b;
    UINTN size;
    BOOLEAN secure = FALSE;
    CHAR16 uuid[37];
    EFI_STATUS err;

    graphics_mode(FALSE);

    if (&pubkey_end - &pubkey < 32) {
        Print(L"Embedded Ed25519 public key is too short!\n");
        gBS->Stall(3 * 1000 * 1000);
        return EFI_INVALID_PARAMETER;
    }

    err = gBS->OpenProtocol(image, &gEfiLoadedImageProtocolGuid, (VOID **)&loaded_image, image, NULL,
                            EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(err)) {
        Print(L"Error getting a LoadedImageProtocol handle: %r\n", err);
        gBS->Stall(3 * 1000 * 1000);
        return err;
    }

    Print(L"(1) Checking Secure Boot status\n");

    if (efivar_get_raw(&gEfiGlobalVariableGuid, L"SecureBoot", &b, &size) == EFI_SUCCESS) {
        if (*b > 0) {
            secure = TRUE;
        }
        gBS->FreePool(b);
    }

    if (secure) {
        Print(L"    Secure boot is enabled\n");
    } else {
        Print(L"    *** Secure boot is DISABLED ***\n"
              L"    Be careful when entering any credentials.\n");
        gBS->Stall(3 * 1000 * 1000);
    }

    Print(L"(2) Loading combined image\n");
    EFI_FILE_PROTOCOL *cur_dir;
    err = open_current_dir(image, loaded_image, &cur_dir);
    if (EFI_ERROR(err)) {
        Print(L"Error opening current directory: %r\n", err);
        gBS->Stall(3 * 1000 * 1000);
        return err;
    }

    struct ReadImageResult imgres = {0};
    err = image_read(cur_dir, L"combined.img", &imgres);
    if (EFI_ERROR(err)) {
        Print(L"Error loading combined image: %r\n", err);
        gBS->Stall(3 * 1000 * 1000);
        return err;
    }

    Print(L"(3) Verifying image\n");
    verify_context ctx = {0};

    ed25519_verify_init(&ctx, imgres.sig, &pubkey);
    ed25519_verify_update(&ctx, (unsigned char *) &imgres, 3*sizeof(UINT64));
    ed25519_verify_update(&ctx, imgres.vmlinuz, imgres.vmlinuz_size);
    ed25519_verify_update(&ctx, imgres.initrd, imgres.initrd_size);
    ed25519_verify_update(&ctx, imgres.cmdline, imgres.cmdline_size);
    if (!ed25519_verify_final(&ctx)) {
        Print(L"Invalid signature!\n");
        while (TRUE) {
            gBS->Stall(3 * 1000 * 1000);
        }
    }

    Print(L"(4) Setting EFI variables\n");

    /* export the device path this image is started from */
    if (disk_get_part_uuid(loaded_image->DeviceHandle, uuid) == EFI_SUCCESS)
        efivar_set(L"LoaderDevicePartUUID", uuid, FALSE);

    /* if LoaderImageIdentifier is not set, assume the image with this stub was
     * loaded directly from UEFI */
    if (efivar_get_raw(&gEfiGlobalVariableGuid, L"LoaderImageIdentifier", &b, &size) != EFI_SUCCESS) {
        CHAR16 *loaded_image_path = ConvertDevicePathToText(loaded_image->FilePath, FALSE, FALSE);
        efivar_set(L"LoaderImageIdentifier", loaded_image_path, FALSE);
        gBS->FreePool(loaded_image_path);
    }

    /* if LoaderFirmwareInfo is not set, let's set it */
    if (efivar_get_raw(&gEfiGlobalVariableGuid, L"LoaderFirmwareInfo", &b, &size) != EFI_SUCCESS) {
        CHAR16 *loader_firmware_info =
            CatSPrint(NULL, L"%s %d.%02d", gST->FirmwareVendor, gST->FirmwareRevision >> 16, gST->FirmwareRevision & 0xffff);
        efivar_set(L"LoaderFirmwareInfo", loader_firmware_info, FALSE);
        gBS->FreePool(loader_firmware_info);
    }

    /* ditto for LoaderFirmwareType */
    if (efivar_get_raw(&gEfiGlobalVariableGuid, L"LoaderFirmwareType", &b, &size) != EFI_SUCCESS) {
        CHAR16 *loader_firmware_type = CatSPrint(NULL, L"UEFI %d.%02d", gST->Hdr.Revision >> 16, gST->Hdr.Revision & 0xffff);
        efivar_set(L"LoaderFirmwareType", loader_firmware_type, FALSE);
        gBS->FreePool(loader_firmware_type);
    }

    /* add StubInfo */
    if (efivar_get_raw(&gEfiGlobalVariableGuid, L"StubInfo", &b, &size) != EFI_SUCCESS)
        efivar_set(L"StubInfo", L"ministub", FALSE);

    //Print(L"", vmlinuz_sha512);
    Print(L"(5) Executing Linux\n");

    err = linux_exec(image, imgres.cmdline, imgres.cmdline_size, (UINTN)imgres.vmlinuz, (UINTN)imgres.initrd,
                     imgres.initrd_size, secure);

    Print(L"Execution of embedded linux image failed: %r\n", err);

    while (TRUE) {
        gBS->Stall(3 * 1000 * 1000);
    }
}

ARCH			=	x86_64

CMDLINE			?=	/dev/null
IMAGE			?=	vmlinuz-linux
INITRAMFS		?=	initramfs.img

OBJS			=	stub.o binaries.o
TARGET			=	ministub.efi

EFIINC			=	/usr/include/efi
LIB				=	/usr/lib

ASFLAGS			=	-DCMDLINE="\"$(CMDLINE)\"" -DIMAGE="\"$(IMAGE)\"" -DINITRAMFS="\"$(INITRAMFS)\""
CFLAGS			=	-I$(EFIINC) -I$(EFIINC)/$(ARCH) -I$(EFIINC)/protocol \
					-std=gnu11 \
					-ffreestanding -fno-stack-protector -fpic -fshort-wchar \
					-mno-sse -mno-mmx \
					-Wall -Wextra -O2

ifeq ($(ARCH),x86_64)
	CFLAGS += -mno-red-zone -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI
endif

LDFLAGS			=	-nostdlib -znocombreloc -shared \
					-T $(LIB)/elf_$(ARCH)_efi.lds \
					-Bsymbolic -L $(LIB) \
					$(LIB)/crt0-efi-$(ARCH).o

all: $(TARGET)

binaries.o: binaries.S $(CMDLINE) $(IMAGE) $(INITRAMFS)

ministub.so: $(OBJS)
	ld $(LDFLAGS) $(OBJS) -o $@ -lefi -lgnuefi

%.efi: %.so
	objcopy -j .text -j .sdata -j .data -j .dynamic \
		-j .dynsym  -j .rel -j .rela -j .reloc \
		--target=efi-app-$(ARCH) $^ $@

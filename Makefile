ARCH			=	x86_64

OBJS			=	stub.o
TARGET			=	ministub.efi

EFIINC			=	/usr/include/efi
LIB				=	/usr/lib

CFLAGS			=	-nostdinc -I$(EFIINC) -I$(EFIINC)/$(ARCH) -I$(EFIINC)/protocol \
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

ministub.so: $(OBJS)
	ld $(LDFLAGS) $(OBJS) -o $@ -lefi -lgnuefi

%.efi: %.so
	objcopy -j .text -j .sdata -j .data -j .dynamic \
		-j .dynsym  -j .rel -j .rela -j .reloc \
		--target=efi-app-$(ARCH) $^ $@

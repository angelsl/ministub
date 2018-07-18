# ministub

An EFI stub that embeds an Ed25519 public key and loads and verifies a combined
vmlinuz+initrd+cmdline bundle, for use in a user key Secure Boot setup.

Adapted from systemd's EFI stub.

### Rationale

systemd's usual EFI stub includes the command line, kernel image and RAM disk as
separate sections in the PE.

I was having random boot failures with that, and so I wondered if my laptop
did not like loading large EFI binaries.

### Usage

1. Generate a private Ed25519 seed


   ```
   dd if=/dev/urandom of=privkey.dat bs=1024 count=1
   ```

2. Generate the public key


   ```
   tools/genpubkey.py privkey.dat pubkey.dat
   ```

3. Build the stub (requires EDK II)


   ```
   build -p MinistubPkg.dsc
   ```

4. Install the stub


   ```
   cp Build/Ministub/RELEASE_GCC5/X64/ministub.efi /boot/efi/EFI/linux/linux.efi
   ```

5. Generate the signed bundle

   ```
   tools/genimg.py /boot/efi/EFI/linux/combined.img privkey.dat /boot/vmlinuz-linux cmdline.txt [/boot/intel-ucode.img] /boot/initramfs-linux.img
   ```

# Chapter 10. Device Security

Until now, we’ve focused on how Android implements sandboxing and privilege separation in order to isolate applications from one another and the core OS. In this chapter, we look at how Android ensures OS integrity and protects device data from attackers that have physical access to a device. We start with a brief description of Android’s bootloader and recovery OS, then discuss Android’s verified boot feature, which guarantees that the *system* partition is not modified by malicious programs. Next we look at how Android encrypts the *userdata* partition, which hosts OS configuration files and application data. This guarantees that the device can’t be booted without the decryption password and that user data can’t be extracted even by direct access to the device’s flash memory. We then show how Android’s screen locking functionality is implemented, and how unlock patterns, PINs, and passphrases are hashed and stored on the device.

We’ll also discuss secure USB debugging, which authenticates hosts that connect to the *Android Debug Bridge (ADB)* daemon over USB and requires users to explicitly allow access for each host. Because ADB access over USB allows execution of privileged operations such as application installation, full backup, and filesystem access (including full access to external storage), this feature helps prevent unauthorized access to device data and applications on devices that have ADB debugging enabled. Finally, we describe the implementation and archive encryption format of Android’s full backup feature.

# Controlling OS Boot-Up and Installation

Given physical access to a device, an attacker can access or modify user and system data not only via higher-level OS constructs such as files and directories, but also by accessing memory or raw disk storage directly. Such direct access can be achieved by physically interfacing with the device’s electronic components by, for example, disassembling the device and connecting to hidden hardware debug interfaces or desoldering flash memory and reading the contents with a specialized device.

### Note

*Such hardware attacks are beyond the scope of this book; see [Chapter 10](ch10.html "Chapter 10. Device Security") of the* Android Hacker’s Handbook *(Wiley, 2014) for an introduction to this topic.*

A less intrusive, but still powerful way to gain access to this data is to use the device update mechanism to modify system files and remove access restrictions, or boot an alternative operating system that allows direct access to storage devices. Most consumer Android devices are locked down by default so that those techniques are either not possible or require possession of a code signing key, typically available only to the device manufacturer.

In the next sections, we briefly discuss how Android’s bootloader and recovery OS regulate access to boot images and device update mechanisms. (We’ll explore bootloader and recovery functionality in more detail in [Chapter 13](ch13.html "Chapter 13. System Updates and Root Access").)

## Bootloader

A *bootloader* is a specialized, hardware-specific program that executes when a device is first powered on (coming out of reset for ARM devices). Its purpose is to initialize device hardware, optionally provide a minimal device configuration interface, and then find and start the operating system.

Booting a device typically requires going through different stages, which may involve a separate bootloader for each stage—but we’ll refer to a single, aggregate bootloader that includes all boot stages, for the sake of simplicity. Android bootloaders are typically proprietary and specific to the system on a chip (SoC) that the device is built upon. Device and SoC manufacturers provide different functionality and levels of protection in their bootloaders, but most bootloaders support a *fastboot*, or more generally, *download mode*, which allows for the writing (usually called *flashing*) of raw partition images to the device’s persistent storage, as well as booting transient system images (without flashing them to the device). Fastboot mode is enabled by a special hardware key combination applied while the device is booting, or by sending the *reboot bootloader* command via ADB.

In order to ensure device integrity, consumer devices are shipped with locked bootloaders, which either disallow flashing and booting system images completely or allow it only for images that have been signed by the device manufacturer. Most consumer devices allow for unlocking the boot-loader, which removes fastboot restrictions and image signature checks. Unlocking the bootloader typically requires formatting the *userdata* partition, thus ensuring that a malicious OS image cannot get access to existing user data.

On some devices, unlocking the bootloader is an irreversible procedure, but most devices provide a way to relock the bootloader and return it to its original state. This is typically implemented by storing a bootloader state flag on a dedicated system partition (typically called `param` or `misc`) that hosts various device metatdata. Relocking the bootloader simply resets the value of this flag.

## Recovery

A more flexible way to update a device is via its recovery OS. The *recovery OS*, or simply *recovery*, is a minimal Linux-based OS that includes a kernel, RAM disk with various low-level tools, and a minimal UI that is typically operated using the device’s hardware buttons. The recovery is used to apply post-ship updates, generally delivered in the form of over-the-air (OTA) update packages. OTA packages include the new versions (or a binary patch) of updated system files and a script that applies the update. As we learned in [Chapter 3](ch03.html "Chapter 3. Package Management"), OTA files are also code signed with the private key of the device manufacturer. The recovery includes the public part of that key and verifies OTA files before applying them. This ensures that only OTA files that originate from a trusted party can modify the device OS.

The recovery OS is stored on a dedicated partition, just like the main Android OS. Therefore, it can be replaced by putting the bootloader into download mode and flashing a custom recovery image, which replaces the embedded public key, or does not verify OTA signatures at all. Such a recovery OS allows the main OS to be completely replaced with a build produced by a third party. A custom recovery OS can also allow unrestricted root access via ADB, as well as raw partition data acquisition. While the *userdata* partition could be encrypted (see “[Disk Encryption](ch10.html#disk_encryption "Disk Encryption")”), making direct data access impossible, it is trivial to install a malicious program (rootkit) on the *system* partition while in recovery mode. The rootkit can then enable remote access to the device when the main OS is booted and thus allow access to user data that is transparently decrypted when the main OS boots. Verified boot (discussed in the next section) can prevent this, but only if the device verifies the *boot* partition using an unmodifiable verification key, stored in hardware.

An unlocked bootloader allows booting or flashing custom system images and direct access to system partitions. While Android security features such as verified boot and disk encryption can limit the damage that a malicious system image flashed via an unlocked bootloader can do, controlling access to the bootloader is integral to protecting an Android device. Therefore the bootloader should only be unlocked on test or development devices, or relocked and returned to its original state immediately after modifying the system.

# Verified Boot

Android’s verified boot implementation is based on the dm-verity device-mapper block integrity checking target.^([[100](#ftn.ch10fn01)]) *Device-mapper*^([[101](#ftn.ch10fn02)]) is a Linux kernel framework that provides a generic way to implement virtual block devices. It’s the basis of Linux’s Logical Volume Manager (LVM), and it’s used to implement full-disk encryption (using the dm-crypt target), RAID arrays, and even distributed replicated storage.

Device-mapper works by essentially mapping a virtual block device to one or more physical block devices and optionally modifying transferred data in transit. For example, dm-crypt (which is also the basis of Android’s *userdata* partition encryption, as discussed in “[Disk Encryption](ch10.html#disk_encryption "Disk Encryption")”) decrypts read physical blocks and encrypts written blocks before committing them to disk. Thus, disk encryption is transparent to users of the virtual dm-crypt block device. Device-mapper targets can be stacked on top of each other, making it possible to implement complex data transformations.

## dm-verity Overview

Because dm-verity is a block integrity checking target, it transparently verifies the integrity of each device block as it’s being read from disk. If the block checks out, the read succeeds; if not, the read generates an I/O error as if the block were physically corrupted.

Under the hood, dm-verity is implemented using a precalculated hash tree (also called a *Merkle tree*) that includes the hashes of all device blocks. The leaf nodes of the tree include hashes of physical device blocks, while intermediate nodes are hashes of their child nodes (hashes of hashes). The root node is called the *root hash* and is based on all hashes in lower levels, as shown in [Figure 10-1](ch10.html#dm-verity_hash_tree "Figure 10-1. dm-verity hash tree"). Thus, a change even in a single device block will result in a change of the root hash, and in order to verify that a hash tree is genuine we only need to verify its root hash.

At runtime, dm-verity calculates the hash of each block when it’s read and verifies it by traversing the precalculated hash tree. Because reading data from a physical device is already a time-consuming operation, the latency added by hashing and verification is relatively low. Furthermore, once verified, disk blocks are cached, and subsequent reads of the same block do not trigger integrity verification.

![dm-verity hash tree](figs/web/10fig01.png.jpg)

Figure 10-1. dm-verity hash tree

Because dm-verity depends on a precalculated hash tree over all blocks of a device, the underlying device must be mounted read-only in order for verification to be possible. Most filesystems record mount times and other metadata in their superblock, so even if no files are changed at runtime, block integrity checks will fail if the underlying block device is mounted read-write. Even though this can be seen as a limitation, it works well for devices or partitions that hold system files, which are only changed by OS updates. Any other change indicates either OS or disk corruption, or that a malicious program is trying to modify the OS or masquerade as a system file.

Ultimately, dm-verity’s read-only requirement fits well with Android’s security model, which hosts only application data on a read-write partition and keeps OS files on the read-only *system* partition.

## Android Implementation

The dm-verity device-mapper target was originally developed in order to implement verified boot in Chrome OS and was integrated into the mainline Linux kernel in version 3.4\. It’s enabled with the `CONFIG_DM_VERITY` kernel configuration item.

Like Chrome OS, Android 4.4 also uses the dm-verity target, but the cryptographic verification of the root hash and mounting of verified partitions are implemented differently. The RSA public key used for verification is embedded in the boot partition under the *verity_key* filename and is used to verify the dm-verity mapping table, which holds the locations of the target device and the offset of the hash table, as well as the root hash and salt.

The mapping table and its signature are part of the verity metadata block, which is written to disk directly after the last filesystem block of the target device. A partition is marked as verifiable by adding the `verify` flag to the Android-specific *fs_mgr_flags* field of the device’s *fstab* file. When Android’s filesystem manager encounters the `verify` flag in *fstab*, it loads the verity metadata from the block device specified in *fstab* and verifies its signature using the included verity key. If the signature check succeeds, the filesystem manager parses the dm-verity mapping table and passes it to the Linux device-mapper, which uses the information contained in the mapping table in order to create a virtual dm-verity block device. This virtual block device is then mounted at the mount point specified in *fstab* in place of the corresponding physical device. As a result, all reads from the underlying physical device are transparently verified against the pre-generated hash tree. Modifying or adding files, or even remounting the partition as read-write results in an integrity verification and an I/O error.

### Note

*Because dm-verity is a kernel feature, in order for its integrity protection to be effective, the kernel that the device boots needs to be trusted. On Android, this requires verifying the boot partition, which also contains the root filesystem RAM disk (*initrd*) and the verity public key. Kernel or boot image verification is a device-specific process, which is typically implemented in the device bootloader and relies on an unmodifiable signature verification key stored in hardware.*

## Enabling Verified Boot

The official Android documentation describes the procedure required to enable verified boot on Android as a multi-step process, which involves generating a hash tree, creating a dm-verity mapping table for the hash tree, signing the table, and generating and writing a verity metadata block to the target device.^([[102](#ftn.ch10fn03)]) In this section, we briefly describe the key steps of this process.

A dm-verity hash tree is generated with the `veritysetup` program, which is part of the *cryptsetup* cryptographic volume management tools package. The `veritysetup` program can operate directly on block devices or generate a hash tree using a filesystem image, and write the hash table to a file. Android’s dm-verity implementation expects that the hash tree data to be stored on the same device as the target filesystem, so an explicit hash offset that points to a location after the verity metadata block must be specified when invoking `veritysetup`. [Figure 10-2](ch10.html#layout_of_a_disk_partition_prepared_for "Figure 10-2. Layout of a disk partition prepared for dm-verity verification") shows the layout of a disk partition prepared for use with dm-verity.

![Layout of a disk partition prepared for dm-verity verification](figs/web/10fig02.png.jpg)

Figure 10-2. Layout of a disk partition prepared for dm-verity verification

Generating the hash tree produces the root hash, which is used to build the dm-verity mapping table for the target device. A sample mapping table is shown in [Example 10-1](ch10.html#android_dm-verity_device_mapping_table "Example 10-1. Android dm-verity device mapping table").

Example 10-1. Android dm-verity device mapping table

```
1➊ /dev/block/mmcblk0p21➋ /dev/block/mmcblk0p21➌ 4096➍ 4096➎
204800➏ 204809➐ sha256➑
1F951588516c7e3eec3ba10796aa17935c0c917475f8992353ef2ba5c3f47bcb➒
5f061f591b51bf541ab9d89652ec543ba253f2ed9c8521ac61f1208267c3bfb1➓
```

As shown in the listing, the table is a single line (split across multiple lines for readability) that, besides the root hash ➒, contains the dm-verity version ➊, name of the underlying data and hash device (➋ and ➌), data and hash block sizes (➍ and ➎), data and hash disk offsets (➏ and ➐), hash algorithm ➑, and salt ➓.

The mapping table is signed using a 2048-bit RSA key, and along with the resulting PKCS#1 v1.5 signature, is used to form the 32 KB verity metadata block. [Table 10-1](ch10.html#verity_metadata_block_contents "Table 10-1. Verity Metadata Block Contents") shows the contents and size of each field of the metadata block.

Table 10-1. Verity Metadata Block Contents

| Field | Description | Size | Value |
| --- | --- | --- | --- |
| Magic number | Used by fs_mgr as a sanity check | 4 bytes | 0xb001b001 |
| Version | Metadata block version | 4 bytes | Currently 0 |
| Signature | Mapping table signature (PKCS#1 v1.5) | 256 bytes |   |
| Mapping table length | Mapping table length in bytes | 4 bytes |   |
| Mapping table | dm-verity mapping table | variable |   |
| Padding | Zero-byte padding to 32k byte length | variable |   |

The RSA public key used for verification needs to be in mincrypt format (a minimalistic cryptographic library, also used by the stock recovery when verifying OTA file signatures), which is a serialization of mincrypt’s `RSAPublicKey` structure. The interesting thing about this structure is that it doesn’t simply include the key’s modulus and public exponent values, but contains pre-computed values used by mincrypt’s RSA implementation (based on Montgomery reduction). The public key is included in the root of the boot image under the *verity_key* filename.

The last step needed to enable verified boot is to modify the device’s *fstab* file in order to enable block integrity verification for the *system* partition. This is simply a matter of adding the `verify` flag, as shown in [Example 10-2](ch10.html#fstab_entry_for_a_dm-verity-formatted_pa "Example 10-2. fstab entry for a dm-verity-formatted partition verified") (example *fstab* file for Nexus 4).

Example 10-2. fstab entry for a dm-verity-formatted partition verified

```
/dev/block/platform/msm_sdcc.1/by-name/system /system ext4 ro,barrier=1 wait,verify
```

When the device boots, Android automatically creates a virtual dm-verity device based on the *fstab* entry and the information in the mapping table (contained in the metadata block), and mounts it at */system* as shown in [Example 10-3](ch10.html#dm-verity_virutal_block_device_mounted_a "Example 10-3. dm-verity virutal block device mounted at /system").

Example 10-3. dm-verity virutal block device mounted at /system

```
# **mount|grep system**
/dev/block/dm-0 /system ext4 ro,seclabel,relatime,data=ordered 0 0
```

Now, any modifications to the system partition will result in read errors when reading the corresponding file(s). Unfortunately, system modifications by file-based OTA updates, which modify file blocks without updating verity metadata, also invalidate the hash tree. As mentioned in the official documentation, in order to be compatible with dm-verity-based verified boot, OTA updates should operate at the block level, ensuring that both file blocks and the hash tree and metadata are updated. This requires changing the current OTA update infrastructure, which is probably one of the reasons verified boot has yet to be deployed to production devices.

# Disk Encryption

Android 3.0 introduced disk encryption along with device administrator policies (see [Chapter 9](ch09.html "Chapter 9. Enterprise Security") for details) that can enforce mandatory device encryption as one of the several “enhancements for the enterprise” included in that release. Disk encryption has been available in all subsequent versions with relatively few changes until version 4.4, which introduced a new key derivation function (scrypt). This section describes how Android implements disk encryption and how encryption keys and meta-data are stored and managed.

### Note

*The Android Compatibility Definition requires that “IF the device has lockscreen, the device MUST support full-disk encryption.”*^([[103](#ftn.ch10fn04)])

*Disk encryption* uses an encryption algorithm to convert every bit of data that goes to disk to ciphertext, ensuring that data cannot be read from the disk without the decryption key. *Full-disk encryption (FDE)* promises that everything on disk is encrypted, including operating system files, cache, and temporary files. In practice, a small part of the OS, or a separate OS loader, must be kept unencrypted so that it can obtain the decryption key and then decrypt and mount the disk volume(s) used by the main OS. The disk decryption key is usually stored encrypted and requires an additional key encryption key (KEK) in order to be decrypted. The KEK can either be stored in a hardware module, such as a smart card or a TPM, or derived from a passphrase obtained from the user on each boot. When stored in a hardware module, the KEK can also be protected by a user-supplied PIN or password.

Android’s FDE implementation encrypts only the *userdata* partition, which stores system configuration files and application data. The *boot* and *system* partitions, which store the kernel and OS files, are not encrypted, but *system* can optionally be verified using the dm-verity device-mapper target as described earlier in “[Verified Boot](ch10.html#verified_boot-id00021 "Verified Boot")”. Android’s disk encryption is not enabled by default, and the disk encryption process must be triggered either by the user or by a device policy on managed devices. We examine Android’s disk encryption implementation in the following sections.

## Cipher Mode

Android’s disk encryption uses dm-crypt,^([[104](#ftn.ch10fn05)]) currently the standard disk encryption subsystem in the Linux kernel. Like dm-verity, dm-crypt is a device-mapper target that maps an encrypted physical block device to a virtual device-mapper device. All data access to the virtual device is decrypted (for reads) or encrypted (for writes) transparently.

The encryption mechanism employed in Android uses a randomly generated 128-bit key together with AES in CBC mode. As we learned in [Chapter 5](ch05.html "Chapter 5. Cryptographic Providers"), CBC mode requires an initialization vector (IV) that needs to be both random and unpredictable in order for encryption to be secure. This presents a problem when encrypting block devices, because blocks are accessed non-sequentially, and therefore each sector (or device block) requires a separate IV.

Android uses the encrypted salt-sector initialization vector (ESSIV) method with the SHA-256 hash algorithm (ESSIV:SHA256) in order to generate per-sector IVs. ESSIV employs a hash algorithm to derive a secondary key *s* from the disk encryption key *K*, called a *salt*. It then uses the salt as an encryption key and encrypts the sector number *SN* of each sector to produce a per-sector IV. In other words, *IV(SN) = AES[s](SN)*, where *s = SHA256(K)*.

Because the IV of each sector depends on a secret piece of information (the disk encryption key), per-sector IVs cannot be deduced by an attacker. However, ESSIV does not change CBC’s malleability property and does not ensure the integrity of encrypted blocks. In fact, it’s been demonstrated that an attacker who knows the original plaintext stored on disk can manipulate stored data and even inject a backdoor on volumes that use CBC for disk encryption.^([[105](#ftn.ch10fn06)])

Alternative Ciper Modes: XTS

This particular attack against the ESSIV mode can be avoided by switching to a tweakable encryption cipher mode such as XTS (XEX-based tweaked-codebook mode with ciphertext stealing), which uses a combination of the sector address and index of the cipher block inside the sector to derive a unique “tweak” (variable parameter) for each sector.

Using a distinct tweak for each sector has the same effect as encrypting each sector with a unique key: the same plaintext will result in different ciphertext when stored in different sectors, but has much better performance than deriving a separate key (or IV) for each sector. However, while better than the CBC ESSIV mode, XTS is still susceptible to data manipulation in some cases and does not provide ciphertext authentication.

As of this writing, Android does not support the XTS mode for disk encryption. However, the underlying dm-crypt device-mapper target supports XTS, and it can easily be enabled with some modifications to Android’s volume daemon (*vold*) implementation.

## Key Derivation

The disk encryption key (called the “master key” in Android source code) is encrypted with another 128-bit AES key (KEK), derived from a user-supplied password. In Android versions 3.0 to 4.3, the key derivation function used was PBKDF2 with 2,000 iterations and a 128-bit random salt value. The resulting encrypted master key and the salt are stored, along with other metadata like the number of failed decryption attempts, in a footer structure occupying the last 16 KB of the encrypted partition, called a *crypto footer*. Storing an encrypted key on disk instead of using a key derived from the user-supplied password directly allows for changing the decryption password quickly, because the only thing that needs to be re-encrypted with the key derived from the new password is the master key (16 bytes).

While using a random salt makes it impossible to use precomputed tables to speed up key cracking, the number of iterations (2,000) used for PBKDF2 is not sufficiently large by today’s standards. (The keystore key derivation process uses 8,192 iterations as discussed in [Chapter 7](ch07.html "Chapter 7. Credential Storage"). Backup encryption uses 10,000 iterations, as discussed later in “[Android Backup](ch10.html#android_backup "Android Backup")”.) Additionally, PBKDF2 is an iterative algorithm, based on standard and relatively easy to implement hash functions, which makes it possible for PBKDF2 key derivation to be parallelized, taking full advantage of the processing power of multi-core devices such as GPUs. This allows even fairly complex alphanumeric passphrases to be brute-forced in a matter of days, or even hours.

In order to make it harder to brute-force disk encryption passwords, Android 4.4 introduced support for a new key derivation function called *scrypt*.^([[106](#ftn.ch10fn07)]) Scrypt employs a key derivation algorithm specifically designed to require large amounts of memory, as well as multiple iterations (such an algorithm is called *memory hard*). This makes it harder to mount brute-force attacks on specialized hardware such as ASICs or GPUs, which typically operate with a limited amount of memory.

Scrypt can be tuned by specifying the variable parameters *N*, *r*, and *p*, which influence the required CPU resources, memory amount, and parallelization cost, respectively. The values used in Android by default are *N* = 32768 (2^(15)), *r* = 8, and *p* = 2\. They can be changed by setting the value of the *ro.crypto.scrypt_params* system property using the *N_factor:r_factor:p_factor* format; for example, *15:3:1* (the default). The value of each parameter is computed by raising 2 to the power of the respective factor. Android 4.4 devices automatically update the key derivation algorithm in the crypto footer from PBKDF2 to scrypt and re-encrypt the master key using a scrypt-derived encryption key. When the encrypted master key is updated, the *N, r*, and *p* parameters that were used for KEK derivation are written to the crypto footer.

### Note

*On the same desktop machine, brute-forcing a 4-digit PIN (using a naive, single-threaded algorithm that generates all possible PINs starting from 0000) takes about 5 milliseconds per PIN when using PBKDF2, and about 230 milliseconds per PIN when using scrypt as the KEK derivation function. In other words, brute-forcing PBKDF2 is almost 50 times cheaper (that is, faster) compared to scrypt.*

## Disk Encryption Password

As discussed in the previous section, the KEK used to encrypt the disk encryption key is derived from a user-supplied password. When you first start the device encryption process, you’re asked to either confirm your device unlock PIN or password, or set one if you haven’t already or you’re using the pattern screen lock (see [Figure 10-3](ch10.html#device_encryption_screen "Figure 10-3. Device encryption screen")). The entered password or PIN is then used to derive the master key encryption key, and you’re required to enter the password or PIN each time you boot the device, and then once more to unlock the screen after it starts.

Android doesn’t have a dedicated setting to manage the encryption password after the device is encrypted, and changing the screen lock password or PIN will also silently change the device encryption password. This is most probably a usability-driven decision: most users would be confused by having to remember and enter two different passwords at different times and would probably quickly forget the less frequently used, and possibly more complex, disk encryption password. While this design is good for usability, it effectively forces users to use a simple disk encryption password, because they have to enter it each time they unlock the device, usually dozens of times a day. No one wants to enter a complex password that many times, and thus most users opt for a simple numeric PIN (unless a device policy requires otherwise). Additionally, passwords are limited to 16 characters (a limit that is hardwired in the framework and not configurable), so using a passphrase is not an option.

![Device encryption screen](figs/web/10fig03.png.jpg)

Figure 10-3. Device encryption screen

What’s the problem with using the same password for both disk encryption and the lockscreen? After all, to get to the data on the phone you need to guess the lockscreen password anyway, so why bother with a separate one for disk encryption? The reason is that the two passwords protect your phone against two different types of attack. Most screen lock attacks would be online, brute-force ones: essentially someone trying out different passwords on a running device when they get brief access to it. After a few unsuccessful attempts, Android will lock the screen for 30 seconds (rate limiting), and even wipe the device if there are more failed unlock attempts (if required by device policy). Thus, even a relatively short screen-lock PIN offers adequate protection against online attacks in most cases (see “[Brute-Force Attack Protection](ch10.html#brute-force_attack_protection "Brute-Force Attack Protection")” for details).

Of course, if someone has physical access to the device or a disk image of it, they can extract password hashes and crack them offline without worrying about rate-limiting or device wiping. This, in fact, is the scenario that full disk encryption is designed to protect against: when a device is stolen or confiscated, the attacker can either brute-force the actual device, or copy its data and analyze it even after the device is returned or disposed of. As mentioned earlier in “[Key Derivation](ch10.html#key_derivation "Key Derivation")”, the encrypted master key is stored on disk, and if the password used to derive its encryption key is based on a short numeric PIN, it can be brute-forced in minutes^([[107](#ftn.ch10fn08)]) (or even seconds on pre-4.4 devices that use PBKDF2 for key derivation). A remote wipe solution could prevent this attack by deleting the master key, which only takes a moment and renders the device useless, but this is often not an option because the device might be offline or turned off.

## Changing the Disk Encryption Password

The user-level part of disk encryption is implemented in the *cryptfs* module of Android’s volume management daemon (*vold*). *crypfs* has commands for both creating and mounting an encrypted volume, and for verifying and changing the master key encryption password. Android system services communicate with *cryptfs* by sending commands to *vold* through a local socket (also named *vold*), and *vold* sets system properties that describe the current state of the encryption or mount process based on the received command. (This results in a fairly complex boot procedure, described in detail in “[Enabling Encryption](ch10.html#enabling_encryption "Enabling Encryption")” below and “[Booting an Encrypted Device](ch10.html#booting_an_encrypted_device "Booting an Encrypted Device")”.)

Android does not provide a UI to change only the disk encryption password, but one can do so by communicating directly with the *vold* daemon using the `vdc` command-line utility. However, access to the *vold* control socket is limited to the root user and members of the *mount* group, and furthermore, *cryptfs* commands are only available to the *root* and *system* users. If you’re using an engineering build, or your device provides root access via a “superuser” app (see [Chapter 13](ch13.html "Chapter 13. System Updates and Root Access")), you can send the *cryptfs* command shown in [Example 10-4](ch10.html#changing_the_disk_encryption_password_us "Example 10-4. Changing the disk encryption password using vdc") to *vold* in order to change the disk encryption password.

Example 10-4. Changing the disk encryption password using `vdc`

```
# **vdc cryptfs changepw <newpass>**
200 0 0
```

### Note

*If you change your lockscreen password, the disk encryption password will be changed automatically. (This does not apply to secondary users on multi-user devices.)*

## Enabling Encryption

As mentioned in the previous section, the user-level part of Android’s disk encryption is implemented by a dedicated *cryptfs* module of the *vold* daemon. *cryptfs* provides the `checkpw`, `restart`, `cryptocomplete`, `enablecrypto`, `changepw`, `verifypw`, `getfield`, and `setfield` commands, which the framework sends at various points of the encryption or encrypted volume mount process. In addition to the permissions set on the *vold* local socket, *crypfs* explicitly checks the identity of the command sender, and only allows access to the *root* and *system* users.

### Controlling Device Encryption Using System Properties

The *vold* daemon sets a number of system properties in order to trigger the various stages of device encryption or mounting and to communicate the current encryption state to framework services. The *ro.crypto.state* property holds the current encryption state, which is set to *encrypted* when the data partition has been successfully encrypted, and to *unencrypted* when it has not yet been encrypted. The property can also be set to *unsupported* if the device does not support disk encryption. The *vold* daemon also sets various predefined values to the *vold.decrypt* property in order to signal the current state of device encryption or mounting. The *vold.encrypt_progress* property holds the current encryption progress (from 0 to 100), or an error string if an error occurred during device encryption or mounting.

The *ro.crypto.fs_crypto_blkdev* system property contains the name of the virtual device allocated by the device mapper. After successfully decrypting the disk encryption key, this virtual device is mounted at */data* in place of the underlying physical volume, as shown in [Example 10-5](ch10.html#encrypted_virtual_block_device_mounted_a "Example 10-5. Encrypted virtual block device mounted at /data") (with output split for readability).

Example 10-5. Encrypted virtual block device mounted at /data

```
# **mount|grep '/data'**
/dev/block/dm-0 /data ext4 rw,seclabel,nosuid,nodev,noatime,
errors=panic,user_xattr,barrier=1,nomblk_io_submit,data=ordered 0 0
```

### Unmounting /data

The Android framework expects */data* to be available, but it needs to be unmounted in order to be encrypted. This creates a catch-22 situation, which Android solves by unmounting the physical *userdata* partition and mounting an on-memory filesystem (tempfs) in its place while performing encryption. Switching partitions at runtime in turn requires stopping and restarting certain system services, which *vold* triggers by setting the value of the *vold.decrypt* system property to *trigger_restart_framework*, *trigger_restart_min_framework*, or *trigger_shutdown_framework*. These values trigger different parts of *init.rc*, as shown in [Example 10-6](ch10.html#volddotdecrypt_triggers_in_initdotrc "Example 10-6. vold.decrypt triggers in init.rc").

Example 10-6. vold.decrypt triggers in init.rc

```
--*snip*--
on post-fs-data➊
    chown system system /data
    chmod 0771 /data
    restorecon /data
    copy /data/system/entropy.dat /dev/urandom
--*snip*--
on property:vold.decrypt=trigger_reset_main➋
    class_reset main

on property:vold.decrypt=trigger_load_persist_props
    load_persist_props

on property:vold.decrypt=trigger_post_fs_data➌
    trigger post-fs-data

on property:vold.decrypt=trigger_restart_min_framework➍
    class_start main

on property:vold.decrypt=trigger_restart_framework➎
    class_start main
    class_start late_start

on property:vold.decrypt=trigger_shutdown_framework➏
    class_reset late_start
    class_reset main
--*snip-*
```

### Triggering the Encryption Process

When the user starts the encryption process via the system Settings UI with Security▸Encrypt phone, the Settings app calls `MountService`, which in turn sends the `cryptfs enablecrypto inplace` *`password`* command to *vold*, where *`password`* is the lockscreen password. In turn, *vold* unmounts the *userdata* partition and sets *vold.decrypt* to *trigger_shutdown_framework* (➏ in [Example 10-6](ch10.html#volddotdecrypt_triggers_in_initdotrc "Example 10-6. vold.decrypt triggers in init.rc")), which shuts down most system services except for those that are part of the *core* service class. The *vold* daemon then unmounts */data,* mounts a tempfs file-system in its place, and then sets *vold.encrypt_progress* to 0 and *vold.decrypt* to *trigger_restart_min_framework* (➍ in [Example 10-6](ch10.html#volddotdecrypt_triggers_in_initdotrc "Example 10-6. vold.decrypt triggers in init.rc")). This starts a few more system services (in the *main* class) that are required for showing the encryption progress UI.

### Updating the Crypto Footer and Encrypting Data

Next, *vold* sets up the virtual dm-crypt device and writes the crypto footer. The footer can be written to the end of the *userdata* partition or to a dedicated partition or file, and its location is specified in the *fstab* file as the value of the `encryptable` flag. For example, on the Nexus 5 the crypto footer is written to the dedicated partition *metadata*, as shown in [Example 10-7](ch10.html#encryptable_fstab_flag_specifies_the_loc "Example 10-7. The encryptable fstab flag specifies the location of the crypto footer") as ➊ (with the single line broken for readability). When the crypto footer is written at the end of the encrypted partition, the `encryptable` flag is set to the string *footer*.

Example 10-7. The `encryptable` fstab flag specifies the location of the crypto footer

```
--*snip*--
/dev/block/platform/msm_sdcc.1/by-name/userdata  /data  ext4
noatime,nosuid,nodev,barrier=1,data=ordered,nomblk_io_submit,noauto_da_alloc,errors=panic
wait,check,encryptable=/dev/block/platform/msm_sdcc.1/by-name/metadata➊
--*snip*--
```

The crypto footer contains the encrypted disk encryption key (master key), the salt used for KEK derivation, and other key derivation parameters and metadata. Its *flags* field is set to `CRYPT_ENCRYPTION_IN_PROGRESS` (0x2) to signal that device encryption has started but not been completed.

Finally, each block is read from the physical *userdata* partition and written to the virtual dm-crypt device, which encrypts read blocks and writes them to disk, thus encrypting the *userdata* partition in place. If encryption completes without errors, *vold* clears the `CRYPT_ENCRYPTION_IN_PROGRESS` flag and reboots the device.

## Booting an Encrypted Device

Booting an encrypted device requires asking the user for the disk encryption password. Rather then use a specialized bootloader UI, Android sets the *vold. decrypt* system property to 1 and then starts a minimal set of system services in order to show a standard Android UI. As with device encryption, this again requires mounting a tmpfs filesystem at */data* in order to allow core system services to start. When the core framework is up, Android detects that *vold. decrypt* is set to 1 and starts the *userdata* partition mount process.

![Device encryption password input UI](figs/web/10fig04.png.jpg)

Figure 10-4. Device encryption password input UI

![UI shown if device encryption fails](figs/web/10fig05.png.jpg)

Figure 10-5. UI shown if device encryption fails

### Obtaining the Disk Encryption Password

The first step in this process is to check whether the partition has been successfully encrypted by sending the `cryptfs cryptocomplete` command to *vold*, which in turn checks whether the crypto footer is properly formatted and that the `CRYPT_ENCRYPTION_IN_PROGRESS` flag is not set. If the partition is found to be successfully encrypted, the framework launches the password entry UI shown in [Figure 10-4](ch10.html#device_encryption_password_input_ui "Figure 10-4. Device encryption password input UI") provided by `CryptKeeper`, part of the system Settings app. This activity acts as a home screen (launcher), and because it has higher priority than the default launcher, it’s started first after the device boots.

If the device is unencrypted, `CryptKeeper` disables itself and finishes, which causes the system activity manager to launch the default home screen application. If the device is encrypted or in the process of being encrypted (that is, the *vold.crypt* property is not empty or set to *trigger_restart_framework*), the `CryptKeeper` activity starts and hides the status and system bars. In addition, `CryptKeeper` ignores hardware back button presses, thus disallowing navigation away from the password input UI.

If the encrypted device is corrupted, or the encryption process interrupted and the *userdata* partition left only partially encrypted, the device cannot be booted. In this case, `CryptKeeper` displays the UI shown in [Figure 10-5](ch10.html#ui_shown_if_device_encryption_fails "Figure 10-5. UI shown if device encryption fails"), allowing the user to trigger a factory reset, which reformats the *userdata* partition.

### Decrypting and Mounting /data

When the user enters their password, `CryptKeeper` sends the `cryptfs checkpw` command to *vold* by calling the `decryptStorage()` method of the system `MountService`. This instructs *vold* to check whether the entered password is correct by trying to mount the encrypted partition at a temporary mount point and then unmounting it. If the procedure succeeds, *vold* sets the name of the virtual block device allocated by the device-mapper as the value of *ro.crypto.fs_crypto_blkdev* property and returns control to `MountService`, which in turn sends the `cryptfs restart` command, instructing *vold* to restart all system services in the *main* class (➋ in [Example 10-6](ch10.html#volddotdecrypt_triggers_in_initdotrc "Example 10-6. vold.decrypt triggers in init.rc")). This allows the tempfs filesystem to be unmounted, and the newly allocated virtual dm-crypt block device to be mounted at */data*.

### Starting All System Services

After the encrypted partition is mounted and prepared, *vold* sets *vold.decrypt* to *trigger_post_fs_data* (➌ in [Example 10-6](ch10.html#volddotdecrypt_triggers_in_initdotrc "Example 10-6. vold.decrypt triggers in init.rc")), thus triggering the *post-fs-data* ➊ section of *init.rc*. The commands in this section set up file and directory permissions, restore SELinux contexts, and create required directories under */data* if necessary.

Finally, *post-fs-data* sets the *vold.post_fs_data_done property* to 1, which *vold* polls periodically. When *vold* detects a value of 1, it sets the *vold.decrypt* property to *trigger_restart_framework* (➎ in [Example 10-6](ch10.html#volddotdecrypt_triggers_in_initdotrc "Example 10-6. vold.decrypt triggers in init.rc")), which restarts all services in the *main* class, and starts all delayed services (class *late_start*). At this point, the framework is fully initialized and the device boots using the decrypted view of the *userdata* partition mounted at */data*. From this point on, all data written by applications or the system is automatically encrypted before being committed to disk.

Limitations of Disk Encryption

Disk encryption only protects data at rest; that is, when the device is turned off. Because disk encryption is transparent and implemented at the kernel level, after an encrypted volume is mounted, it is indistinguishable from a plaintext volume to user-level processes. Therefore disk encryption does not protect data from malicious programs running on the device. Applications that deal with sensitive data should not rely solely on full-disk encryption, but should implement their own, file-based encryption instead. The file encryption key should be encrypted with a KEK derived from a user-supplied password, or some unchangeable hardware property if the data needs to be bound to the device. To ensure file integrity, encrypted data must be authenticated using either an authenticated encryption scheme like GCM, or an additional authentication function such as HMAC.

# Screen Security

One way to control access to an Android device is by requiring user authentication in order to access the system UI and applications. User authentication is implemented by showing a *lockscreen* each time the device boots or its screen is turned on. The lockscreen on a single-user device, configured to require a numeric PIN to unlock, might look like [Figure 10-6](ch10.html#pin_lockscreen "Figure 10-6. PIN lockscreen").

In early Android versions, the lock-screen was only designed to protect access to the device’s UI. As the platform evolved, the lockscreen has been extended with features that display widgets that show up-to-date device or application state, allow switching between users on multi-user devices, and the ability to unlock the system keystore. Similarly, the screen unlock PIN or password is now used to derive the credential storage encryption key (for software implementations), as well as the disk encryption key KEK.

![PIN lockscreen](figs/web/10fig06.png.jpg)

Figure 10-6. PIN lockscreen

## Lockscreen Implementation

Android’s lockscreen (or *keyguard*) is implemented like regular Android applications: with widgets laid out on a window. It’s special because its window lives on a high window layer that other applications cannot draw on top of or control. Additionally, the keyguard intercepts the normal navigation buttons, which makes it impossible to bypass and thus “locks” the device.

The keyguard window layer is not the highest layer, however; dialogs originating from the keyguard itself, and the status bar, are drawn over the keyguard. You can see a list of the currently shown windows using the Hierarchy Viewer tool available with the ADT. When the screen is locked, the active window is the Keyguard window, as shown in [Figure 10-7](ch10.html#keyguard_window_position_in_androidapost "Figure 10-7. Keyguard window position in Android’s window stack").

### Note

*Prior to Android 4.0, third-party applications could show windows in the keyguard layer, which allowed applications to intercept the Home button and implement “kiosk”-style applications. However, because this functionality was abused by certain malware applications, since Android 4.0 adding windows to the keyguard layer requires the `INTERNAL_SYSTEM_WINDOW` signature permission, which is available only to system applications.*

![Keyguard window position in Android’s window stack](figs/web/10fig07.png)

Figure 10-7. Keyguard window position in Android’s window stack

For a long time, the keyguard was an implementation detail of Android’s window system and was not separated into a dedicated component. With the introduction of lockscreen widgets, dreams (that is, screensavers), and support for multiple users, the keyguard gained quite a lot of new functionality and was eventually extracted in a dedicated system application, `Keyguard`, in Android 4.4\. The `Keyguard` app lives in the *com.android.systemui* process, along with the core Android UI implementation.

The UI for each unlock method (discussed next) is implemented as a specialized view component. This component is hosted by a dedicated view container class called `KeyguardHostView`, along with keyguard widgets and other helper UI components. For example, the PIN unlock view shown in [Figure 10-6](ch10.html#pin_lockscreen "Figure 10-6. PIN lockscreen") is implemented in the `KeyguardPINView` class, and password unlock is implemented by the `KeyguardPasswordView` class. The `KeyguardHostView` class automatically selects and displays the appropriate keyguard view for the currently configured unlock method and device state. Unlock views delegate password checks to the `LockPatternUtils` class, which is responsible for comparing user input to saved unlock credentials, as well as for persisting password changes to disk and updating authentication-related metadata.

Besides the implementations of keyguard unlock views, the `Keyguard` system application includes the exported `KeyguardService` service, which exposes a remote AIDL interface, `IKeyguardService`. This service allows its clients to check the current state of the keyguard, set the current user, launch the camera, and hide or disable the keyguard. Operations that change the state of the keyguard are protected by a system signature permission, `CONTROL_KEYGUARD`.

## Keyguard Unlock Methods

Stock Android provides several keyguard unlock methods (also called *security modes* in Android’s source code). Of these, five can be directly selected in the Choose screen lockscreen: Slide, Face Unlock, Pattern, PIN, and Password, as shown in [Figure 10-8](ch10.html#directly_selectable_keyguard_unlock_meth "Figure 10-8. Directly selectable keyguard unlock methods").

The Slide unlock method requires no user authentication and its security level is therefore equivalent to selecting None. Both states are represented internally by setting the current security mode to the `KeyguardSecurityModel.SecurityMode.None` enum value. As of this writing, Face Unlock is the only implementation of the `SecurityMode.Biometric` security mode and is internally referred to as “weak biometric” (a “strong bio-metric” could be implemented with fingerprint or iris recognition in a future version). Unlock methods that are not compatible with the current device security policy (the top three in [Figure 10-8](ch10.html#directly_selectable_keyguard_unlock_meth "Figure 10-8. Directly selectable keyguard unlock methods")) are disabled and cannot be selected. The security policy can be set either explicitly by a device administrator, or implicitly by enabling a security-related OS feature such as credential storage or full-disk encryption.

The Pattern unlock method (`SecurityMode.Pattern`) is Android-specific and requires drawing a predefined pattern on a 3×3 grid to unlock the device, as shown in [Figure 10-9](ch10.html#configuring_the_pattern_unlock_method "Figure 10-9. Configuring the Pattern unlock method").

![Directly selectable keyguard unlock methods](figs/web/10fig08.png.jpg)

Figure 10-8. Directly selectable keyguard unlock methods

![Configuring the Pattern unlock method](figs/web/10fig09.png.jpg)

Figure 10-9. Configuring the Pattern unlock method

The PIN (`SecurityMode.PIN`) and Password (`SecurityMode.Password`) unlock methods are implemented similarly, but differ by the scope of allowed characters: only numeric (0-9) for the PIN, or alphanumeric for Password are allowed.

The `SecurityMode` enum defines three more unlock methods that are not directly selectable in the Choose screen lockscreen: `SecurityMode.Account`, `SecurityMode.SimPin`, and `SecurityMode.SimPuk`. The `SecurityMode.Account` method is available only on devices that support Google accounts (Google experience devices) and is not an independent unlock method. It can only be used as a fallback method for another security mode. Similarly, `SecurityMode.SimPin` and `SecurityMode.SimPuk` are not lockscreen unlock methods per se; they’re only available if the device’s SIM card requires a PIN before use. Because the SIM card remembers the PIN authentication status, the PIN or PUK must be entered only once—when the device boots (or if the SIM card state is otherwise reset). We’ll delve deeper into the implementation of each lockscreen security mode in the next sections.

### Face Unlock

Face Unlock is a relatively new unlock method introduced in Android 4.0\. It uses the device’s front-facing camera to register an image of the owner’s face (see [Figure 10-10](ch10.html#face_unlock_setup_screen "Figure 10-10. Face Unlock setup screen")) and relies on image recognition technology to recognize the face captured when unlocking the device. Although improvements to Face Unlock’s accuracy have been made since its introduction, it’s considered the least secure of all unlock methods, and even the setup screen warns users that “someone who looks similar to you could unlock your phone.” In addition, Face Unlock requires a backup unlock method—either a pattern or a PIN, to handle situations when face recognition is not possible (such as poor lighting, camera malfunction, and so on). The Face Unlock implementation is based on facial recognition technology developed by the PittPatt (Pittsburgh Pattern Recognition) company, which Google acquired in 2011\. The code remains proprietary and no details are available about the format of the stored data or the recognition algorithms employed. As of this writing, the implementation of Face Unlock resides in the `com.android.facelock` package.

![Face Unlock setup screen](figs/web/10fig10.png.jpg)

Figure 10-10. Face Unlock setup screen

### Pattern Unlock

As shown in [Figure 10-9](ch10.html#configuring_the_pattern_unlock_method "Figure 10-9. Configuring the Pattern unlock method"), the code for pattern unlock is entered by joining at least four points on a 3×3 matrix. Each point can be used only once (crossed points are disregarded) and the maximum number of points is nine. Internally, the pattern is stored as a byte sequence, with each point represented by its index, where 0 is top left and 8 is bottom right. Thus the pattern is similar to a PIN with a minimum of four and maximum of nine digits, which uses only nine distinct digits (0 to 8). However, because points cannot be repeated, the number of variations in an unlock pattern is considerably lower compared to those of a nine-digit PIN.

The hash for the pattern lock is stored in */data/system/gesture.key* (*/data/ system/users/<user ID>/gesture.key* on multi-user devices) as an unsalted SHA-1 value. By simply dumping this file, we can easily see that the contents of the *gesture.key* file for the pattern in [Figure 10-9](ch10.html#configuring_the_pattern_unlock_method "Figure 10-9. Configuring the Pattern unlock method") (represented as *00010204060708* in hexadecimal) shown in [Example 10-8](ch10.html#contents_of_the_solidusdatasolidussystem "Example 10-8. Contents of the /data/system/gesture.key file") matches the SHA-1 hash of the pattern byte sequence, which is *6a062b9b3452e366407181a1bf92ea73e9ed4c48* for this example.

Example 10-8. Contents of the /data/system/gesture.key file

```
# **od -t x1 /data/system/gesture.key**
0000000 6a 06 2b 9b 34 52 e3 66 40 71 81 a1 bf 92 ea 73
0000020 e9 ed 4c 48
```

Because a random salt value isn’t used when calculating the hash, each pattern is always hashed to the same value, which makes it relatively easy to generate a precomputed table of all possible patterns and their respective hashes. (Such tables are readily available online.) This allows for instant recovery of the pattern once the *gesture.key* file is obtained. However, the file is owned by the *system* user and its permissions are set to 0600, so recovery is not usually possible on production devices. The entered pattern is checked against the saved hash using the `checkPattern()` method of the `LockScreenUtils` class, and the pattern hash is calculated and persisted using the `saveLockPattern()` method of that class. Saving the pattern also sets the current password quality value to `DevicePolicyManager.PASSWORD_QUALITY_SOMETHING`.

Another unfortunate property of the pattern unlock method is that because capacitive touch screens are operated directly using a finger (not with a stylus or a similar tool), drawing the unlock pattern multiple times leaves a distinct trace on a touch screen, making it vulnerable to the so called “smudge attack.” Using appropriate lighting and cameras, finger smudges on the screen can be detected, and the unlock pattern can be inferred with a very high probability. For these reasons, the pattern unlock method’s security level is considered very low. In addition, because the number of combinations is limited, the unlock pattern is a poor source of entropy and is disallowed when the user’s unlock credential is used to derive an encryption key, such as those used for system’s keystore and device encryption.

Like Face Unlock, the pattern unlock method supports a backup unlock mechanism that is only made available after the user enters an invalid pattern more than five times. Backup authentication must be manually activated by pressing the Forgot Pattern button shown at the bottom of the lock-screen. After the button is pressed, the device goes into the `SecurityMode.Account` security mode and displays the screen shown in [Figure 10-11](ch10.html#google_account_unlock_mode "Figure 10-11. Google account unlock mode").

The user can enter the credentials of any Google account registered on the device to unlock it, and then reset or change the unlock method. Therefore, having a Google account with an easy to guess (or shared) password registered on the device could be a potential backdoor to the device’s lockscreen.

### Note

*As of this writing, Google accounts that have been configured to require two-factor authentication cannot be used to unlock the device.*

![Google account unlock mode](figs/web/10fig11.png.jpg)

Figure 10-11. Google account unlock mode

### PIN and Password Unlock

The PIN and password methods are essentially equivalent: they compare the hash of the user’s input to a salted hash stored on the device and unlock it if the values match. The hash of the PIN or password is a combination of the SHA-1 and MD5 hash values of the user input, salted with a 64-bit random value. The calculated hash is stored in the */data/misc/password.key* (/*data/system/users/<user ID>/password.key* on multi-user devices) file as a hexadecimal string and may look like [Example 10-9](ch10.html#contents_of_the_solidusdatasolidusmiscso "Example 10-9. Contents of the /data/misc/password.key file").

Example 10-9. Contents of the /data/misc/password.key file

```
# **cat /data/system/password.key && echo**
9B93A9A846FE2FC11D49220FC934445DBA277EB0AF4C9E324D84FFC0120D7BAE1041FAAC
```

The salt used for calculating the hash values was saved in the `secure` table of the system’s `SettingsProvider` content provider under the *lockscreen.password_salt* key in Android versions prior to 4.2, but was moved to a dedicated database, along with other lockscreen-related metadata in order to support multiple users per device. As of Android 4.4, the database is located in */data/system/locksettings.db* and is accessed via the `ILockSettings` AIDL interface of the `LockSettingsService`.

Accessing the service requires the `ACCESS_KEYGUARD_SECURE_STORAGE` signature permission, which is only allowed to system applications. The *locksettings.db* database has a single table, also called `locksettings`, which may contain data like [Example 10-10](ch10.html#contents_of_solidusdatasolidussy-id00023 "Example 10-10. Contents of /data/system/locksettings.db for the owner user") for a particular user (the `user` column contains the Android user ID).

Example 10-10. Contents of /data/system/locksettings.db for the owner user

```
sqlite> **select name, user, value from locksettings where user=0;**
name                              |user|value
--*snip*--
lockscreen.password_salt          |0   |6909501022570534487➊
--*snip*--
lockscreen.password_type_alternate|0   |0➋
lockscreen.password_type          |0   |131072➌
lockscreen.passwordhistory        |0   |5BFE43E89C989972EF0FA0EC00BA30F356EE7B
7C7BF8BC08DEA2E067FF6C18F8CD7134B8,EE29A531FE0903C2144F0618B08D1858473C50341A7
8DEA85D219BCD27EF184BCBC2C18C➍
```

Here, the *lockscreen.password_salt* setting ➊ stores the 64-bit (represented as a Java `long` type) salt value, and the *lockscreen.password_type_alternate* setting ➋ contains the type of the backup (also called alternate) unlock method type (0 means none) for the current unlock method. *lockscreen.password_type* ➌ stores the currently selected password type, represented by the value of the corresponding `PASSWORD_QUALITY` constant defined in the `DevicePolicyManager` class. In this example, 131072 (0x00020000 in hexadecimal) corresponds to the `PASSWORD_QUALITY_NUMERIC` constant, which is the password quality provided by a numeric PIN. Finally, *lockscreen.passwordhistory* ➍ contains the password history, saved as a sequence of previous PIN or password hashes, separated by commas. The history is only saved if the history length has been set to a value greater than zero using one of the `setPasswordHistoryLength()` methods of the `DevicePolicyManager` class. When password history is available, entering a new password that is the same as any password in the history is forbidden.

The password hash can be easily calculated by concatenating the password or PIN string (*1234* for this example) with the salt value formatted as a hexadecimal string (*5fe37a926983d657* for this example) and calculating the SHA-1 and MD5 hashes of the resulting string, as shown in [Example 10-11](ch10.html#calculating_a_pin_or_password_hash_using "Example 10-11. Calculating a PIN or password hash using sha1sum and md5sum").

Example 10-11. Calculating a PIN or password hash using sha1sum and md5sum

```
$ **SHA1=`echo -n '12345fe37a926983d657'|sha1sum|cut -d- -f1|tr '[a-z]' '[A-Z]'**➊
$ **MD5=`echo -n '12345fe37a926983d657'|md5sum|cut -d- -f1|tr '[a-z]' '[A-Z]'`**➋
$ **echo "$SHA1$MD5"|tr -d ' '**➌
9B93A9A846FE2FC11D49220FC934445DBA277EB0AF4C9E324D84FFC0120D7BAE1041FAAC
```

In this example the hashes are calculated using the `sha1sum` ➊ and `md5sum` ➋ commands. When concatenated ➌, the output of the two commands produces the string contained in the *password.key* file shown in [Example 10-9](ch10.html#contents_of_the_solidusdatasolidusmiscso "Example 10-9. Contents of the /data/misc/password.key file").

Note that while using a random hash makes it impossible to use a single precalculated table for brute-forcing the PIN or password of any device, calculating the password or hash requires a single hash invocation, so generating a targeted hash table for a particular device (assuming the salt value is also available) is still relatively cheap. Additionally, while Android calculates both the SHA-1 and MD5 hashes of the PIN or password, this provides no security value, as it is sufficient to target the shorter hash (MD5) in order to uncover the PIN or password.

The entered password is checked against the stored hash using the `LockPatternUtils.checkPassword()` method, and the hash of a user-supplied password is calculated and persisted using the one of the `saveLockPassword()` methods of that class. Calling `saveLockPassword()` updates the *password.key* file for the target (or current) user. Like *gesture.key*, this file is owned by the *system* user and has permissions 0600\. In addition to updating the password hash, `saveLockPassword()` calculates the complexity of the entered password and updates the `value` column corresponding to the *lockscreen.password_type* key (➌ in [Example 10-10](ch10.html#contents_of_solidusdatasolidussy-id00023 "Example 10-10. Contents of /data/system/locksettings.db for the owner user")) in *locksettings.db* with the calculated complexity value. If password history is enabled, `saveLockPassword()` also adds the PIN or password hash to the `locksettings` table (➍ in [Example 10-11](ch10.html#calculating_a_pin_or_password_hash_using "Example 10-11. Calculating a PIN or password hash using sha1sum and md5sum")).

Recall that when the device is encrypted, the PIN or password is used to derive a KEK that encrypts the disk encryption key. Therefore, changing the PIN or password of the owner user also re-encrypts the disk encryption key by calling the `changeEncryptionPassword()` method of the system’s `MountService`. (Changing the PIN or password of a secondary user does not affect the disk encryption key.)

### PIN and PUK Unlock

The PIN and PUK security modes are not lockscreen unlock methods per se because they depend on the state of the device’s SIM card and are only shown if the SIM card is in a locked state. A SIM card can require users to enter a preconfigured PIN code in order to unlock the card and get access to any network authentication keys stored inside, which are required to register with the mobile network and place non-emergency calls.

Because a SIM card retains its unlock state until reset, the PIN code typically must be entered only when the device first boots. If an incorrect code is entered more than three times, the SIM card locks and requires the user to enter a separate code to unlock it called the *PIN unlock key (PUK)*, or *personal unblocking code (PUC)*.

When the lockscreen is shown, Android checks the state of the SIM card, and if it’s `State.PIN_REQUIRED` (defined in the `IccCardConstants` class), it shows the SIM unlock keyguard view shown in [Figure 10-12](ch10.html#sim_unlock_screen "Figure 10-12. SIM unlock screen"). When the user enters a SIM unlock PIN, it’s passed to the `supplyPinReportResult()` method of the `ITelephony` interface (implemented in the `TeleService` system application), which in turn passes it to the device’s baseband processor (the device component that implements mobile network communication, also sometimes referred to as the *modem* or *radio*) via the radio interface daemon (*rild*). Finally, the baseband processor, which is directly connected to the SIM, sends the PIN to the SIM card and receives a status code in exchange. The status code is passed back to the unlock view via the same route. If the status code indicates that the SIM card accepted the PIN and no screen lock is configured, the home screen (launcher) is displayed next. If, on the other hand, a screen lock has been configured, it’s shown after unlocking the SIM card, and the user must enter their credentials in order to unlock the device.

![SIM unlock screen](figs/web/10fig12.png.jpg)

Figure 10-12. SIM unlock screen

If the SIM card is locked (that is, in the `PUK_REQUIRED` state), Android shows a PUK entry screen and allows the user to set up a new PIN after they unlock the card. The PUK and new PIN are passed to the `supplyPukReportResult()` method of the `ITelephony` interface, which delivers them to the SIM card. If a screen lock is configured, it is shown when the PUK is validated and the new PIN configured.

The `Keyguard` system application monitors SIM state changes by registering for the `TelephonyIntents.ACTION_SIM_ STATE_CHANGED` broadcast and shows the lockscreen if the card becomes locked or permanently disabled. Users can toggle the SIM card’s PIN protection by navigating to **Settings**▸**Security**▸ **Set up SIM card lock** and using the **Lock SIM card** checkbox.

![Rate limiting after five subsequent failed authentication attempts](figs/web/10fig13.png.jpg)

Figure 10-13. Rate limiting after five subsequent failed authentication attempts

## Brute-Force Attack Protection

Because complex passwords can be tricky to input on a touch screen keyboard, users typically use relatively short unlock credentials, which can easily be guessed or brute-forced. Android protects against brute-force attacks executed directly on the device (online attacks) by requiring users to wait 30 seconds after each five subsequent failed authentication attempts, as shown in [Figure 10-13](ch10.html#rate_limiting_after_five_subsequent_fail "Figure 10-13. Rate limiting after five subsequent failed authentication attempts"). This technique is referred to as *rate limiting*.

To further deter brute-force attacks, password complexity, expiration, and history rules can be set and enforced using the `DevicePolicyManager` API, as discussed in [Chapter 9](ch09.html "Chapter 9. Enterprise Security"). If the device stores or allows access to sensitive corporate data, device administrators can also set a threshold for the allowed failed authentication attempts using the `DevicePolicyManager.setMaximumFailedPasswordsForWipe()` method. When the threshold is reached, all user data on the device is automatically deleted, preventing attackers from gaining unauthorized access to it.

# Secure USB Debugging

One reason for Android’s success is the low entry barrier to application development; apps can be developed on any OS, in a high-level language, without the need to invest in developer tools or hardware (when using the Android emulator). Developing software for embedded or other dedicated devices has traditionally been difficult, because it’s usually hard (or in some cases impossible) to inspect a program’s internal state or otherwise interact with the device in order to debug programs.

Since its earliest versions, Android has included a powerful device interaction toolkit that allows interactive debugging and inspecting device state, called the *Android Debug Bridge (ADB)*. ADB is typically turned off on consumer devices, but can be turned on via the system UI in order to enable app development and debugging on the device. Because ADB provides privileged access to the device’s filesystem and applications, it can be used to obtain unauthorized access to data. In the following sections, we’ll discuss ADB’s architecture, then discuss the steps recent Android versions have taken to restrict access to ADB.

## ADB Overview

ADB keeps track of all devices (or emulators) connected to a host, and offers various services to its clients (command line clients, IDEs, and so on). It consists of three main components: the ADB server, the ADB daemon (*adbd),* and the default command-line client (`adb`). The ADB server runs on the host machine as a background process and decouples clients from the actual devices or emulators. It monitors device connectivity and sets their state appropriately (`CS_CONNECTED`, `CS_OFFLINE`, `CS_RECOVERY`, and so on).

The ADB daemon runs on an Android device (or emulator) and provides the actual services client use. It connects to the ADB server through USB or TCP/IP, and receives and processes commands from it. The `adb` command-line client lets you send commands to a particular device. In practice, it is implemented in the same binary as the ADB server and thus shares much of its code. [Figure 10-14](ch10.html#adb_architecture "Figure 10-14. ADB architecture") shows an overview of ADB’s architecture.

![ADB architecture](figs/web/10fig14.png.jpg)

Figure 10-14. ADB architecture

### Note

*In addition to the native implementation in the `adb` command and the Java-based one in the Android Development Tools (ADT) Eclipse plugin, various third-party implementations of the ADB protocol are also available, including a Python client*^([[108](#ftn.ch10fn09)]) *and an ADB server implemented in JavaScript,*^([[109](#ftn.ch10fn10)]) *which can be embedded in the Chrome browser as an extension.*

The client talks to the local ADB server via TCP (typically via *localhost:5037*) using text-based commands, and receives *OK* or *FAIL* responses in return. Some commands, like enumerating devices, port forwarding, or daemon restart are handled by the local daemon, while others (like shell or log access) require a connection to the target Android device. Device access is generally accomplished by forwarding input and output streams to/from the host. The transport layer that implements this uses simple messages with a 24-byte header, which contains a command identifier, two arguments, the length and CRC32 of the optional payload that follows, and a magic value, which simply flips all bits of the command. The message structure is defined in *system/core/adb/adb.h* and is shown in [Example 10-12](ch10.html#adb_message_structure "Example 10-12. ADB message structure") for reference. Messages are in turn encapsulated in packets, which are sent over the USB or TCP link to the ADB server running on the device.

Example 10-12. ADB message structure

```
struct amessage {
    unsigned command;       /* command identifier constant      */
    unsigned arg0;          /* first argument                   */
    unsigned arg1;          /* second argument                  */
    unsigned data_length;   /* length of payload (0 is allowed) */
    unsigned data_check;    /* checksum of data payload         */
    unsigned magic;         /* command ^ 0xffffffff             */
};
```

We won’t discuss the ADB protocol in more detail other than to note the authentication commands added to the protocol in order to implement secure USB debugging. (For more details on ADB, see the protocol description in the *system/core/adb/protocol.txt* file in Android’s source tree.)

### Note

*You can enable trace logs for all ADB services by setting the `ADB_TRACE` environment variable to 1 on the host and the `persist.adb.trace_mask` system property on the device. Selected services can be traced by setting the value of `ADB_TRACE` or `persist.adb.trace_mask` to a comma- or space-separated (columns or semi-columns as a separator are also supported) list of service tags. See* system/core/adb/adb.c *for the full list of supported tags.*

## The Need for Secure ADB

If you’ve done any development, you know that “debugging” is usually the exact opposite of “secure.” Debugging typically involves inspecting (and sometimes even changing) internal program state, dumping encrypted communication data to log files, universal root access, and other scary but necessary activities. Debugging is hard enough without having to bother with security, so why further complicate things by adding additional security layers? Android debugging, as provided by the ADB, is quite versatile and gives you almost complete control over a device when enabled. This feature is, of course, very welcome when developing or testing an application (or the OS itself), but it can also be used for other purposes.

Here’s a selective list of things ADB lets you do:

*   Copy files to and from the device

*   Debug apps running on the device (using JWDP or `gdbserver`)

*   Execute shell commands on the device

*   Get the system and apps logs

*   Install and remove apps

If debugging is enabled on a device, you can do all of the above and more (for example, inject touch events or input text in the UI) simply by connecting the device to a computer with a USB cable. Because ADB does not depend on the device’s screen lock, you don’t have to unlock the device in order to execute ADB commands, and on most devices that provide root access, connecting via ADB allows you to access and change every file, including system files and password databases. Worse, you don’t actually need a computer with development tools in order to access an Android device via ADB; another Android device and a USB On-The-Go (OTG) cable are sufficient. Android tools that can extract as much data as possible from another device in a very short time are readily available.^([[110](#ftn.ch10fn11)]) If the device is rooted, such tools can extract all of your credentials, disable or brute-force the screen lock, and even log into your Google account. But even without root, anything on external storage, most notably photos, is accessible, as are your contacts and text messages.

## Securing ADB

Android 4.2 was the first version to try to make ADB access harder by hiding the Developer options settings screen, requiring you to use a “secret knock” (tapping the build number seven times) in order to enable it. While not a very effective access protection method, it makes sure that most users don’t accidentally enable ADB access. This is, of course, only a stop-gap measure, and as soon as you manage to turn USB debugging on, your device is once again vulnerable.

![USB debugging authorization dialog](figs/web/10fig15.png.jpg)

Figure 10-15. USB debugging authorization dialog

Android 4.2.2 introduced a proper solution with the so-called secure USB debugging feature. “Secure” here refers to the fact that only hosts that are explicitly authorized by the user can now connect to the *adbd* daemon on the device and execute debugging commands. Thus if someone tries to connect a device to another one via USB in order to access ADB, they must first unlock the target device and authorize access from the debug host by clicking OK in the confirmation dialog shown in [Figure 10-15](ch10.html#usb_debugging_authorization_dialog "Figure 10-15. USB debugging authorization dialog").

You can make your decision persistent by checking the **Always allow from this computer** checkbox and debugging will work just as before, as long as you’re on the same machine.

Naturally, this secure USB debugging is only effective if you have a reasonably secure lockscreen password in place.

### Note

*On tablets with multi-user support, the confirmation dialog is only shown to the primary (owner) user.*

## Secure ADB Implementation

The ADB host authentication functionality is enabled by default when the *ro.adb.secure* system property is set to 1, and there is no way to disable it via the system interface. When a device connects to a host, it is initially in the `CS_UNAUTHORIZED` state and only goes into the `CS_DEVICE` state after the host has authenticated. Hosts use RSA keys in order to authenticate to the ADB daemon on the device, typically following this three-step process:

1.  When a host tries to connect, the device sends an `A_AUTH` message with an argument of type `ADB_AUTH_TOKEN` that includes a 20-byte random value (read from */dev/urandom/*).

2.  The host responds with an `A_AUTH` message with an argument of type `ADB_AUTH_SIGNATURE`, which includes a *SHA1withRSA* signature of the random token with one of the host’s private keys.

3.  The device tries to verify the received signature, and if signature verification succeeds, it responds with an `A_CNXN` packet and goes into the `CS_DEVICE` state. If verification fails, either because the signature value doesn’t match, or because there is no corresponding public key to verify with, the device sends another `ADB_AUTH_TOKEN` with a new random value so that the host can try authenticating again (slowing down if the number of failures goes over a certain threshold).

Signature verification typically fails the first time you connect the device to a new host because it doesn’t yet have the host’s key. In that case the host sends its public key in an `A_AUTH` message with an `ADB_AUTH_RSAPUBLICKEY` argument. The device takes the MD5 hash of that key and displays it in the *Allow USB debugging confirmation* dialog shown in [Figure 10-15](ch10.html#usb_debugging_authorization_dialog "Figure 10-15. USB debugging authorization dialog"). Since *adbd* is a native daemon, the key must be passed to the main Android OS in order for its hash to be displayed on screen. This is accomplished by simply writing the key to a local socket (also named *adbd*), which the *adbd* daemon monitors.

When you enable ADB debugging from the developer settings screen, a thread that listens to that *adbd* socket is started. When the thread receives a message starting with *PK*, it treats it as a public key, parses it, calculates the MD5 hash and displays the confirmation dialog (implemented in a dedicated activity, `UsbDebuggingActivity`, part of the SystemUI package). If you tap OK, the activity sends a simple *OK* response to *adbd*, which uses the key to verify the authentication message. If you check the Always allow from this computer checkbox, the public key is written to disk and automatically used for signature verification the next time you connect to the same host.

### Note

*As of version 4.3, Android allows you to clear all saved host authentication keys. This functionality can be triggered by selecting Settings*▸*Developer options*▸*Revoke USB debugging authorizations.*

The `UsbDeviceManager` class provides public methods for allowing and denying USB debugging, clearing cached authentication keys, as well as for starting and stopping the *adbd* daemon. Those methods are made available to other applications via the `IUsbManager` AIDL interface of the system `UsbService`. Calling `IUsbManager` methods that modify device state requires the `MANAGE_USB` system signature permission.

## ADB Authentication Keys

Although we described the ADB authentication protocol above, we haven’t said much about the actual keys used in the process: 2048-bit RSA keys generated by the local ADB server. These keys are typically stored in *$HOME/.android* (*%USERPOFILE%\.android* on Windows) as *adbkey* (private key) and *adbkey.pub* (public key). The default key directory can be overridden by setting the `ANDROID_SDK_HOME` environment variable. If the `ADB_VENDOR_KEYS` environment variable is set, the directory it points to is also searched for keys. If no keys are found in any of the above locations, a new key pair is generated and saved.

The private key file (*adbkey*), which is only stored on the host, is in standard OpenSSL PEM format. The public key file (*adbkey.pub*) contains the Base 64–encoded mincrypt-compatible representation of the public key, which is basically a serialization of mincrypt’s `RSAPublicKey` structure (see “[Enabling Verified Boot](ch10.html#enabling_verified_boot "Enabling Verified Boot")”), followed by a *user@host* user identifier, separated by space. The user identifier doesn’t seem to be used as of this writing and is only meaningful on Unix-based OSes; on Windows, it is always *unknown@unknown*.

Keys are stored on the device in the */data/misc/adb/adb_keys/* file, and new authorized keys are appended to the same file as you accept them. Read-only “vendor keys” are stored in the */adb_keys* file, but it doesn’t seem to exist on current Nexus devices. Public keys are in the same format as on the host, making it easy to load in libmincrypt, which *adbd* links statically. [Example 10-13](ch10.html#contents_of_the_adbunderscorekeys_file "Example 10-13. Contents of the adb_keys file") shows some sample *adb_keys*. The file is owned by the *system* user, its group is set to *shell*, and its permissions to 0640.

Example 10-13. Contents of the adb_keys file

```
# **cat data/misc/adb/adb_keys**
QAAAAJs1UDFt17wyV+Y2GNGF+EgWoiPfsByfC4frNd3s64w3IGt25fKERnl7O8/A+iVPGv1W
--*snip*--
yZ61cFd7R6ohLFYJRPB6Dy7tISUPRpb+NF4pbQEAAQA= unknown@unknown
QAAAAKFLvP+fp1cB4Eq/6zyV+hnm1S1eV9GYd7cYe+tmwuQZFe+O4vpeow6huIN8YbBRkr7
--*snip*--
m7+bGd6F0hRkO82gopy553xywXU7rI/aMl6FBAEAAQA= user1@host2
```

## Verifying the Host Key Fingerprint

While the USB debugging confirmation dialog helpfully displays a key fingerprint to let you verify that you’re connected to the expected host, the `adb` client doesn’t have a handy command to print the fingerprint of the host key. Although it may seem that there’s little room for confusion (after all, there is only one cable plugged in to a single machine) when running a couple of VMs, things can get a little fuzzy. [Example 10-14](ch10.html#displaying_the_host_keyapostrophes_finge "Example 10-14. Displaying the host key’s fingerprint") shows one way to display the host key’s fingerprint in the same format used by the confirmation dialog shown in [Figure 10-15](ch10.html#usb_debugging_authorization_dialog "Figure 10-15. USB debugging authorization dialog") (run in *$HOME/.android* or specify the full path to the public key file).

Example 10-14. Displaying the host key’s fingerprint

```
$ **cut -d' ' -f1 adbkey.pub|openssl base64 -A -d -a | \**
**openssl md5 -c|cut -d' ' -f2|tr '[a-z]' '[A-Z]'**
69:D4:AC:0D:AF:6B:17:88:BA:6B:C4:BE:0C:F7:75:9A
```

# Android Backup

Android includes a backup framework that allows application data to be backed up to Google’s cloud storage and supports full backup of installed APK files, application data, and external storage files to a host machine connected via USB. While device backup is not exactly a security feature, backups allow application data to be extracted from the device, which can present a security issue.

## Android Backup Overview

Android’s backup framework was publicly announced in Android 2.2, but it was probably available internally earlier. The framework lets applications declare special components called *backup agents*, which are called by the system when creating a backup for an application and when restoring its data. While the backup framework did support pluggable backup transports internally, initially the only transport that was usable in practice was a proprietary one that stores application data in Google’s cloud storage.

### Cloud Backup

Because backups are associated with a user’s Google account, when they install an application that has a backup agent on a new device, the application’s data can be automatically restored if the user has registered the same Google account as the one used when the backup was created. Backup and restore is managed by the system and cannot typically be triggered or controlled by users (though developer commands that trigger cloud backup are accessible via the Android shell). By default, backups are triggered periodically, and restore only when an app is first installed on a device.

### Local Backup

Android 4.0 added a new, local backup transport that lets users save backups to a file on their desktop computer as well. Local backup (also called full backup) requires ADB debugging to be enabled and authorized because backup data is streamed to the host computer using the same method that ADB (via `adb pull`) employs to transfer device files to a host.

![Backup confirmation dialog](figs/web/10fig16.png.jpg)

Figure 10-16. Backup confirmation dialog

Full backup is started by executing the `adb backup` command in a shell. This command starts a new Java process on the device, which binds to the system’s `BackupManagerService` and requests a backup with the parameters specified to `adb backup`. The `BackupManagerService` in turn starts a confirmation activity like the one shown in [Figure 10-16](ch10.html#backup_confirmation_dialog "Figure 10-16. Backup confirmation dialog"), prompting the user to authorize the backup and specify a backup encryption password if desired. If the device is already encrypted, the user must enter the device encryption password to proceed. This password will be used to encrypt the backup as well, because using a dedicated backup encryption password is not supported. The full backup process is started when the user presses the Back up my data button.

Full backup calls the backup agent of each target package in order to obtain a copy of its data. If a backup agent is not defined, the `BackupManagerService` uses an internal `FullBackupAgent` class, which copies all of the package’s files. Full backup honors the `allowBackup` attribute of the `<application>` tag in the package’s *AndroidManifest.xml* file, and will not extract package data if `allowBackup` is set to `false`.

In addition to application data, full backup can include user-installed and system application APK files, as well as external storage contents, with some limitations: full backup doesn’t back up protected (with DRM) apps, and skips some system settings such as mobile network APNs and Wi-Fi access points’ connection details.

Backups are restored using the `adb restore` command. Backup restore is quite limited and doesn’t allow any options to be specified, as it can only perform a full restore.

## Backup File Format

Android backup files start with a few lines of text, followed by binary data. These lines are the backup header and they specify the backup format and encryption parameters (if a backup password was specified) used to create the backup. The header of an unencrypted backup is shown in [Example 10-15](ch10.html#unencrypted_backup_header "Example 10-15. Unencrypted backup header").

Example 10-15. Unencrypted backup header

```
ANDROID BACKUP➊
1➋
1➌
none➍
```

The first line ➊ is the file magic (format identifier), the second ➋ is the backup format version (1 up till Android 4.4.2, 2 in later versions; version 2 denotes a change in the key derivation method, which now takes into account multibyte password characters), the third ➌ is a compression flag (1 if compressed), and the last ➍ is the encryption algorithm used (*none* or *AES-256*).

The actual backup data is a compressed and optionally encrypted tar file that includes a backup manifest file, followed by the application APK (if any), and app data (files, databases, and shared preferences). The data is compressed using the deflate algorithm and can be decompressed using OpenSSL’s `zlib` command, as shown in [Example 10-16](ch10.html#uncompressing_an_android_backup_using_op "Example 10-16. Uncompressing an Android backup using OpenSSL").

Example 10-16. Uncompressing an Android backup using OpenSSL

```
$ **dd if=mybackup.ab bs=24 skip=1|openssl zlib -d > mybackup.tar**
```

After the backup is uncompressed, you can view its contents or extract it with the standard `tar` command, as shown in [Example 10-17](ch10.html#viewing_the_contents_of_an_uncompressed "Example 10-17. Viewing the contents of an uncompressed backup using tar").

Example 10-17. Viewing the contents of an uncompressed backup using `tar`

```
$ **tar tvf mybackup.tar**
-rw------- 1000/1000          1019 apps/org.myapp/_manifest➊
-rw-r--r-- 1000/1000       1412208 apps/org.myapp/a/org.myapp-1.apk➋
-rw-rw---- 10091/10091         231 apps/org.myapp/f/share_history.xml➌
-rw-rw---- 10091/10091           0 apps/org.myapp/db/myapp.db-journal➍
-rw-rw---- 10091/10091        5120 apps/org.myapp/db/myapp.db
-rw-rw---- 10091/10091        1110 apps/org.myapp/sp/org.myapp_preferences.xml➎
```

Inside the tar file, app data is stored in the *apps/* directory, which contains a subdirectory for each backed-up package. Each package directory includes a *_manifest* file ➊ in its root, the APK file (if requested) in *a/* ➋, app files in *f/* ➌, databases in *db/* ➍, and shared preferences in *sp/* ➎. The manifest contains the app’s package name and version code, the platform’s version code, a flag indicating whether the archive contains the app APK, and the app’s signing certificate.

The `BackupManagerService` uses this information when restoring an app in order to check whether it’s been signed with the same certificate as the currently installed one. If the certificates don’t match, it will skip installing the APK, except for system packages, which might be signed with a different (manufacturer-owned) certificate on different devices. Additionally, `BackupManagerService` expects the files to be in the order shown in [Example 10-17](ch10.html#viewing_the_contents_of_an_uncompressed "Example 10-17. Viewing the contents of an uncompressed backup using tar") and restore will fail if they are out for order. For example, if the manifest states that the backup includes an APK, the `BackupManagerService` will try to read and install the APK first, before restoring the app’s files. This restore order is required because you cannot restore files for an app you don’t have installed. However, `BackupManagerService` will not search for the APK in the archive, and if it is not right after the manifest, all other files will be skipped.

If the user requested external storage backup (by passing the `-shared` option to `adb backup`), there will also be a *shared/* directory in the archive, containing external storage files.

## Backup Encryption

If the user supplied an encryption password when requesting the backup, the backup file is encrypted with a key derived from the password. The password is used to generate a 256-bit AES key using 10,000 rounds of PBKDF2 with a randomly generated 512-bit salt. This key is then used to encrypt another, randomly generated 256-bit AES bit master key, which is in turn used to encrypt the actual archive data in CBC mode (using the *AES/CBC/PKCS5Padding* `Cipher` transformation). A master key checksum is also calculated and saved in the backup file header. In order to generate the checksum, the generated raw master key is converted to a Java character array by casting each byte to `char`, with the result treated as a password string, and run through the PBKDF2 function to effectively generate another AES key, whose bytes are used as the checksum.

### Note

*Because an AES key is essentially a random byte sequence, the raw key usually contains several bytes that don’t map to printable characters. Because PKCS#5 does not specify the actual encoding of a password string, Android’s encryption checksum generation method produces implementation and version-dependent results.*

The checksum is used to verify whether the user-supplied decryption password is correct before actually decrypting the backup data. When the master key is decrypted, its checksum is calculated using the method described above and then compared to the checksum in the archive header. If the checksums don’t match, the password is considered incorrect, and the restore process is aborted. [Example 10-18](ch10.html#encrypted_backup_header "Example 10-18. Encrypted backup header") shows an example backup header for an encrypted archive.

Example 10-18. Encrypted backup header

```
ANDROID BACKUP
1
1
AES-256➊
68404C30DF8CACA5FA004F49BA3A70...➋
909459ADCA2A60D7C2B117A6F91E3D...➌
10000➍
789B1A01E3B8FA759C6459AF1CF1F0FD ➎
8DC5E483D3893EC7F6AAA56B97A6C2...➏
```

Here, *AES-256* ➊ is the backup encryption algorithm used, the next line ➋ is the user password salt as a hexadecimal string, followed by the master key checksum salt ➌, the number of PBKDF2 rounds used to derive a key ➍, and the user key IV ➎. The final line ➏ is the master key blob, which contains the archive data encryption IV, the actual master key and its checksum, all encrypted with the key derived from the user-supplied password. [Example 10-19](ch10.html#master_key_blob_format "Example 10-19. Master key blob format") shows the detailed format of the master key blob.

Example 10-19. Master key blob format

```
byte Niv➊
byte[Niv] IV➋
byte Nmk➌
byte [Nmk] MK➍
byte Nck➎
byte [Nck] MKck➏
```

The first field ➊ is the IV length, followed by the IV value ➋, the master key (MK) length ➌, and the actual master key ➍. The last two fields store the master key checksum hash length ➎, and the master key checksum hash itself ➏.

## Controlling Backup Scope

Android’s security model guarantees that each application runs within its own sandbox and that its files cannot be accessed by other applications or the device user, unless the application explicitly allows access. Therefore, most applications do not encrypt their data before storing it to disk. However, both legitimate users and attackers that have somehow obtained the device unlock password can easily extract applications data using Android’s full backup feature. For this reason, applications that store sensitive data should either encrypt it or provide an explicit backup agent that limits exportable data in order to guarantee that sensitive data cannot be easily extracted via backup.

As mentioned in “[Android Backup Overview](ch10.html#android_backup_overview "Android Backup Overview")”, if application data backup isn’t needed or desirable, applications can disallow it completely by setting their `allowBackup` attribute to `false` in *AndroidManifest.xml*, as shown in [Example 10-20](ch10.html#disallowing_application_data_backup_in_a "Example 10-20. Disallowing application data backup in AndroidManifest.xml").

Example 10-20. Disallowing application data backup in AndroidManifest.xml

```
<xml version="1.0" encoding="utf-8"?>
<manifest 
   package="org.example.app"
   android:versionCode="1"
   android:versionName="1.0" >
   --*snip*--
   <application
       android:icon="@drawable/ic_launcher"
       android:label="@string/app_name"
       android:theme="@style/AppTheme"
       android:allowBackup="false">
        --*snip*-
    </application>
</manifest>
```

# Summary

Android employs various measures in order to protect user data and applications, and ensure the integrity of the operating system. On production devices, the bootloader is locked, and the recovery OS only allows OTA updates signed by the device manufacturer to be installed, thus ensuring that only authorized OS builds can be booted or flashed to a device. When enabled, dm-verity-based verified boot guarantees that the *system* partition is not modified by checking the hash value of each device block against a trusted hash tree, which prevents the installation of malicious programs such as rootkits on the *system* partition. Android can also encrypt the *userdata* partition, making it harder to extract applications data by directly accessing storage devices.

Android supports various screen lock methods and applies rate limiting to unsuccessful authentication attempts, thus deterring online attacks against a booted device. The type and complexity of the unlock PIN or password can be specified and enforced by device administrator applications. A device policy that wipes the device after too many unsuccessful authentication attempts is also supported. Secure USB debugging requires debug hosts to be explicitly authorized by the user and added to a whitelist, thus preventing information extraction via USB.

Finally, full device backups can be encrypted with a key derived from a user-supplied password, making it harder to access device data that has been extracted into a backup. To achieve a higher level of device security, all supported security measures should be enabled and configured accordingly.

* * *

^([[100](#ch10fn01)]) Milan Broz, “dm-verity: device-mapper block integrity checking target,” *[https://code.google.com/p/cryptsetup/wiki/DMVerity](https://code.google.com/p/cryptsetup/wiki/DMVerity)*

^([[101](#ch10fn02)]) Red Hat, Inc., “Device-Mapper Resource Page,” *[https://www.sourceware.org/dm/](https://www.sourceware.org/dm/)*

^([[102](#ch10fn03)]) Google, “dm-verity on boot,” *[https://source.android.com/devices/tech/security/dm-verity.html](https://source.android.com/devices/tech/security/dm-verity.html)*

^([[103](#ch10fn04)]) Google, *Android 4.4 Compatibility Definition*, “9.9\. Full-Disk Encryption,” *[https://static.googleusercontent.com/media/source.android.com/en//compatibility/4.4/android-4.4-cdd.pdf](https://static.googleusercontent.com/media/source.android.com/en//compatibility/4.4/android-4.4-cdd.pdf)*

^([[104](#ch10fn05)]) Milan Broz, “dm-crypt: Linux kernel device-mapper crypto target,” *[https://code.google.com/p/cryptsetup/wiki/DMCrypt](https://code.google.com/p/cryptsetup/wiki/DMCrypt)*

^([[105](#ch10fn06)]) Jakob Lell, “Practical malleability attack against CBC-Encrypted LUKS partitions,” *[http://www.jakoblell.com/blog/2013/12/22/practical-malleability-attack-against-cbc-encrypted-luks-partitions/](http://www.jakoblell.com/blog/2013/12/22/practical-malleability-attack-against-cbc-encrypted-luks-partitions/)*

^([[106](#ch10fn07)]) C. Percival and S. Josefsson, *The scrypt Password-Based Key Derivation Function*, *[http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01/](http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01/)*

^([[107](#ch10fn08)]) Demonstrated by viaForensics in the “Into The Droid” talk, presented at DEF CON 20\. Slides are available at *[https://www.defcon.org/images/defcon-20/dc-20-presentations/Cannon/DEFCON-20-Cannon-Into-The-Droid.pdf](https://www.defcon.org/images/defcon-20/dc-20-presentations/Cannon/DEFCON-20-Cannon-Into-The-Droid.pdf)*

^([[108](#ch10fn09)]) Anthony King, “PyAdb: basic ADB core for python using TCP,” *[https://github.com/cybojenix/PyAdb/](https://github.com/cybojenix/PyAdb/)*

^([[109](#ch10fn10)]) Kenny Root, “adb-on-chrome: ADB (Android Debug Bridge) server as a Chrome extension,” *[https://github.com/kruton/adb-on-chrome/](https://github.com/kruton/adb-on-chrome/)*

^([[110](#ch10fn11)]) Kyle Osborn, “p2p-adb Framework,” *[https://github.com/kosborn/p2p-adb/](https://github.com/kosborn/p2p-adb/)*
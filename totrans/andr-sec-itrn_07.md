# Chapter 7. Credential Storage

The previous chapter introduced PKI and the challenges involved in managing trust. While the most prevalent use of PKI is for authenticating the entity you connect to (*server authentication*), it’s also used to authenticate you to those entities (*client authentication*). Client authentication is mostly found in enterprise environments, where it is used for everything from desktop logon to remotely accessing company servers. PKI-based client authentication requires the client to prove that it possesses an authentication key (typically an RSA private key) by performing certain cryptographic operations that the server can verify independently. Therefore, the security of client authentication relies heavily on protecting authentication keys from unauthorized use.

Most operating systems provide a system service that applications can use to securely store and access authentication keys without having to implement key protection themselves. Android has had such a service since version 1.6, and it has improved significantly since Android 4.0.

Android’s credential store can be used to store credentials for built-in features such as Wi-Fi and VPN connectivity, as well as for third-party apps. Apps can access the credential store via standard SDK APIs and use it to manage their keys securely. Recent Android versions feature hardware-backed key storage, which provides enhanced key protection. This chapter discusses the architecture and implementation of Android’s credential store and introduces the public APIs that it provides.

# VPN and Wi-Fi EAP Credentials

*Virtual Private Networks (VPNs)* are the preferred way to offer remote access to private enterprise services. We’ll discuss VPNs and related technologies in more detail in [Chapter 9](ch09.html "Chapter 9. Enterprise Security"), but simply put, a VPN allows a remote client to join a private network by creating an encrypted tunnel between it and a public tunnel endpoint. VPN implementations differ in their use of tunneling technology, but all need to authenticate the client before they establish a secure connection. While some VPNs use a shared key or password for authentication, enterprise solutions often rely on PKI-based client authentication.

*Extensible Authentication Protocol (EAP)* is an authentication framework frequently used in wireless networks and point-to-point (P2P) connections. (EAP is discussed in more detail in [Chapter 9](ch09.html "Chapter 9. Enterprise Security").) Like VPN, EAP can use many different authentication methods, but EAP-Transport Layer Security (EAP-TLS) is preferred in enterprise environments, especially when a company PKI has already been deployed.

## Authentication Keys and Certificates

In the case of both EAP-TLS and PKI-based VPNs, clients have an authentication key and are issued a matching certificate, often by the company certificate authority (CA). Keys are sometimes stored in a portable, tamper-resistant device such as a smart card or USB token. This greatly increases security because keys cannot be exported or extracted from the device and thus authentication requires both physical possession of the token and the knowledge of the associated PIN or passphrase.

When the security policy allows using authentication keys that are not protected by a hardware device, keys and associated certificates are typically stored in the standard PKCS#12 file format. Private keys stored in PKCS#12 files are encrypted with a symmetric key derived from a user-supplied password, and thus extracting the keys requires knowledge of the password. Some applications use PKCS#12 files as secure containers and only extract keys and certificates into memory when required, but typically they’re imported into a system- or application-specific credential storage before use. This is how Android works as well.

The user-facing implementation of importing credentials on Android is rather simple: to import an authentication key and related certificates, users copy their PKCS#12 files (and, if necessary, any related CA certificates) to the device’s external storage (often an SD card) and select **Install from storage** from the **Security** system settings screen. Android searches the root of the external storage for matching files (with the *.pfx* or *.p12* extensions) and presents an import dialog (see [Figure 7-1](ch07.html#pkcshash12_file_password_dialog "Figure 7-1. PKCS#12 file password dialog")). If the correct password is supplied, keys are extracted from the PKCS#12 file and imported into the system credential store.

## The System Credential Store

The system credential store is a system service that encrypts imported credentials before storing them on disk. The encryption key is derived from a user-supplied password: a dedicated credential store protection password in pre-4.0 versions, or the device unlock swipe pattern, PIN, or password in post-4.0 versions of Android. Additionally, the credential store system service regulates access to stored credentials and guarantees that only apps explicitly granted access can access keys.

The original credential store was introduced in Android 1.6 and was limited to storing VPN and Wi-Fi EAP credentials. Only the system—not third-party apps—could access stored keys and certificates. Additionally, the only supported way to import credentials was to go through the system settings UI outlined in the previous section, and no public APIs for credential store management were available.

APIs for accessing the system credential store were first introduced in Android 4.0\. The system credential store was later extended to support hardware-backed credential storage and to offer not only shared system keys, but app-private keys as well. [Table 7-1](ch07.html#credential_store_feature_progression "Table 7-1. Credential Store Feature Progression") shows a summary of the major credential store enhancements added in each Android version. We’ll introduce these enhancements and the related APIs in the following sections.

![PKCS#12 file password dialog](figs/web/07fig01.png.jpg)

Figure 7-1. PKCS#12 file password dialog

Table 7-1. Credential Store Feature Progression

| Android version | API level | Credential store changes |
| --- | --- | --- |
| 1.6 | 4 | Added credential store for VPN and Wi-Fi. |
| 4.0 | 14 | Added public API for credential store (`KeyChain` API). |
| 4.1 | 16 | Added the ability to generate and use keys without exporting them. Introduced keymaster HAL module and initial support for hardware-backed RSA key storage. |
| 4.3 | 18 | Added support for generating and accessing app-private keys using the *AndroidKeyStore* JCA provider, and APIs to check whether the device supports hardware-backed key storage for RSA keys. |
| 4.4 | 19 | Added ECDSA and DSA support to the *AndroidKeyStore* JCA provider. |

# Credential Storage Implementation

We now know that Android can encrypt imported credentials and manage access to them. Let’s see how this is implemented under the hood.

## The keystore Service

Credential storage management in Android was originally implemented by a single native daemon called *keystore*. Its functionality was initially limited to storing arbitrary blobs in encrypted form and verifying the credential store password, but it was extended with new features as Android evolved. It offered a local socket-based interface to its clients, and each client was responsible for managing their own state and socket connections. The *key-store* daemon was replaced with a centralized Binder service in Android 4.3 in order to better integrate it with other framework services and facilitate extension. Let’s see how this *keystore* service works.

The *keystore* service is defined in *init.rc*, as shown in [Example 7-1](ch07.html#keystore_service_definition_in_initdotrc "Example 7-1. keystore service definition in init.rc").

Example 7-1. keystore service definition in init.rc

```
service keystore /system/bin/keystore /data/misc/keystore
    class main
    user keystore
    group keystore drmrpc
```

As you can see, the *keystore* service runs as a dedicated *keystore* user and stores its files in */data/misc/keystore/*. Let’s peek into */data/misc/keystore/* first. If you’re using a single-user device, such as a phone, you will only find a single *user_0/* directory inside the *keystore/* directory (see [Example 7-2](ch07.html#sample_contents_of_the_keystore_director "Example 7-2. Sample contents of the keystore directory on a single-user device"), timestamps removed), but on multi-user enabled devices you should find one directory for each Android user.

Example 7-2. Sample contents of the keystore directory on a single-user device

```
# **ls -la /data/misc/keystore/user_0**
-rw------- keystore keystore       84 .masterkey
-rw------- keystore keystore      980 1000_CACERT_cacert
-rw------- keystore keystore      756 1000_USRCERT_test
-rw------- keystore keystore      884 1000_USRPKEY_test
-rw------- keystore keystore      724 10019_USRCERT_myKey
-rw------- keystore keystore      724 10019_USRCERT_myKey1
```

In this example, each file name consists of the UID of the app that created it (1000 is *system*), the entry type (CA certificate, user certificate, or private key), and the key name (alias), all connected with underscores. Since Android 4.3, system and app-private keys are supported as well, and the UID reflects the Android user ID as well as the app ID. On multi-user devices the user ID is `UID / 100000`, as discussed in [Chapter 4](ch04.html "Chapter 4. User Management").

In addition to system or app-owned key blobs, there is also a single *.masterkey* file, which we’ll discuss shortly. When an app that owns store-managed keys is uninstalled for a user, only keys created by that user are deleted. If an app is completely removed from the system, its keys are deleted for all users. Because key access is tied to the app ID, this feature prevents a different app that happens to get the same UID from accessing an uninstalled app’s keys. (Keystore reset, which deletes both key files and the master key, also affects only the current user.)

In the default software-based implementation, these files have the following contents (contents may be different for hardware-backed implementations; instead of encrypted key material, they often store only a reference to hardware-managed key objects):

*   The master key (stored in *.masterkey*) is encrypted with a 128-bit AES key derived from the screen unlock password by applying the *PBKDF2* key derivation function with 8192 iterations and a randomly generated 128-bit salt. The salt is stored in the *.masterkey* file’s info header.

*   All other files store key blobs. A *key blob* (binary large object) contains a serialized, optionally encrypted key along with some data that describes the key (metadata). Each keystore key blob contains a metadata header, the initial vector (IV) used for encryption, and a concatenation of an MD5 hash value of the data with the data itself, encrypted with the 128-bit AES master key in CBC mode. Or more concisely: `metadata || Enc(MD5(data) || data)`.

In practice, this architecture means that the Android keystore is pretty secure for a software solution. Even if you had access to a rooted device and managed to extract the key blobs, you would still need the keystore password to derive the master key. Trying different passwords in an attempt to decrypt the master key would require at least 8192 iterations to derive a key, which is prohibitively expensive. In addition, because the derivation function is seeded with a 128-bit random number, pre-calculated password tables cannot be used. However, the MD5-based integrity mechanism used does not employ a standard Message Authentication Code (MAC) algorithm such as HMAC and is a remnant of the original implementation. It’s kept for backward compatibility, but may be replaced in a future version.

## Key Blob Versions and Types

Beginning with Android 4.1, two fields were added to key blobs: *version* and *type*. The current version (as of Android 4.4) is *2* and keys blobs are automatically upgraded to the latest version when an application first accesses them. As of this writing, the following key types are defined:

*   `TYPE_ANY`

*   `TYPE_GENERIC`

*   `TYPE_MASTER_KEY`

*   `TYPE_KEY_PAIR`

`TYPE_ANY` is a meta key type that matches any key type. `TYPE_GENERIC` is used for key blobs that are saved using the original get/put interface, which stores arbitrary binary data, and `TYPE_MASTER_KEY` is, of course, only used for the keystore master key. The `TYPE_KEY_PAIR` type is used for key blobs created using the `generate_keypair` and `import_keypair` operations, newly introduced in Android 4.1\. We’ll discuss these in the “[keymaster Module and keystore Service Implementation](ch07.html#keymaster_module_and_keystore_service_im "keymaster Module and keystore Service Implementation")” section.

Android 4.3 is the first version to use the `flags` field of key blobs. It uses this field to distinguish encrypted (the default) from non-encrypted key blobs. Key blobs that are protected by a hardware-based implementation (available on some devices) are stored without additional encryption.

## Access Restrictions

Key blobs are owned by the *keystore* user, so on a regular (not rooted) device, you need to go through the *keystore* service in order to access them. The *keystore* service applies the following access restrictions:

*   The *root* user cannot lock or unlock the keystore, but can access system keys.

*   The *system* user can perform most keystore management operations (like initialization, reset, and so on) in addition to storing keys. However, the *system* user cannot use or retrieve other users’ keys.

*   Non-system users can insert, delete, and access keys, but can only see their own keys.

Now that we know what the *keystore* service does, let’s look at the actual implementation.

## keymaster Module and keystore Service Implementation

While the original daemon-based implementation included both key blob management and encryption in a single binary, Android 4.1 introduced a new *keymaster Hardware Abstraction Layer (HAL)* system module responsible for generating asymmetric keys and signing/verifying data without the need to export the keys first.

The *keymaster* module is meant to decouple the *keystore* service from the underlying asymmetric key operations implementation and to allow for easier integration of device-specific, hardware-backed implementations. A typical implementation would use a vendor-provided library to communicate with the crypto-enabled hardware and provide a “glue” HAL library, which the *keystore* daemon links with.

Android also comes with a default *softkeymaster* module that performs all key operations in software only (using the system OpenSSL library). This module is used on the emulator and included in devices that lack dedicated cryptographic hardware. The key size of generated keys was initially fixed at 2048 bits and only RSA keys were supported. Android 4.4 added support for specifying key size, as well as the Digital Signature Algorithm (DSA) and Elliptic Curve DSA (ECDSA) algorithms and their respective keys.

As of this writing, the default *softkeymaster* module supports RSA and DSA keys with sizes between 512 and 8192 bits. If the key size is not explicitly specified, DSA keys default to 1024 bits, and RSA ones to 2048 bits. For EC keys, the key size is mapped to a standard curve with the respective field size. For example, when 384 is specified as the key size, the *secp384r1* curve is used to generate keys. Currently the following standard curves are supported: *prime192v1*, *secp224r1*, *prime256v1*, *secp384r1*, and *secp521r1*. Keys for each of the supported algorithms can be imported as well if they are converted to the standard PKCS#8 format.

The HAL module interface is defined in *hardware/keymaster.h* and defines the operations listed below.

*   `generate_keypair`

*   `import_keypair`

*   `sign_data`

*   `verify_data`

*   `get_keypair_public`

*   `delete_keypair`

*   `delete_all`

All asymmetric key operations exposed by the *keystore* service are implemented by calling the system *keymaster* module. Thus if the *keymaster* HAL module is backed by a hardware cryptographic device, all upper-level commands and APIs that use the *keystore* service interface automatically get to use hardware crypto. Aside from asymmetric key operations, all other credential store operations are implemented by the *keystore* system service and do not depend on HAL modules. The service registers itself to Android’s `ServiceManager` with the *android.security.keystore* name and is started at boot. Unlike most Android services, it is implemented in C++ and the implementation resides in *system/security/keystore/*.

## Nexus 4 Hardware-Backed Implementation

To give some perspective to the whole “hardware-backed” idea, let’s briefly discuss how it’s implemented on the Nexus 4\. The Nexus 4 is based on Qualcomm’s Snapdragon S4 Pro APQ8064 system on a chip (SoC). Like most recent ARM SoCs, it is TrustZone-enabled, with Qualcomm’s Secure Execution Environment (QSEE) implemented on top of that.

ARM’s TrustZone technology provides two virtual processors backed by hardware-based access control, which allows a SoC system to be partitioned into two virtual “worlds”: the *Secure world* for the security subsystem, and the *Normal world* for everything else. Applications running in the Secure world are referred to as *trusted applications* and can only be accessed by Normal world applications (which the Android OS and apps run in) through a limited interface that they explicitly expose. [Figure 7-2](ch07.html#trustzone_software_architecture "Figure 7-2. TrustZone software architecture") shows a typical software configuration for a TrustZone-enabled system.

![TrustZone software architecture](figs/web/07fig02.png.jpg)

Figure 7-2. TrustZone software architecture

As usual, implementation details are quite scarce, but on the Nexus 4 the only way to interact with trusted applications is through the controlled interface that the */dev/qseecom* device provides. Android applications that wish to interact with the QSEE load the proprietary *libQSEEComAPI.so* library and use its functions to send commands to the QSEE.

As with most other SEEs, the *QSEECom* communication API is quite low level and basically only allows for exchanging opaque blobs (typically commands and replies), the contents of which depend entirely on the secure app you’re communicating with. In the case of the Nexus 4 *keymaster*, the commands used are: `GENERATE_KEYPAIR`, `IMPORT_KEYPAIR`, `SIGN_DATA`, and `VERIFY_DATA`. The *keymaster* implementation merely creates command structures, sends them via the *QSEECom* API, and parses the replies. It does not contain any cryptographic code.

One interesting detail is that the QSEE *keystore* trusted app (which may not be a dedicated app, but part of a more general-purpose trusted application) doesn’t return simple references to protected keys; it uses proprietary encrypted key blobs. In this model, the only thing that is actually protected by hardware is some form of master key-encryption key (KEK); user-generated keys are only indirectly protected by being encrypted with the KEK.

This method allows for a practically unlimited number of protected keys, but it has the disadvantage that if the KEK is compromised, all externally stored key blobs are compromised as well. (Of course, the actual implementation might generate a dedicated KEK for each key blob created, or the key can be fused in hardware; either way no details are available about the internal implementation.) That said, Qualcomm *keymaster* key blobs are defined in AOSP code (shown in [Example 7-3](ch07.html#qsee_keymaster_blob_definition_left_pare "Example 7-3. QSEE keymaster blob definition (for Nexus 4)")) and the definition suggests that private exponents are encrypted using AES ➊, most probably in CBC mode, with an added HMAC-SHA256 ➋ to check encrypted data integrity.

Example 7-3. QSEE keymaster blob definition (for Nexus 4)

```
#define KM_MAGIC_NUM     (0x4B4D4B42)    /* "KMKB" Key Master Key Blob in hex */
#define KM_KEY_SIZE_MAX  (512)           /* 4096 bits */
#define KM_IV_LENGTH     (16)           ➊/* AES128 CBC IV */
#define KM_HMAC_LENGTH   (32)           ➋/* SHA2 will be used for HMAC */

struct qcom_km_key_blob {
  uint32_t magic_num;
  uint32_t version_num;
  uint8_t modulus[KM_KEY_SIZE_MAX];➌
  uint32_t modulus_size;
  uint8_t public_exponent[KM_KEY_SIZE_MAX];➍
  uint32_t public_exponent_size;
  uint8_t iv[KM_IV_LENGTH];➎
  uint8_t encrypted_private_exponent[KM_KEY_SIZE_MAX];➏
  uint32_t encrypted_private_exponent_size;
  uint8_t hmac[KM_HMAC_LENGTH];➐
};
```

As you can see in [Example 7-3](ch07.html#qsee_keymaster_blob_definition_left_pare "Example 7-3. QSEE keymaster blob definition (for Nexus 4)"), the QSEE key blob contains the key modulus ➌, public exponent ➍, the IV ➎ used for private exponent encryption, the private exponent itself ➏, and the HMAC value ➐.

Since the QSEE used in the Nexus 4 is implemented using the TrustZone functions of the processor, in this case the “hardware” of the hardware-backed credential store is simply the ARM SoC. Are other implementations possible? Theoretically, a hardware-backed *keymaster* implementation does not need to be based on TrustZone. Any dedicated device that can generate and store keys securely can be used, with the usual candidates being embedded Secure Elements (SE) and Trusted Platform Modules (TPMs). We’ll discuss SEs and other tamper-resistant devices in [Chapter 11](ch11.html "Chapter 11. NFC and Secure Elements"), but as of this writing no mainstream Android devices have dedicated TPMs and recent flagship devices have begun shipping without embedded SEs. Therefore, implementations using dedicated hardware are unlikely to show up in mainstream devices.

### Note

*Of course, all mobile devices have some form of* Universal Integrated Circuit Card (UICC)*, colloquially known as a SIM card, which typically can generate and store keys, but Android still doesn’t have a standard API to access the UICC even though vendor firmware often includes one. So while one could theoretically implement a UICC-based* keymaster *module, it would only work on custom Android builds and would depend on network operators to include support in their UICCs.*

## Framework Integration

While managing credentials securely is the key feature of Android’s credential storage, its main purpose is to provide this service seamlessly to the rest of the system. Let’s briefly discuss how it integrates with the rest of Android before presenting the public APIs that are available for third-party apps.

Because the *keystore* service is a standard Binder service, in order to use it potential clients only need to get a reference to it from the `ServiceManager`. The Android framework provides the singleton `android.security.KeyStore` hidden class, which is responsible for obtaining a reference to the *keystore* service and serves as a proxy to the `IKeystoreService` interface it exposes. Most system applications, such as the PKCS#12 file importer (see [Figure 7-1](ch07.html#pkcshash12_file_password_dialog "Figure 7-1. PKCS#12 file password dialog")), and the implementations of some of the public APIs use the `KeyStore` proxy class to communicate with the *keystore* service.

In the case of lower-level libraries that are not part of the Android framework, such as native libraries and JCA classes in the core Java library, integration with the system credential store is provided indirectly through an OpenSSL engine called the *Android keystore engine*.

An OpenSSL engine is a pluggable cryptographic module implemented as a dynamic shared library. The *keystore* engine is one such module that implements all of its operations by calling the system *keymaster* HAL module. It supports only loading and signing with RSA, DSA, or EC private keys, but that’s enough to implement key-based authentication (such as SSL client authentication). The *keystore* engine makes it possible for native code that uses OpenSSL APIs to use private keys saved in the system credential store without the need for code modifications. It also has a Java wrapper (`OpenSSLEngine`), which is used to implement access to keystore-managed private keys in the JCA framework.

# Public APIs

While system applications can access the *keystore* daemon AIDL interface directly or through the `android.security.KeyStore` proxy class, those interfaces are too closely coupled with the implementation to be part of the public API. Android provides higher-level abstractions for third-party apps with the `KeyChain` API and the *AndroidKeyStoreProvider* JCA provider. We’ll show how these APIs are used and provide some implementation details in the following sections.

## The KeyChain API

Android has offered a system-wide credential store since version 1.6, but it was only usable by built-in VPN and Wi-Fi EAP clients. It was possible to install a private key/certificate pair using the Settings app, but the installed keys were not accessible by third-party applications.

Android 4.0 introduced SDK APIs for both trusted certificate management and secure credential storage via the `KeyChain` class. This feature was extended in Android 4.3 to support the newly introduced hardware-backed features. We’ll discuss how it’s used and review its implementation in the following sections.

### The KeyChain Class

The `KeyChain` class is quite simple: it offers six public static methods, which are sufficient for most certificate- and key-related tasks. We’ll look at how to install a private key/certificate pair and then use that pair to access the credential-store-managed private key.

The `KeyChain` API lets you install a private key/certificate pair bundled in a PKCS#12 file. The `KeyChain.createInstallIntent()` factory method is the gateway to this functionality. It takes no parameters and returns a system intent that can parse and install keys and certificates. (This is actually the same intent that is used internally by the Settings system app.)

### Installing a PKCS#12 File

To install a PKCS#12 file, you have to read it to a byte array, store it under the `EXTRA_PKCS12` key in the intent’s extras, and start the associated activity (see [Example 7-4](ch07.html#installing_a_pkcshash12_file_using_the_k "Example 7-4. Installing a PKCS#12 file using the KeyChain API")):

Example 7-4. Installing a PKCS#12 file using the `KeyChain` API

```
Intent intent = KeyChain.createInstallIntent();
byte[] p12 = readFile("keystore-test.pfx");
intent.putExtra(KeyChain.EXTRA_PKCS12, p12);
startActivity(intent);
```

![Private key and certificate import dialog](figs/web/07fig03.png.jpg)

Figure 7-3. Private key and certificate import dialog

This should prompt you for the PKCS#12 password in order to extract and parse the key and certificate. If the password is correct, you should be prompted for a certificate name, as shown in [Figure 7-3](ch07.html#private_key_and_certificate_import_dialo "Figure 7-3. Private key and certificate import dialog"). If the PKCS#12 has a friendly name attribute, it will be shown as the default; if not, you’ll just get a long hexadecimal hash string. The string you enter here is the key or certificate alias you can use later to look up and access keys via the `KeyChain` API. You should be prompted to set a lock screen PIN or password to protect the credential storage if you haven’t already set one.

### Using a Private Key

To use a private key stored in the system credential store, you need to obtain a reference to the key using its alias and request key access permission from the user. If you’ve never accessed a key before and don’t know its alias, you need to first call `KeyChain.choosePrivateKeyAlias()` and provide a callback implementation that receives the selected alias as shown in [Example 7-5](ch07.html#using_a_private_key_stored_in_the_system "Example 7-5. Using a private key stored in the system credential store").

Example 7-5. Using a private key stored in the system credential store

```
public class KeystoreTest extends Activity implements OnClickListener,
KeyChainAliasCallback {
   @Override
   public void onClick(View v) {
       KeyChain.choosePrivateKeyAlias(➊this, ➋(KeyChainAliasCallback)this,
          ➌new String[] { "RSA" }, ➍null, ➎null, ➏-1, ➐null);
   }
   @Override
   public void alias(final String alias) {➑
       Log.d(TAG, "Thread: " + Thread.currentThread().getName());
       Log.d(TAG, "selected alias: " + alias);
   }
}
```

The first parameter ➊ is the current context; the second ➋ is the callback to invoke; and the third and fourth specify the acceptable keys ➌ (`RSA`, `DSA`, or `null` for any) and acceptable certificate issuers ➍ for the certificate matching the private key. The next two parameters are the host ➎ and port number ➏ of the server requesting a certificate, and the last one ➐ is the alias to preselect in the key selection dialog. We leave all but the key type as unspecified (`null` or `-1`) here in order to be able to select from all available certificates. Note that the `alias()` ➑ callback will not be called on the main thread, so don’t try to directly manipulate the UI from it. (It’s called on a binder thread.)

Using the key requires user authorization, so Android should display a key selection dialog (see [Figure 7-4](ch07.html#key_selection_dialog "Figure 7-4. Key selection dialog")) which also serves to grant access to the selected key. Once the user has granted key access to an app, it can look up that key directly without going through the key selection dialog.

![Key selection dialog](figs/web/07fig04.png.jpg)

Figure 7-4. Key selection dialog

[Example 7-6](ch07.html#getting_a_key_instance_and_its_certifica "Example 7-6. Getting a key instance and its certificate chain") shows how to use the `KeyChain` API to obtain a reference to a private key managed by the system keystore.

Example 7-6. Getting a key instance and its certificate chain

```
PrivateKey pk =  KeyChain.getPrivateKey(context, alias);➊
X509Certificate[] chain =  KeyChain.getCertificateChain(context, alias);➋
```

To get a reference to a private key, you need to call the `KeyChain.getPrivateKey()` ➊ method, passing it the key alias name received in the previous step. If you try to call this method on the main thread, you’ll get an exception, so make sure to call it from a background thread like the one created by the `AsyncTask` utility class. The `getCertificateChain()` ➋ method returns the certificate chain associated with the private key (see [Example 7-6](ch07.html#getting_a_key_instance_and_its_certifica "Example 7-6. Getting a key instance and its certificate chain")). If a key or certificate with the specified alias doesn’t exist, the `getPrivateKey()` and `getCertificateChain()` methods will return `null`.

### Installing a CA Certificate

Installing a CA certificate is not very different from installing a PKCS#12 file. To do so, load the certificate in a byte array and pass it as an extra to the install intent under the `EXTRA_CERTIFICATE` key, as shown in [Example 7-7](ch07.html#installing_a_ca_certificate_using_the_ke "Example 7-7. Installing a CA certificate using the KeyChain API").

Example 7-7. Installing a CA certificate using the `KeyChain` API

```
Intent intent = KeyChain.createInstallIntent();
intent.putExtra(KeyChain.EXTRA_CERTIFICATE, cert);
startActivity(intent);
```

Android parses the certificate, and if its *Basic Constraints* extension is set to `CA:TRUE`, considers it a CA certificate and imports it into the user trust store. You need to authenticate in order to import the certificate.

Unfortunately, the import dialog (see [Figure 7-5](ch07.html#ca_certificate_import_dialog-id00013 "Figure 7-5. CA certificate import dialog")) shows neither the certificate DN nor its hash value. The user has no way of knowing what they’re importing until it’s done. Very few people bother to check a certificate’s validity, so this could be a potential security threat because malicious applications could trick people into installing rogue certificates.

After the certificate is imported, it should show up in the Trusted credentials screen’s User tab (Settings ▸Security ▸Trusted credentials). Tap the certificate entry to display a details dialog where you can check the subject, issuer, validity period, serial number, and SHA-1/SHA-256 fingerprints. To remove a certificate, press the **Remove** button (see [Figure 7-6](ch07.html#certificate_details_dialog "Figure 7-6. Certificate details dialog")).

![CA certificate import dialog](figs/web/07fig05.png.jpg)

Figure 7-5. CA certificate import dialog

![Certificate details dialog](figs/web/07fig06.png.jpg)

Figure 7-6. Certificate details dialog

### Deleting Keys and User Certificates

While you can delete individual CA certificates, there is no way to delete individual keys and user certificates, although the Clear credentials option in the Credential Storage section of the security settings will delete all keys and user certificates.

### Note

*As long as you have keys in the credential store, you can’t remove the screen lock because it is used to protect access to the keystore.*

### Getting Information about Supported Algorithms

Android 4.3 added two methods to the `KeyChain` class related to the newly introduced hardware support. According to the API documentation, `isBoundKeyAlgorithm(String algorithm)` “returns `true` if the current device’s `KeyChain` implementation binds any `PrivateKey` of the given algorithm to the device once imported or generated.” In other words, if you pass the string *RSA* to this method, it should return `true` if generated or imported RSA keys have hardware protection and cannot simply be copied off the device. The `isKeyAlgorithmSupported(String algorithm)` method should return `true` if the current `KeyChain` implementation supports keys of the specified type (RSA, DSA, EC, and so on).

We’ve introduced the main features of the `KeyChain` API. Now let’s look at the underlying Android implementation.

## KeyChain API Implementation

The public `KeyChain` class and supporting interfaces reside in the `android.security` Java package. The package also contains two hidden AIDL files: `IKeyChainService.aidl` and `IKeyChainAliasCallback`. This is a hint that the actual keystore functionality, like most Android OS services, is implemented as a remote service to which the public APIs bind. The interface `IKeyChainAliasCallback` is called when you select a key via `KeyStore.choosePrivateKeyAlias()`, so it’s of little interest. `IKeyChainService.aidl` defines the actual system interface that services use, so we’ll describe it in more detail.

The `IKeyChainService` interface has one implementation, the `KeyChainService` class in the `KeyChain` system application. In addition to `KeyChainService`, the application includes an activity, `KeyChain`, and a broadcast receiver, `KeyChainBroadcastReceiver`. The `KeyChain` application has its `sharedUserId` is set to *android.uid.system* and therefore inherits all privileges of the *system* user. This allows its components to send management commands to the native *keystore* service. Let’s examine the service first.

The `KeyChainService` is a wrapper for the `android.security.KeyStore` proxy class that directly communicates with the native *keystore* service. It provides four main services:

*   Keystore management: methods for getting private keys and certificates.

*   Trust store management: methods for installing and deleting CA certificates in the user trust store.

*   Key and trust store initialization: a `reset()` method that deletes all key-store entries, including the master key, thus returning the keystore to an uninitialized state; it also removes all user-installed trusted certificates.

*   Methods for querying and adding entries to the key access grant database.

## Controlling Access to the Keystore

Since the `KeyChain` application runs as the *system* user, any process that binds to its remote interface would technically be able to perform all key and trust store operations. To prevent this, the `KeyChainService` imposes additional access control on its users by controlling access to credential store operations based on the caller’s UID and using a key access grant database to regulate access to individual keys. Only the *system* user can delete a CA certificate and reset the key and trust stores (operations typically called via the Settings app’s UI, which runs as *system*). By the same token, only the *system* user or the certificate installer application (`com.android.certinstaller` package) can install a trusted CA certificate.

Controlling access to individual keys in the credential store is a little bit more interesting than operation restrictions. The `KeyChainService` maintains a grants database (in */data/data/com.android.keychain/databases/grants.db*) that maps UIDs to the key aliases they are allowed to use. Let’s have a look inside in [Example 7-8](ch07.html#schema_and_contents_of_the_grants_databa "Example 7-8. Schema and contents of the grants database").

Example 7-8. Schema and contents of the grants database

```
# **sqlite3 grants.db**
sqlite> .schema
.schema
CREATE TABLE android_metadata (locale TEXT);
CREATE TABLE grants (alias STRING NOT NULL, uid INTEGER NOT NULL, UNIQUE (alias,uid));
sqlite> select * from grants;
select * from grants;
➊test|10044➋
➌key1|10044
```

In this example, the application with UID *10044* ➋ is granted access to the keys with the `test` ➊ and `key1` ➌ aliases.

Each call to `getPrivateKey()` or `getCertificate()` is subject to a check against the grants database, and results in an exception if a grant for the required alias is not found. As stated before, `KeyChainService` has APIs for adding and querying grants, and only the *system* user can call them. But who is responsible for actually granting and revoking access?

Remember the private key selection dialog ([Figure 7-4](ch07.html#key_selection_dialog "Figure 7-4. Key selection dialog"))? When you call `KeyChain.choosePrivateKeyAlias()`, it starts the `KeyChainActivity` (introduced above), which checks to see if the keystore is unlocked; if so, `KeyChainActivity` shows the key selection dialog. Clicking the **Allow** button returns to the `KeyChainActivity`, which then calls `KeyChainService.setGrant()` with the selected alias, adding it to the grants database. Thus, even if the activity requesting access to a private key has the needed permissions, the user must unlock the keystore and explicitly authorize access to each individual key.

Besides controlling private key storage, the `KeyChainService` also offers trust store management by using the newly added `TrustedCertificateStore` class (part of *libcore*). This class provides both the ability to add user-installed trusted CA certificates and remove (mark as not trusted) system (preinstalled) CAs. [Chapter 6](ch06.html "Chapter 6. Network Security and PKI") discusses the details of its implementation.

### KeyChainBroadcastReceiver

The last component of the `KeyChain` app is the `KeyChainBroadcastReceiver`. It listens for the `android.intent.action.PACKAGE_REMOVED` system broadcast and simply forwards control to the `KeyChainService`. On receiving the `PACKAGE_REMOVED` action, the service does some grant database maintenance: it goes through all entries and deletes any referencing packages that are no longer available (that is, ones that have been uninstalled).

### Credential and Trust Store Summary

Android 4.0 introduces a new service that grants access to both the system keystore (managed by the *keystore* system service) and the trust store (managed by the `TrustedCertificateStore` class) that backs the `KeyChain` API exposed in the public SDK. This feature makes it possible to control access to keys based on both the calling process’s UID and the key access grant database, thus allowing for fine-grained, user-driven control over which keys each application can access. The components of Android’s credential and trust store and their relationship are presented in [Figure 7-7](ch07.html#system_credential_store_components "Figure 7-7. System credential store components").

![System credential store components](figs/web/07fig07.png)

Figure 7-7. System credential store components

## Android Keystore Provider

While the `KeyChain` API introduced in Android 4.0 allows applications to import keys into the system credential store, those keys are owned by the *system* user and any application can request access to them. Android 4.3 adds support for *app-private* keys, which allows any app to generate and save private keys that can only be accessed and used by itself and are not visible to other apps.

Instead of introducing yet another Android-specific API, keystore access is exposed via standard JCA APIs, namely `java.security.KeyPairGenerator` and `java.security.KeyStore`. Both are backed by a new Android JCA provider, *AndroidKeyStoreProvider*, and are accessed by passing *AndroidKeyStore* as the `type` parameter of the respective factory methods. [Example 7-9](ch07.html#generating_and_accessing_rsa_keys_using "Example 7-9. Generating and accessing RSA keys using the AndroidKeyStoreProvider") shows how to generate and access RSA keys using the *AndroidKeyStoreProvider.*

Example 7-9. Generating and accessing RSA keys using the AndroidKeyStoreProvider

```
// generate a key pair
Calendar notBefore = Calendar.getInstance()
Calendar notAfter = Calendar.getInstance(); notAfter.add(1, Calendar.YEAR);
KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(ctx) .setAlias("key1")
                .setKeyType("RSA")
                .setKeySize(2048)
                .setSubject(new X500Principal("CN=test"))
                .setSerialNumber(BigInteger.ONE).setStartDate(notBefore.getTime())
                .setEndDate(notAfter.getTime()).build();➊
KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA",
                              "AndroidKeyStore");
kpGenerator.initialize(spec);➋
KeyPair kp = kpGenerator.generateKeyPair();➌
// in another part of the app, access the keys
KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
ks.load(null);
KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry("key1", null);➍
RSAPublic pubKey = (RSAPublicKey)keyEntry.getCertificate().getPublicKey();
RSAPrivateKey privKey = (RSAPrivateKey) keyEntry.getPrivateKey();
```

First ➊ you create a `KeyPairGeneratorSpec` describing the keys you want to generate and the automatically created self-signed certificate each key is associated with. You can specify the key type (*RSA*, *DSA*, or *EC*) using the `setKeyType()` method, and key size with the `setKeySize()` method.

### Note

*Each `PrivateKeyEntry` managed by a `KeyStore` object needs to be associated with a certificate chain. Android automatically creates a self-signed certificate when you generate a key, but you can replace the default certificate with one signed by a CA later.*

Next, you initialize a `KeyPairGenerator` ➋ with the `KeyPairGeneratorSpec` instance and then generate the keys by calling `generateKeyPair()` ➌.

The most important parameter is the alias. You pass the alias to `KeyStore.getEntry()` ➍ in order to get a reference to the generated keys later. The returned key object does not contain the actual key material; it is only a pointer to a hardware-managed key object. Therefore, it is not usable with cryptographic providers that rely on key material being directly accessible.

If the device has a hardware-backed keystore implementation, keys will be generated outside the Android OS and won’t be directly accessible even to the system (or *root*) user. If the implementation is software only, keys will be encrypted with a per-user key-encryption master key derived from the unlock PIN or password.

# Summary

As you’ve learned in this chapter, Android has a system credential store that can be used to store credentials for built-in features such as Wi-Fi and VPN connectivity, as well as for use by third-party apps. Android 4.3 and later versions provide standard JCA APIs for generating and accessing app-private keys, which makes it easier for non-system apps to store their keys securely without needing to implement key protection themselves. Hardware-backed key storage, which is available on supported devices, guarantees that even apps with *system* or *root* privileges cannot extract the keys. Most current hardware-backed credential storage implementations are based on ARM’s TrustZone technology and do not use dedicated tamper-resistant hardware.
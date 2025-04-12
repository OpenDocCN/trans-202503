# Chapter 3. Package Management

In this chapter, we take an in-depth look at Android package management. We begin with a description of Android’s package format and code signing implementation, and then detail the APK install process. Next, we explore Android’s support for encrypted APKs and secure application containers, which are used to implement a form of DRM for paid applications. Finally, we describe Android’s package verification mechanism and its most widely used implementation: the Google Play application verification service.

# Android Application Package Format

Android applications are distributed and installed in the form of application package (APK) files, which are usually referred to as *APK files*. APK files are container files that include both application code and resources, as well as the application manifest file. They can also include a code signature. The APK format is an extension of the Java JAR format,^([[17](#ftn.ch03fn01)]) which in turn is an extension of the popular ZIP file format. APK files typically have the *.apk* extension and are associated with the *application/vnd.android.package-archive* MIME type.

Because APK files are simply ZIP files, you can easily examine their contents by extracting them with any compression utility that supports the ZIP format. [Example 3-1](ch03.html#contents_of_a_typical_apk_file "Example 3-1. Contents of a typical APK file") shows the contents of a typical APK file after it has been extracted.

Example 3-1. Contents of a typical APK file

```
apk/
|-- AndroidManifest.xml➊
|-- classes.dex➋
|-- resources.arsc➌
|-- assets/➍
|-- lib/➎
|   |-- armeabi/
|   |   `-- libapp.so
|   `-- armeabi-v7a/
|       `-- libapp.so
|-- META-INF/➏
|   |-- CERT.RSA
|   |-- CERT.SF
|   `-- MANIFEST.MF
`-- res/➐
    |-- anim/
    |-- color/
    |-- drawable/
    |-- layout/
    |-- menu/
    |-- raw/
    `-- xml/
```

Every APK file includes an *AndroidManifest.xml* file ➊ which declares the application’s package name, version, components, and other metadata. The *classes.dex* file ➋ contains the executable code of the application and is in the native DEX format of the Dalvik VM. The *resources.arsc* ➌ packages all of the application’s compiled resources such as strings and styles. The *assets* directory ➍ is used to bundle raw asset files with the application, such as fonts or music files.

Applications that take advantage of native libraries via JNI contain a *lib* directory ➎, with subdirectories for each supported platform architecture. Resources that are directly referenced from Android code, either directly using the `android.content.res.Resources` class or indirectly via higher-level APIs, are stored in the *res* directory ➐, with separate directories for each resource type (animations, images, menu definitions, and so on). Like JAR files, APK files also contain a *META-INF* directory ➏, which hosts the package manifest file and code signatures. We’ll describe the contents of this directory in the next section.

# Code signing

As we learned in [Chapter 2](ch02.html "Chapter 2. Permissions"), Android uses APK code signing, in particular the APK signing certificate, in order to control which applications can be granted permission with the *signature* protection level. The APK signing certificate is also used for various checks during the application installation process, so before we get into details about APK installation, we should become more familiar with code signing in Android. This section provides some details about Java code signing in general and highlights the differences with Android’s implementation.

Let’s start with a few words about code signing in general. Why would anyone want to sign code? For the usual reasons: integrity and authenticity. Before executing any third-party program, you want to make sure that it hasn’t been tampered with (integrity) and that it was actually created by the entity that it claims to come from (authenticity). These features are usually implemented by a digital signature scheme, which guarantees that only the entity owning the signing key can produce a valid code signature.

The signature verification process verifies both that the code has not been tampered with and that the signature was produced with the expected key. But one problem that code signing doesn’t solve directly is whether the code signer (software publisher) can be trusted. The usual way to establish trust is to require that the code signer holds a digital certificate and attaches it to the signed code. Verifiers decide whether to trust the certificate based on a trust model (such as PKI or web of trust) or on a case-by-case basis.

Another problem that code signing does not even attempt to solve is whether the signed code is safe to run. As Flame^([[18](#ftn.ch03fn02)]) and other code-signed malware have demonstrated, even code that appears to have been signed by a trusted third party might not be safe.

## Java Code Signing

Java code signing is performed at the JAR file level. It reuses and extends JAR manifest files in order to add a code signature to the JAR archive. The main JAR manifest file (*MANIFEST.MF*) has entries with the filename and digest value of each file in the archive. For example, [Example 3-2](ch03.html#jar_manifest_file_excerpt "Example 3-2. JAR manifest file excerpt") shows the start of the JAR manifest file of a typical APK file. (We’ll use APKs instead of regular JARs for all examples in this section.)

Example 3-2. JAR manifest file excerpt

```
Manifest-Version: 1.0
Created-By: 1.0 (Android)

Name: res/drawable-xhdpi/ic_launcher.png
SHA1-Digest: K/0Rd/lt0qSlgDD/9DY7aCNlBvU=
Name: res/menu/main.xml
SHA1-Digest: kG8WDil9ur0f+F2AxgcSSKDhjn0=

Name: ...
```

### Implementation

Java code signing is implemented by adding another manifest file called a *signature file* (with extension *.SF*), which contains the data to be signed, and a digital signature over it. The digital signature is called a *signature block file* and is stored in the archive as a binary file with one of the *.RSA*, *.DSA*, or *.EC* extensions, depending on the signature algorithm used. As shown in [Example 3-3](ch03.html#jar_signature_file_excerpt "Example 3-3. JAR signature file excerpt"), the signature file is very similar to the manifest.

Example 3-3. JAR signature file excerpt

```
Signature-Version: 1.0
SHA1-Digest-Manifest-Main-Attributes: ZKXxNW/3Rg7JA1r0+RlbJIP6IMA=
Created-By: 1.7.0_51 (Sun Microsystems Inc.)
SHA1-Digest-Manifest: zb0XjEhVBxE0z2ZC+B4OW25WBxo=➊

Name: res/drawable-xhdpi/ic_launcher.png
SHA1-Digest: jTeE2Y5L3uBdQ2g40PB2n72L3dE=➋

Name: res/menu/main.xml
SHA1-Digest: kSQDLtTE07cLhTH/cY54UjbbNBo=➌

Name: ...
```

The signature file contains the digest of the whole manifest file (*SHA1-Digest-Manifest* ➊), as well as digests for each entry in *MANIFEST.MF* (➋ and ➌). SHA-1 was the default digest algorithm until Java 6, but Java 7 and later can generate file and manifest digests using the SHA-256 and SHA-512 hash algorithms, in which case the digest attributes become *SHA-256-Digest* and *SHA-512-Digest*, respectively. Since version 4.3, Android supports SHA-256 and SHA-512 digests.

The digests in the signature file can easily be verified by using the following OpenSSL commands, as shown in [Example 3-4](ch03.html#verifying_jar_signature_file_digests_usi "Example 3-4. Verifying JAR signature file digests using OpenSSL").

Example 3-4. Verifying JAR signature file digests using OpenSSL

```
$ **openssl sha1 -binary MANIFEST.MF |openssl base64**➊
zb0XjEhVBxE0z2ZC+B4OW25WBxo=
$ **echo -en "Name: res/drawable-xhdpi/ic_launcher.png\r\nSHA1-Digest: \**
**K/0Rd/lt0qSlgDD/9DY7aCNlBvU=\r\n\r\n"|openssl sha1 -binary |openssl base64**➋
jTeE2Y5L3uBdQ2g40PB2n72L3dE=
```

The first command ➊ takes the SHA-1 digest of the entire manifest file and encodes it to Base64 to produce the *SHA1-Digest-Manifest* value. The second command ➋ simulates the way the digest of a single manifest entry is calculated. It also demonstrates the attribute canonicalization format required by the JAR specification.

The actual digital signature is in binary PKCS#7^([[19](#ftn.ch03fn03)]) (or more generally, CMS^([[20](#ftn.ch03fn04)])) format and includes the signature value and signing certificate. Signature block files produced using the RSA algorithm are saved with the extension *.RSA*, and those generated with DSA or EC keys are saved with *.DSA* or *.EC* extensions. Multiple signatures can also be performed, resulting in multiple *.SF* and *.RSA/DSA/EC* files in the JAR file’s *META-INF* directory.

The CMS format is rather involved, allowing for signing *and* encryption, both with different algorithms and parameters. It’s also extensible via custom signed or unsigned attributes. A thorough discussion is beyond the scope of this chapter (see RFC 5652 for details about CMS), but as used for JAR signing, a CMS structure basically contains the digest algorithm, signing certificate, and signature value. The CMS specifications allows for including signed data in the `SignedData` CMS structure (a format variation called *attached signature*), but JAR signatures don’t include it. When the signed data is not included in the CMS structure, the signature is called a *detached signature* and verifiers need to have a copy of the original signed data in order to verify it. [Example 3-5](ch03.html#contents_of_a_jar_file_signature_block "Example 3-5. Contents of a JAR file signature block") shows an RSA signature block file parsed into *ASN.1*,^([[21](#ftn.ch03fn05)]) with the certificate details trimmed:

Example 3-5. Contents of a JAR file signature block

```
$ **openssl asn1parse -i -inform DER -in CERT.RSA**
    0:d=0  hl=4 l= 888 cons: SEQUENCE
    4:d=1  hl=2 l=   9 prim:  OBJECT            :pkcs7-signedData➊
   15:d=1  hl=4 l= 873 cons:  cont [ 0 ]
   19:d=2  hl=4 l= 869 cons:   SEQUENCE
   23:d=3  hl=2 l=   1 prim:    INTEGER           :01➋
   26:d=3  hl=2 l=  11 cons:    SET
   28:d=4  hl=2 l=   9 cons:     SEQUENCE
   30:d=5  hl=2 l=   5 prim:      OBJECT            :sha1➌
   37:d=5  hl=2 l=   0 prim:      NULL
   39:d=3  hl=2 l=  11 cons:    SEQUENCE
   41:d=4  hl=2 l=   9 prim:     OBJECT            :pkcs7-data➍
   52:d=3  hl=4 l= 607 cons:    cont [ 0 ]➎
   56:d=4  hl=4 l= 603 cons:     SEQUENCE
   60:d=5  hl=4 l= 452 cons:      SEQUENCE
   64:d=6  hl=2 l=   3 cons:       cont [ 0 ]
   66:d=7  hl=2 l=   1 prim:        INTEGER           :02
   69:d=6  hl=2 l=   1 prim:       INTEGER           :04
   72:d=6  hl=2 l=  13 cons:       SEQUENCE
   74:d=7  hl=2 l=   9 prim:        OBJECT            :sha1WithRSAEncryption
   85:d=7  hl=2 l=   0 prim:        NULL
   87:d=6  hl=2 l=  56 cons:       SEQUENCE
   89:d=7  hl=2 l=  11 cons:       SET
   91:d=8  hl=2 l=   9 cons:        SEQUENCE
   93:d=9  hl=2 l=   3 prim:         OBJECT            :countryName
   98:d=9  hl=2 l=   2 prim:         PRINTABLESTRING   :JP
  --*snip*--
  735:d=5  hl=2 l=   9 cons:     SEQUENCE
  737:d=6  hl=2 l=   5 prim:      OBJECT            :sha1➏
  744:d=6  hl=2 l=   0 prim:      NULL
  746:d=5  hl=2 l=  13 cons:     SEQUENCE
  748:d=6  hl=2 l=   9 prim:      OBJECT            :rsaEncryption➐
  759:d=6  hl=2 l=   0 prim:      NULL
  761:d=5  hl=3 l= 128 prim:    OCTET STRING       [HEX DUMP]:892744D30DCEDF74933007...➑
```

The signature block contains an object identifier ➊ that describes the type of data (ASN.1 object) that follows: `SignedData`, and the data itself. The included `SignedData` object contains a version ➋ (1); a set of hash algorithm identifiers used ➌ (only one for a single signer, SHA-1 in this example); the type of data that was signed ➍ (*pkcs7-data*, which simply means “arbitrary binary data”); the set of signing certificates ➎; and one or more (one for each signer) `SignerInfo` structures that encapsulates the signature value (not shown in full in [Example 3-5](ch03.html#contents_of_a_jar_file_signature_block "Example 3-5. Contents of a JAR file signature block")). `SignerInfo` contains a version; a `SignerIdentifier` object, which typically contains the DN of the certificate issuer and the certificate serial number (not shown); the digest algorithm used ➏ (SHA-1, included in ➌); the digest encryption algorithm used to generate the signature value ➐; and the encrypted digest (signature value) itself ➑.

The most important elements of the `SignedData` structure, with regard to JAR and APK signatures, are the set of signing certificates ➎ and the signature value ➑ (or values, when signed by multiple signers).

If we extract the contents of a JAR file, we can use the OpenSSL `smime` command to verify its signature by specifying the signature file as the content or signed data. The `smime` command prints the signed data and the verification result as shown in [Example 3-6](ch03.html#verifying_a_jar_file_signature_block "Example 3-6. Verifying a JAR file signature block"):

Example 3-6. Verifying a JAR file signature block

```
$ **openssl smime -verify -in CERT.RSA -inform DER -content CERT.SF signing-cert.pem**
Signature-Version: 1.0
SHA1-Digest-Manifest-Main-Attributes: ZKXxNW/3Rg7JA1r0+RlbJIP6IMA=
Created-By: 1.7.0_51 (Sun Microsystems Inc.)
SHA1-Digest-Manifest: zb0XjEhVBxE0z2ZC+B4OW25WBxo=

Name: res/drawable-xhdpi/ic_launcher.png
SHA1-Digest: jTeE2Y5L3uBdQ2g40PB2n72L3dE=

--*snip*--
Verification successful
```

### JAR File Signing

The official JDK tools for JAR signing and verification are the `jarsigner` and `keytool` commands. Since Java 5.0 `jarsigner` also supports timestamping the signature by a Timestamping Authority (TSA), which can be quite useful when you need to ascertain whether a signature was produced before or after the signing certificate expired. However, this feature is not widely used and is not supported on Android.

A JAR file is signed using the `jarsigner` command by specifying a key-store file (see [Chapter 5](ch05.html "Chapter 5. Cryptographic Providers")) together with the alias of the key to use for signing (the first eight characters of the alias become the base name for the signature block file, unless the `-sigfile` option is specified) and optionally a signature algorithm. See ➊ in [Example 3-7](ch03.html#signing_an_apk_file_and_verifying_the_si "Example 3-7. Signing an APK file and verifying the signature using the jarsigner command") for an example invocation of `jarsigner`.

### Note

*Since Java 7, the default algorithm has changed to* SHA256withRSA, *so you need to specify it explicitly if you want to use SHA-1 for backward compatibility. SHA-256-and SHA-512-based signatures have been supported since Android 4.3.*

Example 3-7. Signing an APK file and verifying the signature using the `jarsigner` command

```
$ **jarsigner -keystore debug.keystore -sigalg SHA1withRSA test.apk androiddebugkey**➊
$ **jarsigner -keystore debug.keystore -verify -verbose -certs test.apk**➋
--*snip*--

smk      965 Sat Mar 08 23:55:34 JST 2014 res/drawable-xxhdpi/ic_launcher.png

      X.509, CN=Android Debug, O=Android, C=US (androiddebugkey)➌
      [certificate is valid from 6/18/11 7:31 PM to 6/10/41 7:31 PM]

smk   458072 Sun Mar 09 01:16:18 JST 2013 classes.dex

      X.509, CN=Android Debug, O=Android, C=US (androiddebugkey)➍
      [certificate is valid from 6/18/11 7:31 PM to 6/10/41 7:31 PM]

         903 Sun Mar 09 01:16:18 JST 2014 META-INF/MANIFEST.MF
         956 Sun Mar 09 01:16:18 JST 2014 META-INF/CERT.SF
         776 Sun Mar 09 01:16:18 JST 2014 META-INF/CERT.RSA

  s = signature was verified
  m = entry is listed in manifest
  k = at least one certificate was found in keystore
  i = at least one certificate was found in identity scope

jar verified.
```

The `jarsigner` tool can use all keystore types supported by the platform, as well as keystores that are not natively supported and that require a dedicated JCA provider, such as those backed by a smart card, HSM, or another hardware device. The type of store to be used for signing is specified with the `-storetype` option, and the provider name and class with the `-providerName` and `-providerClass` options. Newer versions of the Android-specific `signapk` tool (discussed in “[Android Code Signing Tools](ch03.html#android_code_signing_tools "Android Code Signing Tools")”), also support the `-providerClass` option.

### JAR File Verification

JAR file verification is performed using the `jarsigner` command by specifying the `-verify` option. The second `jarsigner` command at ➋ in [Example 3-7](ch03.html#signing_an_apk_file_and_verifying_the_si "Example 3-7. Signing an APK file and verifying the signature using the jarsigner command") first verifies the signature block and signing certificate, ensuring that the signature file has not been tampered with. Next it verifies that each digest in the signature file (*CERT.SF*) matches its corresponding section in the manifest file (*MANIFEST.MF*). (The number of entries in the signature file does not have to match those in the manifest file. Files can be added to a signed JAR without invalidating its signature: as long as none of the original files have been changed, verification succeeds.)

Finally, `jarsigner` reads each manifest entry and checks that the file digest matches the actual file contents. If a keystore has been specified with the `-keystore` option (as in our example), `jarsigner` also checks to see whether the signing certificate is present in the specified keystore. As of Java 7, there is a new `-strict` option that enables additional certificate validations, including a time validity check and certificate chain verification. Validation errors are treated as warnings and are reflected in the exit code of the `jarsigner` command.

### Viewing or Extracting Signer Information

As you can see in [Example 3-7](ch03.html#signing_an_apk_file_and_verifying_the_si "Example 3-7. Signing an APK file and verifying the signature using the jarsigner command"), by default, `jarsigner` prints certificate details for each entry (➌ and ➍) even though they are the same for all entries. A slightly better way to view signer info when using Java 7 is to specify the `-verbose:summary` or `-verbose:grouped` options, or alternatively use the `keytool` command, as shown in [Example 3-8](ch03.html#viewing_apk_signer_information_using_the "Example 3-8. Viewing APK signer information using the keytool command").

Example 3-8. Viewing APK signer information using the `keytool` command

```
$ **keytool -list -printcert -jarfile test.apk**
Signer #1:
Signature:
Owner: CN=Android Debug, O=Android, C=US
Issuer: CN=Android Debug, O=Android, C=US
Serial number: 4dfc7e9a
Valid from: Sat Jun 18 19:31:54 JST 2011 until: Mon Jun 10 19:31:54 JST 2041
Certificate fingerprints:
         MD5: E8:93:6E:43:99:61:C8:37:E1:30:36:14:CF:71:C2:32
         SHA1: 08:53:74:41:50:26:07:E7:8F:A5:5F:56:4B:11:62:52:06:54:83:BE
         Signature algorithm name: SHA1withRSA
         Version: 3
```

Once you have found the signature block filename (by listing the archive contents for example), you can use OpenSSL with the `unzip` command to easily extract the signing certificate to a file, as shown in [Example 3-9](ch03.html#extracting_the_apk_signing_certificate_u "Example 3-9. Extracting the APK signing certificate using the unzip and OpenSSL pkcs7 commands"). (If the `SignedData` structure includes more than one certificate, all certificates will be extracted. In that case, you will need to parse the `SignedInfo` structure to find the identifier of the actual signing certificate.)

Example 3-9. Extracting the APK signing certificate using the `unzip` and OpenSSL `pkcs7` commands

```
$ **unzip -q -c test.apk META-INF/CERT.RSA|openssl pkcs7 -inform DER -print_certs -out cert.pem**
```

## Android Code Signing

Because Android code signing is based on Java JAR signing, it uses public key cryptography and X.509 certificates like many code signing schemes, but that’s where the similarities end.

In practically all other platforms that use code signing (such as Java ME and Windows Phone), code signing certificates must be issued by a CA that the platform trusts. While there are many CAs that issue code signing certificates, it can prove quite difficult to obtain a certificate that is trusted by all targeted devices. Android solves this problem quite simply: it doesn’t care about the contents or signer of the signing certificate. Thus you do not need to have it issued by a CA, and virtually all code signing certificates used in Android are self-signed. Additionally, you don’t need to assert your identity in any way: you can use pretty much anything as the subject name. (The Google Play Store does have a few checks to weed out some common names, but not the Android OS itself.) Android treats signing certificates as binary blobs, and the fact that they are in X.509 format is merely a consequence of using the JAR format.

Android doesn’t validate certificates in the PKI sense (see [Chapter 6](ch06.html "Chapter 6. Network Security and PKI")). In fact, if a certificate is not self-signed, the signing CA’s certificate does not have to be present or trusted; Android will even happily install apps with an expired signing certificate. If you are coming from a traditional PKI background, this may sound like heresy, but keep in mind that Android does not use PKI for code signing, it only uses the same certificate and signature formats.

Another difference between Android and “standard” JAR signing is that all APK entries must be signed by the same set of certificates. The JAR file format allows each file to be signed by a different signer and permits unsigned entries. This makes sense in the Java sandboxing and access control mechanism, which was originally designed for applets, because that model defines a *code source* as a combination of a signer certificate and code origin URL. However, Android assigns signers per-APK (usually only one, but multiple signers are supported) and does not allow different signers for different APK file entries.

Android’s code signing model, coupled with the poor interface of the `java.util.jar.JarFile` class, which is not a good abstraction for the complexities of the underlying CMS signature format, makes it rather difficult to properly verify the signature of APK files. While Android manages to both verify APK integrity and ensure that all APK file entries have been signed by the same set of certificates by adding additional signing certificate checks to its package parsing routines, it is evident that the JAR file format was not the best choice for Android code signing.

### Android Code Signing Tools

As the examples in the “[Java Code Signing](ch03.html#java_code_signing "Java Code Signing")” section showed, you can use the regular JDK code signing tools to sign or verify APKs. In addition to these tools, the AOSP *build/* directory contains an Android-specific tool called `signapk`. This tool performs pretty much the same task as `jarsigner` in signing mode, with a few notable differences. For one, while `jarsigner` requires that keys be stored in a compatible keystore file, `signapk` takes a separate signing key (in DER-encoded *PKCS#8* format^([[22](#ftn.ch03fn06)])) and certificate file (in DER-encoded X.509 format) as input. The advantage of the PKCS#8 format, which is the standard key encoding format in Java, is that it includes an explicit algorithm identifier that describes the type of the encoded private key. The encoded private key might include key material, possibly encrypted, or it might contain only a reference, such as a key ID, to a key stored in a hardware device.

As of Android 4.4, the `signapk` can only produce signatures with the *SHA1withRSA* or *SHA256withRSA* (added to the platform in Android 4.3) mechanisms. As of this writing, the version of `signapk` found in AOSP’s master branch has been extended to support ECDSA signatures.

While raw private keys in PKCS#8 format are somewhat hard to come by, you can easily generate a test key pair and a self-signed certificate using the `make_key` script found in *development/tools/*. If you have existing OpenSSL keys, you’ll have to convert them to PKCS#8 format first, using something like OpenSSL’s `pkcs8` command as shown in [Example 3-10](ch03.html#converting_an_openssl_key_to_pkcshash8_f "Example 3-10. Converting an OpenSSL key to PKCS#8 format"):

Example 3-10. Converting an OpenSSL key to PKCS#8 format

```
$ **echo "keypwd"|openssl pkcs8 -in mykey.pem -topk8 -outform DER -out mykey.pk8 -passout stdin**
```

Once you have the needed keys, you can sign an APK using `signapk` as shown in [Example 3-11](ch03.html#signing_an_apk_using_the_signapk_tool "Example 3-11. Signing an APK using the signapk tool").

Example 3-11. Signing an APK using the `signapk` tool

```
$ **java -jar signapk.jar cert.cer key.pk8 test.apk test-signed.apk**
```

### OTA File Code Signing

Besides its default APK signing mode, the `signapk` tool also has a “sign whole file” mode that can be enabled with the `-w` option. When in this mode, in addition to signing each individual JAR entry, the tool generates a signature over the whole archive as well. This mode is not supported by `jarsigner` and is specific to Android.

Why sign the whole archive when each file is already signed? In order to support over-the-air (OTA) updates. OTA packages are ZIP files in a format similar to JAR files that contain updated files and the scripts to apply them. The packages include a *META-INF/* directory, manifests, a signature block, and a few extra files, including *META-INF/com/android/otacert*, which contains the update signing certificate (in PEM format). Before booting into recovery to apply updates, Android verifies the package signature and then checks to see if the signing certificate is trusted to sign updates. OTA-trusted certificates are separate from the “regular” system trust store (see [Chapter 6](ch06.html "Chapter 6. Network Security and PKI")), and reside in a ZIP file that is usually stored as */system/ etc/security/otacerts.zip*. On a production device, this file typically contains a single file usually named *releasekey.x509.pem*. After the device reboots, the recovery OS verifies the OTA package signature once again before applying it in order to make sure that the OTA file has not been tampered with in the meantime.

If OTA files are like JAR files, and JAR files don’t support whole-file signatures, where does the signature go? The Android `signapk` tool slightly abuses the ZIP format by adding a null-terminated string comment in the ZIP comment section, followed by the binary signature block and a 6-byte final record containing the signature offset and the size of the entire comment section. Adding the offset record to the end of the file makes it easy to verify the package by first reading and verifying the signature block from the end of the file, and only reading the rest of the file (which could be in the hundreds of megabytes) if the signature checks out.

# APK Install Process

There are a few ways to install Android applications:

*   Via an application store client (such as the Google Play Store). This is how most users install applications.

*   Directly on the device by opening downloaded app files (if the “Unknown sources” option in system settings is enabled). This method is commonly referred to as *sideloading* an app.

*   From a USB-connected computer with the `adb install` Android SDK command which, in turn invokes the `pm` command line utility with the `install` parameter. This method is used mostly by application developers.

*   By directly copying an APK file to one of the system application directories using the Android shell. Because application directories are not accessible on production builds, this method can only be used on devices running an engineering (development) build.

When an APK file is copied directly to one of the application directories it is automatically detected and installed by the package manager, which watches these directories for changes. In the case of all other install methods, the installer application (whether Google Play Store client, default system package install activity, `pm` command, or other) invokes one of the `installPackage()` methods of the system package manager, which then copies the APK to one of the application directories and installs it. In the following sections, we’ll explore the main steps of the Android package install process, and discuss some of the more complex installation steps like encrypted container creation and package verification.

Android’s package management functionality is distributed across several system components that interact with each other during package installation, as shown in [Figure 3-1](ch03.html#package_management_components "Figure 3-1. Package management components"). Solid arrows in the figure represent dependencies between components, as well as function calls. Dashed arrows point to files or directories that are monitored for changes by a component, but which are not directly modified by that component.

![Package management components](figs/web/03fig01.png.jpg)

Figure 3-1. Package management components

## Location of Application Packages and Data

Recall from [Chapter 1](ch01.html "Chapter 1. Android’s Security Model") that Android distinguishes between system- and user-installed applications. System applications are found on the read-only *system* partition (bottom left in [Figure 3-1](ch03.html#package_management_components "Figure 3-1. Package management components")) and cannot be changed or uninstalled on production devices. System applications are therefore considered trusted and are given more privileges, and have some signature checks relaxed. Most system applications are found in the */system/app/* directory, while */system/ priv-app/* holds privileged apps that can be granted permission with the *signatureOrSystem* protection level (as discussed in [Chapter 2](ch02.html "Chapter 2. Permissions")). The */system/ vendor/app/* directory hosts vendor-specific applications. User-installed applications live on the read-write *userdata* partition (shown at the bottom right in [Figure 3-1](ch03.html#package_management_components "Figure 3-1. Package management components")) and can be uninstalled or replaced at any time. Most user-installed applications are installed in the */data/app/* directory.

Data directories for both system and user-installed applications are created on the *userdata* partition under the */data/data/* directory. The *userdata* partition also hosts the optimized DEX files for user-installed applications (in /*data/dalvik-cache/*), the system package database (in */data/system/packages.xml*), and other system databases and settings files. (We’ll discuss the rest of the *userdata* partition directories shown in [Figure 3-1](ch03.html#package_management_components "Figure 3-1. Package management components") when we cover the APK install process.)

## Active Components

Having established the roles of the *userdata* and *system* partitions, let’s introduce the active components that play a role during package installation.

### PackageInstaller System Application

This is the default APK file handler. It provides a basic GUI for package management and when passed an APK file URI with the `VIEW` or `INSTALL_ACTION` intent action, it parses the package and displays an install confirmation screen showing the permissions the application requires (see [Figure 2-1](ch02.html#default_android_application_install_conf "Figure 2-1. Default Android application install confirmation dialog")). Installation using the `PackageInstaller` application is only possible if the user has enabled the Unknown Sources option in the device’s security settings (see [Figure 3-2](ch03.html#application_install_security_settings "Figure 3-2. Application install security settings")). If Unknown Sources is not enabled, `PackageInstaller` will show a dialog informing the user that installation of apps obtained from unknown sources is blocked.

![Application install security settings](figs/web/03fig02.png.jpg)

Figure 3-2. Application install security settings

What is considered an “unknown source”? While the on-screen hint defines it as “apps from sources other than the Play Store,” the actual definition is a bit more broad. When started, `PackageInstaller` retrieves the UID and package of the app that requested APK installation and checks to see if it is a privileged app (installed in */system/priv-app/*). If the requesting app is unprivileged, it is considered an unknown source. If the Unknown Sources option is selected and the user okays the install dialog, `PackageInstaller` calls the `PackageManagerService`, which performs the actual installation. The `PackageInstaller` GUI is also shown when upgrading side-loaded packages or uninstalling apps from the Apps screen of System Settings.

### pm command

The `pm` command (introduced in [Chapter 2](ch02.html "Chapter 2. Permissions")) provides a command-line interface to some of the functions of the system package manager. It can be used to install or uninstall packages when invoked as `pm install` or `pm uninstall` from the Android shell, respectively. Additionally, the *Android Debug Bridge (ADB)* client provides the `adb install/uninstall` shortcuts.

Unlike the `PackageInstaller`, `pm install` does not depend on the Unknown Sources system option and does not display a GUI, and it provides various useful options for testing package installation that cannot be specified via the `PackageInstaller` GUI. To start the install process, it calls the same `PackageManager` API as the GUI installer.

### PackageManagerService

The `PackageManagerService` (`PackageManager` in [Figure 3-1](ch03.html#package_management_components "Figure 3-1. Package management components")) is the central object in Android’s package management infrastructure. It is responsible for parsing APK files, starting the application install, upgrading and uninstalling packages, maintaining the package database, and managing permissions.

The `PackageManagerService` also provides a number of `installPackage()` methods that can perform package installation with various options. The most general of these is the `installPackageWithVerificationAndEncryption()`, which allows for the installation of an encrypted APK file, and package verification by a verification agent. (We’ll discuss app encryption and verification later in “[Installing Encrypted APKs](ch03.html#installing_encrypted_apks "Installing Encrypted APKs")” and “[Package Verification](ch03.html#package_verification "Package Verification")”.)

### Note

*The `android.content.pm.PackageManager` Android SDK facade class exposes a subset of the functionality of the `PackageManagerService` to third-party applications.*

### Installer class

While the `PackageManagerService` is one of the most privileged Android system services, it still runs inside the system server process (with the *system* UID) and lacks root privileges. However, because creating, deleting, and changing the ownership of application directories requires superuser capabilities, the `PackageManagerService` delegates those operations to the *installd* daemon (discussed next). The `Installer` class connects to the *installd* daemon through the */dev/socket/installd* Unix domain socket and encapsulates the *installd* command-oriented protocol.

### installd Daemon

The *installd* daemon is a native daemon with elevated privileges that provides application and user directory management functionality (for multi-user devices) to the system package manager. It is also used to start the `dexopt` command, which generates optimized DEX files for newly installed packages.

The *installd* daemon is accessed via the *installd* local socket, which is only accessible to processes running as the *system* UID. The *installd* daemon does not execute as root (although it used to do so in earlier Android versions), but instead takes advantage of the `CAP_DAC_OVERRIDE` and `CAP_CHOWN` Linux capabilities^([[23](#ftn.ch03fn07)]) in order to be able to set the owner and group UID of the application directories and files it creates to those of the owning application.

### MountService

The `MountService` is responsible for mounting detachable external storage such as SD cards, as well as *opaque binary blob (OBB) files*, which are used as expansion files for applications. It is also used to kick off device encryption (see [Chapter 10](ch10.html "Chapter 10. Device Security")) and to change the encryption password.

`MountService` also manages *secure containers*, which hold applications files that should not be accessible to non-system applications. Secure containers are encrypted and used to implement a form of DRM called *forward locking* (discussed in “[Forward Locking](ch03.html#forward_locking "Forward Locking")” and “[Android 4.1 Forward Locking Implementation](ch03.html#android_4dot1_forward_locking_implementa "Android 4.1 Forward Locking Implementation")”). Forward locking is used primarily when installing paid applications in order to ensure that their APK files cannot be easily copied off the device and redistributed.

### vold daemon

*vold* is Android’s volume management daemon. While the `MountService` contains most system APIs that deal with volume management, because it runs as the *system* user it lacks the privileges required to actually mount and unmount disk volumes. Those privileged operations are implemented in the *vold* daemon, which runs as root.

*vold* has a local socket interface which is exposed via the */dev/socket/ vold* Unix domain socket that is only accessible to root and members of the *mount* group. Because the list of supplementary GIDs of the *system_server* process (which hosts `MountService`) includes *mount* (GID 1009), `MountService` is allowed to access *vold*’s command socket. Besides mounting and unmounting volumes, *vold* can also create and format filesystems and manage secure containers.

### MediaContainerService

The `MediaContainerService` copies APK files to their final install location or to an encrypted container, and allows the `PackageManagerService` to access files on removable storage. APK files obtained from a remote location (either directly or through an application market) are downloaded using Android’s `DownloadManager` service and the downloaded files are accessed through `DownloadManager`’s content provider interface. The `PackageManager` grants temporary access to each downloaded APK to the `MediaContainerService` process. If the APK file is encrypted, `MediaContainerService` decrypts the file first (as discussed in “[Installing an Encrypted APK with Integrity Check](ch03.html#installing_an_encrypted_apk_with_integri "Installing an Encrypted APK with Integrity Check")”). If an encrypted container was requested, `MediaContainerService` delegates encrypted container creation to the `MountService` and copies the protected part of the APK (both code and assets) into the newly created container. Files that do not need to be protected by a container are copied directly to the filesystem.

### AppDirObserver

An `AppDirObserver` is a component that monitors an application directory for APK file changes^([[24](#ftn.ch03fn08)]) and calls the appropriate `PackageManagerService` method based on the event type. When an APK file is added to the system, `AppDirObserver` kicks off a package scan which either installs or updates the application. When an APK file is removed, `AppDirObserver` starts the uninstall process, which removes app directories and the app entry in the system package database.

[Figure 3-1](ch03.html#package_management_components "Figure 3-1. Package management components") shows a single `AppDirObserver` instance due to space constraints, but there is a dedicated instance for each watched directory. The directories monitored on the *system* partition are */system/framework/* (which holds the framework resource package *framework-res.apk*); */system/ app/* and */system/priv-app/* (system packages); and the vendor package directory */system/vendor/app/*. The directories monitored on the *userdata* partition are */data/app/* and */data/app-private/* which hosts “old style” (pre-Android 4.1) forward locked APKs and temporary files produced during APK decryption.

## Installing a Local Package

Now that we know what Android components are involved in package installation, we’ll cover the install process, beginning with the simplest case: installing an unencrypted local package without verification and forward locking.

### Parsing and Verifying the Package

Opening a local APK file starts the *application/vnd.android.package-archive* handler, typically the `PackageInstallerActivity` from the `PackageInstaller` system application. `PackageInstallerActivity` first checks to see if the application that requested the install is trusted (that is, not considered from an “unknown source”). If it is not, and the `Settings.Global.INSTALL_NON_MARKET_APPS` is `false` (it is set to `true` when the Unknown sources checkbox in [Figure 3-2](ch03.html#application_install_security_settings "Figure 3-2. Application install security settings") is checked), `PackageInstaller` shows a warning dialog and ends the install process.

If the installation is allowed, the `PackageInstallerActivity` parses the APK file and collects information from the *AndroidManifest.xml* file and package signature. The integrity of the APK file is verified automatically while extracting the signing certificates for each of its entries using the `java.util.jar.JarFile` and related classes. This implementation is necessary because the API of the `JarFile` class lacks any explicit methods to verify the signature of the whole file or of a particular entry. (System applications are implicitly trusted and only the integrity of the *AndroidManifest.xml* file is verified when parsing their APK files. However, all APK entries are verified for packages that are not part of the system image, such as user-installed applications or updates for system applications.) The hash value of the *AndroidManifest.xml* file is also calculated as part of APK parsing and passed to subsequent install steps, which use it to verify that the APK file was not replaced between the time when the user pressed OK in the install dialog and the APK copy process was started.

### Note

*Another noteworthy detail is that while at install time, APK file integrity is verified using standard Java library classes, at runtime, the Dalvik virtual machine loads APK files using its own native implementation of a ZIP/JAR file parser. Subtle differences in their implementations have been the source of several Android bugs, most notably bug #8219321 (commonly known as the* Android Master Key*) which allows a signed APK file to be modified and still considered valid without resigning. A `StrictJarFile` class, which uses the same ZIP file parsing implementation as Dalvik, has been added in AOSP’s master branch in order to address this. `StrictJarFile` is used by the system package manager when parsing APK files, ensuring that both Dalvik and the package manager parse APK files in the same way. This new unified implementation should be incorporated in future Android versions.*

### Accepting Permissions and Starting the Install Process

Once the APK has been parsed, `PackageInstallerActivity` displays information about the application and the permissions it requires in a dialog similar to the one shown in [Figure 2-1](ch02.html#default_android_application_install_conf "Figure 2-1. Default Android application install confirmation dialog"). If the user OK’s the install, `PackageInstallerActivity` forwards the APK file and its manifest digest, along with install metadata such as the referrer URL, the installer package name, and originating UID to the `InstallAppProgress` activity, which starts the actual package install process. `InstallAppProgress` then passes the APK URI and install metadata to the `installPackageWithVerificationAndEncryption()` method of the `PackageManagerService`, starting the install process. It then waits for the process to complete and handles any errors.

The install method first verifies that the caller has the `INSTALL_PACKAGES` permission, which has a protection-level *signature* and is reserved for system applications. On multi-user devices, the method also verifies whether the calling user is allowed to install applications. Next, it determines the preferred install location, which is either internal or external storage.

### Copying to the Application Directory

If the APK file is not encrypted and no verification is required, the next step is to copy it to the application directory (*/data/app/*). To copy the file, the `PackageManagerService` first creates a temporary file in the application directory (with the *vmdl* prefix and *.tmp* extension) and then delegates copying to the `MediaContainerService`. The file is not copied directly because it might need to be decrypted, or an encrypted container created for it if it will be forward locked. Because the `MediaContainerServices` encapsulates these tasks, the `PackageManagerService` does not need to be concerned with the underlying implementation.

When the APK file is successfully copied, any native libraries it contains are extracted to a dedicated app directory under the system’s native library directory (*/data/app-lib/*). Next, the temporary APK file and the library directory are renamed to their final names, which are based on the package name, such as *com.example.app-1.apk* for the APK and */data/app-lib/com.example.app-1* for the library directory. Finally, the APK file permissions are set to *0644* and its SELinux context is set (see [Chapter 12](ch12.html "Chapter 12. Selinux")).

### Note

*By default, APK files are world-readable and any other application can access them. This facilitates sharing public app resources and allows the development of third-party launchers and other applications that need to show a list of all installed packages. However, those default permissions also allow anyone to extract APK files from a device, which is problematic for paid applications distributed via an application market. APK file forward locking provides a way for APK resources to remain public, while limiting access to code and assets.*

### The Package Scan

The next step in the install process is to trigger a package scan by calling the `scanPackageLI()` method of `PackageManagerService`. (If the install process stops before scanning the new APK file, it will eventually be picked up by the `AppDirObserver` instance which monitors the */data/app/* directory and also triggers a package scan.)

In the case of a new install, the package manager first creates a new `PackageSettings` structure that contains the package name, code path, a separate resource path if the package is forward-locked, and a native library path. It then assigns a UID to the new package and stores it in the settings structure. Once the new app has a UID, its data directory can be created.

### Creating Data Directories

Because the `PackageManagerService` does not have enough privileges to create and set ownership of app directories, it delegates directory creation to the *installd* daemon by sending it the `install` command which takes the package name, UID, GID, and *seinfo* tag (used by SELinux) as parameters. The *installd* daemon creates the package data directory (for example, */data/data/com.example.app/* when installing the *com.example.app* package), shared native library directory (*/data/app-lib/com.example.app/*), and local library directory (*/data/data/com.example.app/lib/*). It then sets the package directory permissions to *0751* and creates symbolic links for the app’s native libraries (if any) in the local library directory. Finally, it sets the SELinux context of the package directory and changes its owner to the UID and GID assigned to the app.

If the system has more than one user, the next step is to create data directories for each user by sending the `mkuserdata` command to *installd* (see [Chapter 4](ch04.html "Chapter 4. User Management")). When all the necessary directories are created, control returns to the `PackageManagerService`, which extracts any native libraries to the application’s native library directory and creates symbolic links in */data/data/com.example.app/lib/*.

### Generating Optimized DEX

The next step is to generate optimized DEX for the application’s code. This operation is also delegated to *installd* by sending it the `dexopt` command. The *installd* daemon forks a *dexopt* process, which creates the optimized DEX file in the */data/dalivk-cache/* directory. (The optimization process is also referred to as “sharpening.”)

### Note

*If the device is using the experimental Android Runtime (ART) introduced in version 4.4 instead of generating optimized DEX,* installd *generates native code using the `dex2oat` command.*

### File and Directory Structure

When all of the above processes have completed, the application’s files and directories might look something like [Example 3-12](ch03.html#files_and_directories_created_after_inst "Example 3-12. Files and directories created after installing an application"). (Timestamps and file sizes have been omitted.)

Example 3-12. Files and directories created after installing an application

```
-rw-r--r-- system   system   ... /data/app/com.example.app-1.apk➊
-rwxr-xr-x system   system   ... /data/app-lib/com.example.app-1/libapp.so➋
-rw-r--r-- system   all_a215 ... /data/dalvik-cache/data@app@com.example.app-1.apk@classes.dex➌
drwxr-x--x u0_a215  u0_a215  ... /data/data/com.example.app➍
drwxrwx--x u0_a215  u0_a215  ... /data/data/com.example.app/databases➎
drwxrwx--x u0_a215  u0_a215  ... /data/data/com.example.app/files
lrwxrwxrwx install  install  ... /data/data/com.example.app/lib -> /data/app-lib/com.example.app-1➏
drwxrwx--x u0_a215  u0_a215  ... /data/data/com.example.app/shared_prefs
```

Here, ➊ is the APK file and ➋ is the extracted native library file. Both files are owned by *system* and are world readable. The file at ➌ is the optimized DEX file for the application’s code. Its owner is set to *system* and its group is set to the special *all_a215* group, which includes all device users that have installed the app. This allows all users to share the same optimized DEX file, thus avoiding the need to create a copy for each user, which could take up too much disk space on a multi-user device. The application’s data directory ➍ and its subdirectories (such as *databases/* ➎) are owned by the dedicated Linux user created by combining the ID of the device user that installed the application (*u0*, the sole user on single-user devices) and the app ID (*a215*) to produce *u0_a215*. (App data directories are not readable or writable by other users in accordance with Android’s sandboxing security model. The *lib/* directory ➏ is merely a symbolic link to the app’s shared library directory in */data/app-lib/*.)

### Adding the New Package to packages.xml

The next step is to add the package to the system package database. A new package entry that looks like [Example 3-13](ch03.html#package_database_entry_for_a_newly_insta "Example 3-13. Package database entry for a newly installed application") is generated and added to *packages.xml*.

Example 3-13. Package database entry for a newly installed application

```
<package name="com.google.android.apps.chrometophone"
         codePath="/data/app/com.google.android.apps.chrometophone-2.apk"
         nativeLibraryPath="/data/app-lib/com.google.android.apps.chrometophone-2"
         flags="572996"
         ft="142dfa0e588"
         it="142cbeac305"
         ut="142dfa0e8d7"
         version="16"
         userId="10088"
         installer="com.android.vending">➊
    <sigs count="1">
        <cert index="7" key="30820252..." />
    </sigs>➋
    <perms>
        <item name="android.permission.USE_CREDENTIALS" />
        <item name="com.google.android.apps.chrometophone.permission.C2D_MESSAGE" />
        <item name="android.permission.GET_ACCOUNTS" />
        <item name="android.permission.INTERNET" />
        <item name="android.permission.WAKE_LOCK" />
        <item name="com.google.android.c2dm.permission.RECEIVE" />
    </perms>➌
    <signing-keyset identifier="2" />➍
</package>
```

Here, the `<sigs>` ➋ element holds the DER-encoded values of the package signing certificates (typically only one) in hexadecimal string format, or a reference to the first occurrence of the certificate in the case of multiple apps signed by the same key and certificate. The `<perms>` ➌ elements holds the permissions granted to the application, as described in [Chapter 2](ch02.html "Chapter 2. Permissions").

The `<signing-keyset>` ➍ element is new in Android 4.4 and holds a reference to the signing key set of the application, which contains all public keys (but *not* certificates) that have signed files inside the APK. The `PackageManagerService` collects and stores signing keys for all applications in a global `<keyset-settings>` element, but key sets are not checked or otherwise used as of Android 4.4.

### Package Attributes

The root element `<package>` ➊ (shown in [Example 3-13](ch03.html#package_database_entry_for_a_newly_insta "Example 3-13. Package database entry for a newly installed application")) holds the core attributes of each package, such as install location and version. The main package attributes are listed in [Table 3-1](ch03.html#package_attributes-id00005 "Table 3-1. Package Attributes"). The information in each package entry can be obtained via the `getPackageInfo(String packageName, int flags)` method of the `android.content.pm.PackageManager` SDK class, which should return a `PackageInfo` instance that encapsulates the attributes available in each *packages.xml* entry, as well as information about components, permissions, and features defined in the application’s manifest.

Table 3-1. Package Attributes

| Attribute Name | Description |
| --- | --- |
| `name` | The package name. |
| `codePath` | Full path to the location of the package. |
| `resourcePath` | Full path to the location of the publicly available parts of the package (primary resource package and manifest). Only set on forward-locked apps. |
| `nativeLibraryPath` | Full path to the directory where native libraries are stored. |
| `flags` | Flags associated with the application. |
| `ft` | APK file timestamp (Unix time in milliseconds, as per `System.currentTimeMillis()`). |
| `it` | The time at which the app was first installed (Unix time in milliseconds). |
| `ut` | The time the app was last updated (Unix time in milliseconds). |
| `version` | The version number of the package, as specified by the `versionCode` attribute in the app manifest. |
| `userId` | The kernel UID assigned to the application. |
| `installer` | The package name of the application that installed the app. |
| `sharedUserId` | The shared user ID name of the package, as specified by the `sharedUserId` attribute in the manifest. |

### Updating Components and Permissions

After creating the *packages.xml* entry, the `PackageManagerService` scans all Android components defined in the new application’s manifests and adds them to its internal on-memory component registry. Next, any permission groups and permissions the app declares are scanned and added to the permission registry.

### Note

*Custom permissions defined by applications are registered using a “first one wins” strategy: if both app A and B define permission P, and A is installed first, A’s permission definition is registered and B’s permission definition is ignored (because P is already registered). This is possible because permission names are not bound to the defining app package in any way, and thus any app can define any permission. This “first one wins” strategy can result in permission protection level downgrade: if A’s permission definition has a lower protection level (for example,* normal*) than B’s definition (for example,* signature*), and A is installed first, access to B’s components protected by P will not require callers to be signed with the same key as B. Therefore, when using custom permissions to protect components, be sure to check whether the currently registered permission has the protection level your app expects.*^([[25](#ftn.ch03fn09)])

Finally, changes to the package database (the package entry and any new permissions) are saved to disk and the `PackageManagerService` sends the `ACTION_PACKAGE_ADDED` to notify other components about the newly added application.

## Updating a Package

The process of updating a package follows most of the same steps as installing a package, so we’ll highlight only the differences here.

### Signature Verification

The first step is to check whether the new package has been signed by the same set of signers as the existing one. This rule is referred to as *same origin policy*, or *Trust On First Use (TOFU)*. This signature check guarantees that the update is produced by the same entity as the original application (assuming that the signing key has not been compromised) and establishes a trust relationship between the update and the existing application. As we shall see in “[Updating Non-System Apps](ch03.html#updating_non-system_apps "Updating Non-System Apps")”, the update inherits the data of the original application.

### Note

*When signing certificates are compared for equality, the certificates are not validated in the PKI sense of the word (time validity, trusted issuer, revocation, and so on are not checked).*

The certificate equality check is performed by the `PackageManagerService.compareSignatrues()` method as shown in [Example 3-14](ch03.html#package_signature_comparison_method "Example 3-14. Package signature comparison method").

Example 3-14. Package signature comparison method

```
static int compareSignatures(Signature[] s1, Signature[] s2) {
    if (s1 == null) {
        return s2 == null
            ? PackageManager.SIGNATURE_NEITHER_SIGNED
            : PackageManager.SIGNATURE_FIRST_NOT_SIGNED;
    }
    if (s2 == null) {
        return PackageManager.SIGNATURE_SECOND_NOT_SIGNED;
    }
    HashSet<Signature> set1 = new HashSet<Signature>();
    for (Signature sig : s1) {
        set1.add(sig);
    }
    HashSet<Signature> set2 = new HashSet<Signature>();
    for (Signature sig : s2) {
        set2.add(sig);
    }
    // Make sure s2 contains all signatures in s1.
    if (set1.equals(set2)) {➊
        return PackageManager.SIGNATURE_MATCH;
    }
    return PackageManager.SIGNATURE_NO_MATCH;
}
```

Here, the `Signature` class serves as an “opaque, immutable representation of a signature associated with an application package.” ^([[26](#ftn.ch03fn10)]) In practice, it is a wrapper for the DER-encoded signing certificate associated with an APK file. [Example 3-15](ch03.html#package_signature_representation "Example 3-15. Package signature representation") shows an excerpt, focusing on its `equals()` and `hashCode()` methods.

Example 3-15. Package signature representation

```
public class Signature implements Parcelable {
    private final byte[] mSignature;
    private int mHashCode;
    private boolean mHaveHashCode;
    --*snip*--
    public Signature(byte[] signature) {
        mSignature = signature.clone();
    }

    public PublicKey getPublicKey() throws CertificateException {
        final CertificateFactory certFactory =
                CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bais = new ByteArrayInputStream(mSignature);
        final Certificate cert = certFactory.generateCertificate(bais);
        return cert.getPublicKey();
    }

    @Override
    public boolean equals(Object obj) {
        try {
            if (obj != null) {
                Signature other = (Signature)obj;
                return this == other
                    || Arrays.equals(mSignature, other.mSignature);➊
            }
        } catch (ClassCastException e) {
        }
        return false;
    }

    @Override
    public int hashCode() {
        if (mHaveHashCode) {
            return mHashCode;
        }
        mHashCode = Arrays.hashCode(mSignature);➋
        mHaveHashCode = true;
        return mHashCode;
    }
--*snip*--
}
```

As you can see at ➊, two signature classes are considered equal if the DER-encoding of the underlying X.509 certificates match exactly, and the `Signature` class hash code is calculated solely based on the encoded certificate ➋. If the signing certificates do not match, the `compareSignatures()` methods returns the `INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES` error code.

This binary certificate comparison naturally knows nothing about CAs or expiration dates. One consequence of this is that after an app (identified by a unique package name) is installed, updates need to use the same signing certificates (with the exception of system app updates, as discussed in “[Updating System Apps](ch03.html#updating_system_apps "Updating System Apps")”).

While multiple signatures on Android apps are rare, they do occur. If the original application was signed by more than one signer, any updates need to be signed by the same signers, each using its original signing certificate (enforced by ➊ in [Example 3-14](ch03.html#package_signature_comparison_method "Example 3-14. Package signature comparison method")). This means that if a developer’s signing certificate(s) expires or he loses access to his signing key, he cannot update the app and must release a new one instead. This would result in not only losing any existing user base or ratings, but more importantly losing access to the legacy app’s data and settings.

The solution to this problem is straightforward, if not ideal: back up your signing key and don’t let your certificate expire. The currently recommended validity period is at least 25 years, and the Google Play Store requires validity until at least October 2033\. While technically this only amounts to putting off the problem, proper certificate migration support might eventually be added to the platform.

When the package manager establishes that the update has been signed with the same certificate, it proceeds with updating the package. The process is different for system and user-installed apps, as described next.

### Updating Non-System Apps

Non-system apps are updated by essentially reinstalling the app while retaining its data directory. The first step is to kill any process of the package being updated. Next, the package is removed from internal structures and the package database, which removes all components that the app has registered as well. Next, the `PackageManagerService` triggers a package scan by calling the `scanPackageLI()` method. The scan proceeds as it would with new installs, except that it updates the package’s code, resource path, version, and timestamp. The package manifest is scanned and any defined components are registered with the system. Next, permissions for all packages are re-granted to ensure that they match any definitions in the updated package. Finally, the updated packaged database is written to disk and a `PACKAGE_REPLACED` system broadcast is sent.

### Updating System Apps

As with user-installed apps, preinstalled apps (usually found in */system/app/*) can be updated without a full-blown system update, usually via the Google Play Store or a similar app distribution service. Though because the *system* partition is mounted read-only, updates are installed in */data/app/*, while the original app is left intact. In addition to a `<package>` entry, the updated app will also have an `<updated-package>` entry that might look like the example in [Example 3-16](ch03.html#package_database_entries_for_an_updated "Example 3-16. Package database entries for an updated system package").

Example 3-16. Package database entries for an updated system package

```
<package name="com.google.android.keep"
         codePath="/data/app/com.google.android.keep-1.apk"➊
         nativeLibraryPath="/data/app-lib/com.google.android.keep-1"
         flags="4767461"➋
         ft="142ee64d980"
         it="14206f3e320"
         ut="142ee64dfcb"
         version="2101"
         userId="10053"➌
         installer="com.android.vending">
    <sigs count="1">
        <cert index="2" />
    </sigs>
    <signing-keyset identifier="3" />
    <signing-keyset identifier="34" />
</package>
--*snip*--
<updated-package name="com.google.android.keep"
                 codePath="/system/app/Keep.apk"
                 nativeLibraryPath="/data/app-lib/Keep"
                 ft="ddc8dee8"
                 it="14206f3e320"
                 ut="ddc8dee8"
                 version="2051"
                 userId="10053">➍
    <perms>
        <item name="android.permission.READ_EXTERNAL_STORAGE" />
        <item name="android.permission.USE_CREDENTIALS" />
        <item name="android.permission.WRITE_EXTERNAL_STORAGE" />
        --*snip*--
    </perms>
</updated-package>
```

The update’s `codePath` attribute is set to the path of the new APK in */data/app/* ➊. It inherits the original app’s permissions and UID (➌ and ➍) and is marked as an update to a system app by adding the `FLAG_UPDATED_SYSTEM_APP` (0x80) to its `flags` attribute ➋.

System apps can be updated directly in the *system* partition as well, usually as the result of an OTA system update, and in such case the updated system APK is allowed to be signed with a different certificate. The rationale behind this is that if the installer has enough privileges to write to the *system* partition, it can be trusted to change the signing certificate as well. The UID, and any files and permissions, are retained. The exception is that if the package is part of a shared user (discussed in [Chapter 2](ch02.html "Chapter 2. Permissions")), the signature cannot be updated, because doing so would affect other apps. In the reverse case, when a new system app is signed by a different certificate than that of the currently installed non-system app (with the same package name), the non-system app will be deleted first.

## Installing Encrypted APKs

Support for installing encrypted APKs was added in Android 4.1 along with support for forward locking using ASEC containers. Both features were announced as *app encryption*, but we’ll discuss them separately, beginning with support for encrypted APK files. But first let’s see how to install encrypted APKs.

Encrypted APKs can be installed using the Google Play Store client, or with the `pm` command from the Android shell, but the system `PackageInstaller` does not support encrypted APKs. Because we can’t control the Google Play Store installation flow, in order to install an encrypted APK we need to either use the `pm` command or write our own installer app. We’ll take the easy route and use the `pm` command.

### Creating and Installing an Encrypted APK

The `adb install` command both copies the APK file to a temporary file on the device and starts the install process. The command provides a convenient wrapper to the `adb push` and `pm install` commands. `adb install` gained three new parameters in Android 4.1 in order to support encrypted APKs (see [Example 3-17](ch03.html#adb_install_command_options "Example 3-17. adb install command options")).

Example 3-17. `adb install` command options

```
adb install [-l] [-r] [-s] [--algo <algorithm name> --key <hex-encoded key>
--iv <hex-encoded iv>] <file>
```

The `--algo`, `--key`, and `--iv` parameters let you specify the encryption algorithm, key, and initialization vector (IV), respectively. But in order to use those new parameters, we need to create an encrypted APK first.

An APK file can be encrypted using the `enc` OpenSSL commands as shown in [Example 3-18](ch03.html#encrypting_an_apk_file_using_openssl "Example 3-18. Encrypting an APK file using OpenSSL"). Here we use AES in CBC mode with a 128-bit key, and specify an IV that is the same as the key in order to make things simpler.

Example 3-18. Encrypting an APK file using OpenSSL

```
$ **openssl enc -aes-128-cbc -K 000102030405060708090A0B0C0D0E0F**
**-iv 000102030405060708090A0B0C0D0E0F -in my-app.apk -out my-app-enc.apk**
```

Next, we install our encrypted APK by passing the encryption algorithm key (in `javax.crypto.Cipher` transformation string format, which is discussed in [Chapter 5](ch05.html "Chapter 5. Cryptographic Providers")) and IV bytes to the `adb install` command as shown in [Example 3-19](ch03.html#installing_an_encrypted_apk_using_adb_in "Example 3-19. Installing an encrypted APK using adb install").

Example 3-19. Installing an encrypted APK using `adb install`

```
$ **adb install --algo 'AES/CBC/PKCS5Padding' \**
**--key 000102030405060708090A0B0C0D0E0F \**
**--iv 000102030405060708090A0B0C0D0E0F my-app-enc.apk**
        pkg: /data/local/tmp/my-app-enc.apk
Success
```

As the `Success` output indicates, the APK installs without errors. The actual APK file is copied into */data/app/*, and comparing its hash with our encrypted APK reveals that it is in fact a different file. The hash value is exactly the same as that of the original (unencrypted) APK, so we conclude that the APK is decrypted at install time using the provided encryption parameters (algorithm, key, and IV).

### Implementation and Encryption Parameters

Let’s see how this is implemented. After it has transferred the APK to the device, `adb install` calls the `pm` Android command-line utility with the `install` parameter and the path to the copied APK file. The component responsible for installing apps on Android is `PackageManagerService` and the `pm` command is just a convenient frontend for some of its functionality. When started with the `install` parameter, `pm` calls the method `installPackageWithVerificationAndEncryption()`, converting its options to the relevant parameters as necessary. [Example 3-20](ch03.html#packagemanagerservicedotinstallpackagewi "Example 3-20. PackageManagerService.installPackageWithVerificationAndEncryption() method signature") shows the method’s full signature.

Example 3-20. `PackageManagerService.installPackageWithVerificationAndEncryption()` method signature

```
public void installPackageWithVerificationAndEncryption(Uri packageURI,
        IPackageInstallObserver observer, int flags,
        String installerPackageName,
        VerificationParams verificationParams,
        ContainerEncryptionParams encryptionParams) {
--*snip*--
}
```

We discussed most of the method’s parameters in “[APK Install Process](ch03.html#apk_install_process "APK Install Process")” earlier, but we have yet to encounter the `VerificationParams` and `ContainerEncryptionParams` classes. As the name implies, the `VerificationParams` class encapsulates a parameter used during package verification, which we will discuss in “[Package Verification](ch03.html#package_verification "Package Verification")”. The `ContainerEncryptionParams` class holds encryption parameters, including the values passed via the `--algo`, `--key`, and `--iv` options of `adb install`. [Example 3-21](ch03.html#containerencryptionparams_data_members "Example 3-21. ContainerEncryptionParams data members") shows its data members.

Example 3-21. `ContainerEncryptionParams` data members

```
public class ContainerEncryptionParams implements Parcelable {
    private final String mEncryptionAlgorithm;
    private final IvParameterSpec mEncryptionSpec;
    private final SecretKey mEncryptionKey;
    private final String mMacAlgorithm;
    private final AlgorithmParameterSpec mMacSpec;
    private final SecretKey mMacKey;
    private final byte[] mMacTag;
    private final long mAuthenticatedDataStart;
    private final long mEncryptedDataStart;
    private final long mDataEnd;
    --*snip*--
}
```

The `adb install` parameters above correspond to the first three fields of the class. While not available through the `adb install` wrapper, the `pm install` command also takes the `--macalgo`, `--mackey`, and `--tag` parameters, which correspond to the `mMacAlgorithm`, `mMacKey`, and `mMacTag` fields of the `ContainerEncryptionParams` class. In order to use those parameters, we need to calculate the MAC value of the encrypted APK first, which we accomplish with the OpenSSL `dgst` command as shown in [Example 3-22](ch03.html#calculating_the_mac_of_an_encrypted_apk "Example 3-22. Calculating the MAC of an encrypted APK").

Example 3-22. Calculating the MAC of an encrypted APK

```
$ **openssl dgst -hmac 'hmac_key_1' -sha1 -hex my-app-enc.apk**
HMAC-SHA1(my-app-enc.apk)= 962ecdb4e99551f6c2cf72f641362d657164f55a
```

### Note

*The `dgst` command doesn’t allow you to specify the HMAC key using hexadecimal or Base64, so we’re limited to ASCII characters. This may not be a good idea for production use, so consider using a real key and calculating the MAC in some other way (for example, using a JCE program).*

### Installing an Encrypted APK with Integrity Check

We can now install an encrypted APK and verify its integrity by opening the Android shell using `adb shell` and executing the command shown in [Example 3-23](ch03.html#installing_an_encrypted_apk_with-id00006 "Example 3-23. Installing an encrypted APK with integrity verification using pm install").

Example 3-23. Installing an encrypted APK with integrity verification using `pm install`

```
$ **pm install -r --algo 'AES/CBC/PKCS5Padding' \**
**--key 000102030405060708090A0B0C0D0E0F \**
**--iv 000102030405060708090A0B0C0D0E0F \**
**--macalgo HmacSHA1 --mackey 686d61635f6b65795f31 \**
**--tag 962ecdb4e99551f6c2cf72f641362d657164f55a /sdcard/my-app-enc.apk**
        pkg: /sdcard/kr-enc.apk
Success
```

The app’s integrity is checked by comparing the specified MAC tag with the value calculated based on the actual file contents, the contents are decrypted, and the decrypted APK is copied to */data/app/*. (To test that MAC verification is indeed performed, change the tag value slightly. Doing so should result in an install error with error code `INSTALL_FAILED_INVALID_APK`.)

As we saw in [Example 3-19](ch03.html#installing_an_encrypted_apk_using_adb_in "Example 3-19. Installing an encrypted APK using adb install") and [Example 3-23](ch03.html#installing_an_encrypted_apk_with-id00006 "Example 3-23. Installing an encrypted APK with integrity verification using pm install"), the APK files that are ultimately copied to */data/app/* are not encrypted and thus the installation process is the same as for unencrypted APKs, except for file decryption and the optional integrity verification. Decryption and integrity verification are performed transparently by the `MediaContainerService` while copying the APK to the application directory. If a `ContainerEncryptionParams` instance is passed to its `copyResource()` method, it uses the provided encryption parameters to instantiate the JCA classes `Cipher` and `Mac` (see [Chapter 5](ch05.html "Chapter 5. Cryptographic Providers")) that can perform decryption and integrity checking.

### Note

*The MAC tag and encrypted APK can be bundled in a single file, in which case the `MediaContainerService` uses the `mAuthenticatedDataStart`, `mEncryptedDataStart`, and `mDataEnd` members to extract the MAC and APK data from the file.*

## Forward Locking

Forward locking appeared around the time ringtones, wallpapers, and other digital “goods” started selling on feature phones. Because installed APK files are world readable on Android, it’s relatively easy to extract apps from even a production device. In an attempt to lock down paid apps (and prevent a user from forwarding them to another user) without losing any of the OS’s flexibility, early Android versions introduced forward locking (also called *copy protection*).

The idea behind forward locking was to split app packages into two parts: a world-readable part that contains resources and the manifest (in */data/app/*), and a package that is readable only by the *system* user and which contains executable code (in */data/app-private/*). The code package was protected by filesystem permissions, which made it inaccessible to users on most consumer devices, but it could be extracted from devices with root access, and this early forward locking mechanism was quickly deprecated and replaced with an online application licensing service called Google Play Licensing.

The problem with Google Play Licensing was that it shifted app protection implementation from the OS to app developers, and it had mixed results. The forward locking implementation was redesigned in Android 4.1, and now offers the ability to store APKs in an encrypted container that requires a device-specific key to be mounted at runtime. Let’s look at it in a bit more detail.

## Android 4.1 Forward Locking Implementation

While the use of encrypted app containers as a forward locking mechanism was introduced in Android version 4.1, encrypted containers were originally introduced in Android 2.2\. At that time (mid-2010), most Android devices came with limited internal storage and relatively large (a few gigabytes) external storage, usually in the form of a microSD card. To make file sharing easier, external storage was formatted using the FAT filesystem, which lacks file permissions. As a result, files on the SD card could be read and written by any application.

To prevent users from simply copying paid apps from the SD card, Android 2.2 created an encrypted filesystem image file and stored the APK in it when a user opted to move an app to external storage. The system would then create a mount point for the encrypted image, and mount it using Linux’s device-mapper. Android loaded each app’s files from its mount point at runtime.

Android 4.1 built on this idea by making the container use the ext4 filesystem, which allows for file permissions. A typical forward-locked app’s mount point now looks like [Example 3-24](ch03.html#contents_of_a_forward-locked_appapostrop "Example 3-24. Contents of a forward-locked app’s mount point") (timestamps omitted).

Example 3-24. Contents of a forward-locked app’s mount point

```
# **ls -l /mnt/asec/com.example.app-1**
drwxr-xr-x system   system             lib
drwx------ root     root               lost+found
-rw-r----- system   u0_a96     1319057 pkg.apk
-rw-r--r-- system   system      526091 res.zip
```

Here, the *res.zip* holds app resources and the manifest file and is world readable, while the *pkg.apk* file that holds the full APK is only readable by the system and the app’s dedicated user (*u0_a96*). The actual app containers are stored in */data/app-asec/* in files with the *.asec* extension.

### Encrypted App Containers

Encrypted app containers are referred to as *Android Secure External Caches*, or *ASEC containers.* ASEC container management (creating, deleting, mounting, and unmounting) is implemented in the system volume daemon (*vold*), and the `MountService` provides an interface to its functionality to framework services. We can also use the `vdc` command-line utility to interact with *vold* in order to manage forward-locked apps from Android’s shell (see [Example 3-25](ch03.html#issuing_asec_management_commands_with_vd "Example 3-25. Issuing ASEC management commands with vdc")).

Example 3-25. Issuing ASEC management commands with `vdc`

```
# **vdc asec list**➊
vdc asec list
111 0 com.example.app-1
111 0 org.foo.app-1
200 0 asec operation succeeded

# **vdc asec path com.example.app-1**➋
vdc asec path com.example.app-1
211 0 /mnt/asec/com.example.app-1

# **vdc asec unmount org.example.app-1**➌
200 0 asec operation succeeded

# **vdc asec mount com.example.app-1 000102030405060708090a0b0c0d0e0f 1000**➍
com.example.app-1 000102030405060708090a0b0c0d0e0f 1000
200 0 asec operation succeeded
```

Here, the `asec list` command ➊ lists the namespace IDs of mounted ASEC containers. Namespace IDs are based on the package name and have the same format as APK filenames for non-forward-locked applications. All other commands take a namespace ID as a parameter.

The `asec path` command ➋ shows the mount point of the specified ASEC container, while the `asec unmount` command unmounts it ➌. In addition to a namespace ID, `asec mount` ➍ requires that you specify the encryption key and the mount point’s owner UID (1000 is *system*).

The ASEC container encryption algorithm and the key length are unchanged from the original Android 2.2 apps-to-SD implementation: Twofish with a 128-bit key stored in */data/misc/systemkeys/*, as shown in [Example 3-26](ch03.html#asec_container_encryption_key_location_a "Example 3-26. ASEC container encryption key location and contents").

Example 3-26. ASEC container encryption key location and contents

```
# **ls -l /data/misc/systemkeys**
-rw------- system   system         16 AppsOnSD.sks
# **od -t x1 /data/misc/systemkeys/AppsOnSD.sks**
0000000 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
0000020
```

Forward locking an application is triggered by specifying the `-l` option of `pm install` or by specifying the `INSTALL_FORWARD_LOCK` flag when calling one of `PackageManager`’s `installPackage()` methods.

### Installing Forward-Locked APKs

The install process of forward-locked APKs involves two additional steps: creating and mounting the secure container, and extracting the public resource files from the APK file. As with encrypted APKs, those steps are encapsulated by the `MediaContainerService` and are performed while copying the APK to the application directory. As the `MediaContainerService` does not have enough privileges to create and mount secure containers, it delegates container management to the *vold* daemon by calling the appropriate `MountService` methods (`createSecureContainer()`, `mountSecureContainer()`, and so on).

## Encrypted Apps and Google Play

Because installing apps without user interaction, encrypted or otherwise, requires system permissions, only system applications can install applications. Google’s own Play Store Android client takes advantage of both encrypted apps and forward locking. While describing exactly how the Google Play client works would require detailed knowledge of the underlying protocol (which is not open and is constantly evolving), a casual look into the implementation of a recent Google Play Store client reveals a few useful pieces of information.

Google Play servers send quite a bit of metadata about the app you are about to download and install, such as download URL, APK file size, version code, and refund window. Among these, the `EncryptionParams` shown in [Example 3-27](ch03.html#encryptionparams_used_in_the_google_play "Example 3-27. EncryptionParams used in the Google Play Store protocol") looks very similar to the `ContainerEncryptionParams` shown in [Example 3-21](ch03.html#containerencryptionparams_data_members "Example 3-21. ContainerEncryptionParams data members").

Example 3-27. `EncryptionParams` used in the Google Play Store protocol

```
class AndroidAppDelivery$EncryptionParams {
  --*snip*--
  private String encryptionKey;
  private String hmacKey;
  private int version;
}
```

The encryption algorithm and the HMAC algorithm of paid applications downloaded from Google Play are always set to *AES/CBC/PKCS5Padding* and *HMACSHA1*, respectively. The IV and the MAC tag are bundled with the encrypted APK in a single blob. After all parameters are read and verified, they are essentially converted to a `ContainerEncryptionParams` instance, and the app is installed using the `PackageManager.installPackageWithVerification()` method.

The `INSTALL_FORWARD_LOCK` flag is set when installing a paid app in order to enable forward locking. The OS takes it from here, and the process is as described in the previous two sections: free apps are decrypted and the APKs end up in */data/app/*, while an encrypted container in */data/app-asec/* is created and mounted under */mnt/asec/<package-name>* for paid apps.

How secure is this in practice? Google Play can now claim that paid apps are always transferred and stored in encrypted form, and so can your own app distribution channel if you decide to implement it using the app encryption facilities that Android provides. The APK file contents have to be made available to the OS at some point though, so if you have root access to a running Android device, it’s still possible to extract a forward-locked APK or the container encryption key.

# Package Verification

Package verification was introduced as an official Android feature in version 4.2 as *application verification* and was later backported to all versions running Android 2.3 and later and the Google Play Store. The infrastructure that makes package verification possible is built into the OS, but Android doesn’t ship with any built-in verifiers. The most widely used package verification implementation is the one built into the Google Play Store client and backed by Google’s app analysis infrastructure. It’s designed to protect Android devices from what Google calls “potentially harmful applications”^([[27](#ftn.ch03fn11)]) (backdoors, phishing applications, spyware, and so on), commonly known simply as *malware*.

![Application verification warning dialog](figs/web/03fig03.png.jpg)

Figure 3-3. Application verification warning dialog

When package verification is turned on, APKs are scanned by a verifier prior to installation, and the system shows a warning (see [Figure 3-3](ch03.html#application_verification_warning_dialog "Figure 3-3. Application verification warning dialog")) or blocks installation if the verifier deems the APK potentially harmful. Verification is on by default on supported devices but requires one-time user approval on first use, as it sends application data to Google. Application verification can be toggled via the Verify Apps option on the system settings Security screen (see [Figure 3-2](ch03.html#application_install_security_settings "Figure 3-2. Application install security settings")).

The following sections discuss the Android package verification infrastructure and then take a brief look at Google Play’s implementation.

## Android Support for Package Verification

As with most things that deal with application management, package verification is implemented in the `PackageManagerService`, and has been available since Android 4.0 (API level 14). Package verification is performed by one or more *verification agents*, and has a *required verifier* and zero or more *sufficient verifiers*. Verification is considered complete when the required verifier and at least one of the sufficient verifiers return a positive result. An application can register itself as a required verifier by declaring a broadcast receiver with an intent filter that matches the `PACKAGE_NEEDS_VERIFICATION` action and the APK file MIME type (*application/vnd.android.package-archive*), as shown in [Example 3-28](ch03.html#required_verification_declaration_in_and "Example 3-28. Required verification declaration in AndroidManifest.xml").

Example 3-28. Required verification declaration in AndroidManifest.xml

```
<receiver android:name=".MyPackageVerificationReceiver"
          android:permission="android.permission.BIND_PACKAGE_VERIFIER">
    <intent-filter>
        <action
             android:name="android.intent.action.PACKAGE_NEEDS_VERIFICATION" />
        <action android:name="android.intent.action.PACKAGE_VERIFIED" />
        <data android:mimeType="application/vnd.android.package-archive" />
    </intent-filter>
</receiver>
```

In addition, the declaring application needs to be granted the `PACKAGE_VERIFICATION_AGENT` permission. As this is a signature permission reserved for system applications (`signature|system`), only system applications can become the required verification agent.

Applications can register sufficient verifiers by adding a `<package-verifier>` tag to their manifest and listing the sufficient verifier’s package name and public key in the tag’s attributes, as shown in [Example 3-29](ch03.html#sufficient_verifier_declaration_in_andro "Example 3-29. Sufficient verifier declaration in AndroidManifest.xml").

Example 3-29. Sufficient verifier declaration in AndroidManifest.xml

```
<manifest 
        package="com.example.app">
        <package-verifier android:name="com.example.verifier"
                          android:publicKey="MIIB..." />
    <application ...>
     --*snip*--
    </application>
</manifest>
```

When installing a package, the `PackageManagerService` performs verification when a required verifier is installed and the `Settings.Global.PACKAGE_ VERIFIER_ENABLE` system setting is set to `true`. Verification is enabled by adding the APK to a queue of pending installs and sending the `ACTION_PACKAGE_NEEDS_ VERIFICATION` broadcast to registered verifiers.

The broadcasts contains a unique verification ID, and various metadata about the package being verified. Verification agents respond by calling the `verifyPendingInstall()` method and passing the verification ID and a verification status. Calling the method requires the `PACKAGE_VERIFICATION_AGENT` permission, which guarantees that non-system apps cannot participate in package verification. Each time the `verifyPendingInstall()` is called, the `PackageManagerService` checks to see whether sufficient verification for the pending install has been received. If so, it removes the pending install from the queue, sends the `PACKAGE_VERIFIED` broadcast, and starts the package installation process. If the package is rejected by verification agents, or sufficient verification is not received within the allotted time, installation fails with the `INSTALL_FAILED_VERIFICATION_FAILURE` error.

## Google Play Implementation

Google’s application verification implementation is built into the Google Play Store client. The Google Play Store app registers itself as a required verification agent and if the Verify apps option is turned on, it receives a broadcast each time an application is about to be installed, whether through the Google Play Store client itself, the `PackgeInstaller` application, or via `adb install`.

The implementation is not open source, and few details are publicly available, but Google’s “Protect against harmful apps” Android help page states, “When you verify applications, Google receives log information, URLs related to the app, and general information about the device, such as the Device ID, version of the operating system, and IP address.”^([[28](#ftn.ch03fn12)]) We can observe that, as of this writing, in addition to this information, the Play Store client sends the APK file’s SHA-256 hash value, file size, the app package name, the names of its resources along with their SHA-256 hashes, the SHA-256 hashes of the app’s manifest and classes files, its version code and signing certificates, as well as some metadata about the installing application and referrer URLs, if available. Based on that information, Google’s APK analysis algorithms determine whether the APK is potentially harmful and return a result to the Play Store client that includes a status code and an error message to display in case the APK is deemed potentially harmful. In turn, the Play Store client calls the `verifyPendingInstall()` method of the `PackageManagerService` with the appropriate status code. Application install is accepted or rejected based on the algorithm described in the previous section.

In practice (at least on “Google experience” devices), the Google Play Store verifier is usually the sole verification agent, so whether the package is installed or rejected depends only on the response of Google’s online verification service.

# Summary

Android application packages (APK files) are an extension of the JAR file format and contain resources, code, and a manifest file. APK files are signed using the JAR file code signing format, but require that all files are signed with the same set of certificates. Android uses the code signer certificate to establish the same origin of apps and their updates and to establish trust relationships between apps. APK files are installed by copying them to the */data/app/* directory and creating a dedicated data directory for each application under */data/data/*.

Android supports encrypted APK files and secure app containers for forward locked apps. Encrypted apps are automatically decrypted before being copied to the application directory. Forward locked apps are split into a resource and manifest part, which is publicly accessible, and a private code and asset part, which is stored in a dedicated encrypted container, directly accessible only by the OS.

Android can optionally verify apps before installing them by consulting one or more verification agents. Currently, the most widely used verification agent is built into the Google Play Store client applications and uses Google’s online app verification service in order to detect potentially harmful applications.

* * *

^([[17](#ch03fn01)]) Oracle, *JAR File Specification*, *[http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html](http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html)*

^([[18](#ch03fn02)]) Microsoft Corporation, *Flame malware collision attack explained*, *[http://blogs.technet.com/b/srd/archive/2012/06/06/more-information-about-the-digital-certificates-used-to-sign-the-flame-malware.aspx](http://blogs.technet.com/b/srd/archive/2012/06/06/more-information-about-the-digital-certificates-used-to-sign-the-flame-malware.aspx)*

^([[19](#ch03fn03)]) EMC RSA Laboratories, *PKCS #7: Cryptographic Message Syntax Standard*, *[http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-7-cryptographic-message-syntax-standar.htm](http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-7-cryptographic-message-syntax-standar.htm)*

^([[20](#ch03fn04)]) Housley, *RFC 5652 – Cryptographic Message Syntax (CMS)*, *[http://tools.ietf.org/html/rfc5652](http://tools.ietf.org/html/rfc5652)*

^([[21](#ch03fn05)]) *Abstract Syntax Notation One (ASN.1)* is a standard notation that describes rules and structures for encoding data in telecommunications and computer networking. It’s used extensively in cryptography standards to define the structure of cryptographic objects.

^([[22](#ch03fn06)]) EMC RSA Laboratories, *PKCS #8: Private-Key Information Syntax Standard*, *[http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-8-private-key-information-syntax-stand.htm](http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-8-private-key-information-syntax-stand.htm)*

^([[23](#ch03fn07)]) For a discussion of Linux capabilities, see Chapter 39 of Michael Kerrisk’s *The Linux Programming Interface: A Linux and UNIX System Programming Handbook*, No Starch Press, 2010.

^([[24](#ch03fn08)]) File monitoring is implemented using Linux’s *inotify* facility. For more details about *inotify*, see Chapter 19 of Michael Kerrisk’s *The Linux Programming Interface: A Linux and UNIX System Programming Handbook*, No Starch Press, 2010.

^([[25](#ch03fn09)]) See CommonsWare, *CWAC-Security*, *[https://github.com/commonsguy/cwac-security](https://github.com/commonsguy/cwac-security)*, for further discussion and a sample project that shows how to perform the check.

^([[26](#ch03fn10)]) Google, *Android API Reference,* “Signature,” *[https://developer.android.com/reference/android/content/pm/Signature.html](https://developer.android.com/reference/android/content/pm/Signature.html)*

^([[27](#ch03fn11)]) Google, *Android Practical Security from the Ground Up*, presented at VirusBulletin 2013\. Retrieved from *[https://docs.google.com/presentation/d/1YDYUrD22Xq12nKkhBfwoJBfw2Q-OReMr0BrDfHyfyPw](https://docs.google.com/presentation/d/1YDYUrD22Xq12nKkhBfwoJBfw2Q-OReMr0BrDfHyfyPw)*

^([[28](#ch03fn12)]) Google*, Protect against harmful apps*, *[https://support.google.com/accounts/answer/2812853](https://support.google.com/accounts/answer/2812853)*
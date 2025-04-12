# Chapter 11. NFC and Secure Elements

This chapter gives a brief overview of near field communication (NFC) and secure elements (SEs), and explains how they’re integrated into mobile devices. While NFC has many uses, we focus on its card emulation mode, which is used to provide an interface to an SE integrated into a mobile device. Secure elements offer protected storage for private data, such as authentication keys, and provide a secure execution environment that can protect security-critical code. We’ll describe which types of SEs Android supports and introduce the APIs that Android applications can use to communicate with SEs. Finally, we’ll discuss host-based card emulation (HCE) and its Android implementations, and demonstrate how to implement an HCE application.

# NFC Overview

*NFC* is a technology that allows devices that are in close proximity (usually 10 centimeters or less) to establish radio communication with each other and exchange data. NFC is not a single standard, but is based on a set of standards that define radio frequencies, communication protocols, and data exchange formats. NFC builds upon radio-frequency identification (RFID) technology and operates at the 13.56 MHz frequency, allowing various data transmission rates such as 106kbps, 212kbps, and 424kbps.

NFC communication involves two devices: an initiator and a target. In *active mode*, both the initiator and the target have their own power supplies and each can transmit a radio signal in order to communicate with the other party. In *passive mode*, the target device does not have its own power source and is activated and powered by the electromagnetic field emitted by the initiator.

When communicating in passive mode, the initiator is often called a *reader*, and the target a *tag*. The reader can be a dedicated device or be embedded in a general purpose device, such as a personal computer or a mobile phone. Tags come in various shapes and sizes and range from simple stickers with very limited amount of memory to contactless smart cards, which have an embedded CPU.

NFC devices can operate in three different modes: reader/writer (R/W), peer-to-peer (P2P), and card emulation (CE). In R/W mode, a device acts as an active initiator and can read and write data to external tags. In P2P mode, two NFC devices can actively exchange data using a bidirectional communication protocol. The CE mode allows an NFC device to emulate a tag or a contactless smart card. Android supports all three modes with some limitations. We give an overview of Android’s NFC architecture and show how to use each mode in the next section.

# Android NFC Support

NFC support in Android was introduced in version 2.3 and the related architecture and features remained largely unchanged until version 4.4, which introduced HCE support.

Android’s NFC implementation resides in the `NfcService` system service, part of the `Nfc` system application (package `com.android.nfc`). It wraps the native libraries required to drive each supported NFC controller; implements access control, tag discovery, and dispatch; and controls card emulation. Android doesn’t expose a low-level API to the functionality of `NfcService`, but instead offers an event-driven framework that allows interested applications to register for NFC events. This event-driven approach is used in all three NFC operating modes.

## Reader/Writer Mode

NFC-enabled Android applications can’t directly set the device in R/W mode. Instead, they declare the type of tags they’re interested in, and Android’s tag dispatch system selects and starts the matching application when it discovers a tag.

The tag dispatch system both uses the tag technology (discussed shortly) and parses tag contents in order to decide which application to dispatch the tag to. The tag dispatch system uses three intent actions to notify applications about the discovered tag: `ACTION_NDEF_DISCOVERED`, `ACTION_TECH_DISCOVERED`, and `ACTION_TAG_DISCOVERED`. The `ACTION_NDEF_DISCOVERED` intent has the highest priority and is sent when Android discovers a tag that is formatted using the standard NFC Data Exchange Format (NDEF)^([[111](#ftn.ch11fn01)]) and that contains a recognized data type. The `ACTION_TECH_DISCOVERED` intent is sent when the scanned tag does not contain NDEF data or the data format is not recognized by applications that can handle the discovered tag technology. If no applications can handle `ACTION_NDEF_DISCOVERED` or `ACTION_TECH_DISCOVERED`, the `NfcService` sends the generic `ACTION_TAG_DISCOVERED` intent. Tag dispatch events are delivered only to activities, and therefore cannot be processed in the background without user interaction.

### Registering for Tag Dispatch

Applications register for NFC events using the standard intent filter system by declaring the intents that an NFC-enabled activity supports in *AndroidManifest.xml*, as shown in [Example 11-1](ch11.html#manifest_file_of_an_nfc-enabled_applicat "Example 11-1. Manifest file of an NFC-enabled application").

Example 11-1. Manifest file of an NFC-enabled application

```
<?xml version="1.0" encoding="utf-8"?>
<manifest 
    package="com.example.nfc" ...>
    --*snip*--

    <uses-permission android:name="android.permission.NFC" />➊
    --*snip*-
    <application ...>
        <activity
            android:name=".NfcActivity"➋
            android:launchMode="singleTop" >
            <intent-filter>
                <action android:name="android.nfc.action.NDEF_DISCOVERED"/>➌
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:mimeType="text/plain" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.nfc.action.TECH_DISCOVERED" />➍
            </intent-filter>
            <intent-filter>
                <action android:name="android.nfc.action.TAG_DISCOVERED" />➎
            </intent-filter>

            <meta-data
                android:name="android.nfc.action.TECH_DISCOVERED"➏
                android:resource="@xml/filter_nfc" >
            </meta-data>
        </activity>
        --*snip*--
    </application>
</manifest>
```

As you can see in this listing, the application first requests the `android.permission.NFC` permission ➊, which is required to access the NFC controller, and then declares an activity that handles NFC events, `NfcActivity` ➋. The activity registers three intent filters; one for each tag discovery event. The application declares that it can handle NDEF data with the *text/plain* MIME type by specifying the `mimeType` attribute of the `<data>` tag in the `NDEF_DISCOVERED` intent filter ➌. `NfcActivity` also declares that it can handle the `TECH_DISCOVERED` intent ➍, which is sent if the scanned tag uses one of the technologies specified in the associated metadata XML resource file ➏. Finally, the application requests that it be notified about all discovered NFC tags by adding the catch-all `TAG_DISCOVERED` intent filter ➎.

If more than one activity that supports the scanned tag is found, Android shows a selection dialog, allowing the user to select which activity should handle the tag. Applications already in the foreground can short-circuit this selection by calling the `NfcAdapter.enableForegroundDispatch()` method. Such an application will be given priority over all other matching applications and will automatically receive the NFC intent when it’s in the foreground.

### Tag Technologies

A *tag technology* is an abstract term that describes a concrete NFC tag. The tag technology is determined by the communication protocol the tag uses, its internal structure, or the features it offers. For example, a tag that uses the NFC-A protocol (based on ISO 14443-3A)^([[112](#ftn.ch11fn02)]) for communication matches the *NfcA* technology, and a tag that contains NDEF-formatted data matches the *Ndef* technology, regardless of the underlying communication protocol. (See the `TagTechnology` class reference documentation^([[113](#ftn.ch11fn03)]) for a full list of tag technologies supported by Android.)

An activity that specifies the `TECH_DISCOVERED` intent filter must provide an XML resource file that in turn specifies the concrete technologies it supports with a `<tech-list>` element. An activity is considered a match for a tag if one of the tech lists it declares is a subset of the technologies supported by the tag. Multiple tech lists can be declared in order to match different tags, as shown in [Example 11-2](ch11.html#declaring_technologies_to_match_using_te "Example 11-2. Declaring technologies to match using tech lists").

Example 11-2. Declaring technologies to match using tech lists

```
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <tech-list>➊
        <tech>android.nfc.tech.IsoDep</tech>
        <tech>android.nfc.tech.NfcA</tech>
    </tech-list>

    <tech-list>➋
        <tech>android.nfc.tech.NfcF</tech>
    </tech-list>
</resources>
```

Here, the first tech list ➊ will match tags that provide a communication interface compatible with ISO 14443-4 (ISO-DEP), and which are implemented using the NFC-A technology (usually used by NXP contactless smart cards); the second tech list ➋ matches tags that use the NFC-F technology (typically Felica cards). Because both tech lists are defined independently, our example `NfcActivity` (see [Example 11-1](ch11.html#manifest_file_of_an_nfc-enabled_applicat "Example 11-1. Manifest file of an NFC-enabled application")) will be notified when either a contactless NXP smart card or a Felica card or tag is scanned.

### Reading a Tag

After the tag dispatch system selects an activity to handle the scanned tag, it creates an NFC intent object and passes it to the selected activity. The activity can then use the `EXTRA_TAG` extra to obtain a `Tag` object representing the scanned tag and call its methods in order to read or write to the tag. (Tags that contain NDEF data also provide the `EXTRA_NDEF_MESSAGES` extra, which contains an array of NDEF messages parsed from the tag.)

A concrete `Tag` object representing the underlying tag technology can be obtained using the static `get()` method of the corresponding technology class, as shown in [Example 11-3](ch11.html#obtaining_a_concrete_tag_instance_from_t "Example 11-3. Obtaining a concrete Tag instance from the NFC intent"). If the `Tag` object does not support the requested technology, the `get()` method returns `null.`

Example 11-3. Obtaining a concrete `Tag` instance from the NFC intent

```
protected void onNewIntent(Intent intent) {
    setIntent(intent);

    Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
    IsoDep isoDep = IsoDep.get(tag);
    if (isoDep != null) {
         isoDep.connect();
         byte[] command = {...};
         byte[] response = isoDep.transceive(command);
         --*snip*--
    }
}
```

### Using Reader Mode

In addition to the intent-based tag dispatch system, Android 4.4 adds a new method that activities can use to obtain a live `Tag` object, called reader mode. Reader mode guarantees that while the target activity is in the foreground, all other operation modes supported by the NFC controller (such as peer-to-peer and card emulation) are disabled. This mode is helpful when scanning an active NFC device, such as another Android device in host-based emulation mode, which could trigger point-to-point communication and thus take control away from the current foreground activity.

Activities can enable reader mode by calling the `enableReaderMode()` method of the `NfcAdapter` class,^([[114](#ftn.ch11fn04)]) as shown in [Example 11-4](ch11.html#enabling_reader_mode_and_obtaining_a_tag "Example 11-4. Enabling reader mode and obtaining a Tag object using ReaderCallback").

Example 11-4. Enabling reader mode and obtaining a `Tag` object using `ReaderCallback`

```
public class NfcActivity extends Activity implements NfcAdapter.ReaderCallback {
    private NfcAdapter adapter;
    --*snip*--
    @Override
    public void onResume() {
       super.onResume();
       if (adapter != null) {
           adapter.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A➊
                   | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
       }
    }

    @Override
    public void onTagDiscovered(Tag tag) {➋
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep != null) {
             isoDep.connect();
             byte[] command = {...};
             byte[] response = isoDep.transceive(command);
             --*snip*--
        }
    }
    --*snip*--
}
```

In this case, the activity enables reader mode when it comes to the foreground by calling the `enableReaderMode()` method ➊ (the activity should disable reader mode using the matching `disableReaderMode()` method when it leaves the foreground), and obtains a `Tag` instance directly (without an intermediate intent) via the `onTagDiscovered()` callback ➋. The `Tag` object is then used in the same way as in intent-based dispatch.

## Peer-to-Peer Mode

Android implements a limited NFC P2P mode data exchange between devices using the proprietary NDEF push and the standard Simple NDEF Exchange Protocol (SNEP) protocols.^([[115](#ftn.ch11fn05)]) Android devices can exchange a single NDEF message with any device that supports either of these protocols, but the P2P mode is typically used with another Android device in order to implement the so-called Android Beam feature.

In addition to NDEF messages, Android Beam allows for the transfer of larger data objects, such as photos and videos, which cannot fit in a single NDEF message by creating a temporary Bluetooth connection between devices. This process is called *NFC handover* and was added in Android 4.1.

NDEF message exchange in P2P mode is enabled by calling the `setNdefPushMessage()` or `setNdefPushMessageCallback()` methods of the `NfcAdapter` class. (See the official NFC API guide^([[116](#ftn.ch11fn06)]) for more details and sample code.)

## Card Emulation Mode

As mentioned in “[NFC Overview](ch11.html#nfc_overview "NFC Overview")”, CE mode allows an Android device to emulate a contactless smart card or an NFC tag. In CE mode, the device receives commands over NFC, processes them, and sends replies, again over NFC. The component responsible for processing commands can be either a hardware secure element (as discussed in the next section) connected to the device’s NFC controller, or an Android application running on the device (when in host-based card emulation, HCE).

In the following sections, we’ll discuss secure elements in mobile devices, and the Android APIs that applications can use to communicate with SEs. We’ll also describe how Android implements HCE and demonstrate how to create an application that enables card emulation.

# Secure Elements

A *secure element (SE)* is a tamper-resistant smart card chip capable of running smart card applications (called *applets* or *cardlets*) with a certain level of security and isolation. A smart card is essentially a minimal computing environment on a single chip, complete with a CPU, ROM, EEPROM, RAM, and I/O port. Recent cards also include cryptographic co-processors that implement common algorithms such as AES and RSA.

Smart cards use various techniques to implement tamper resistance, making it quite hard to extract data by disassembling or analyzing the chip. Modern smart cards come pre-programmed with a multi-application OS that takes advantage of the hardware’s memory protection features to ensure that each application’s data is only available to itself. Application installation and (optionally) access is controlled by requiring the use of cryptographic keys for each operation.

The SE can be integrated in mobile devices as a Universal Integrated Circuit Card (UICC, commonly known as a *SIM card*) embedded in the handset or connected to a SD card slot. If the device supports NFC, the SE is usually connected to (or embedded into) the NFC controller, making it possible to communicate with the SE wirelessly.

Smart cards have been around since the 1970s and are now used in applications ranging from pre-paid phone calls and transit ticketing to credit cards and VPN credential storage. Because an SE installed in a mobile device has equivalent or superior capabilities to that of a smart card, it can theoretically be used for any application that physical smart cards are currently used for. Additionally, because an SE can host multiple applications, it has the potential to replace the bunch of cards people use daily with a single device. Furthermore, because the SE can be controlled by the device’s OS, access to it can be restricted by requiring additional authentication (PIN, passphrase, or code signature) to enable it.

One of the main applications of SEs in mobile devices is that of emulating contactless payment cards, and the goal of enabling mobile payments has indeed been the driving force behind SE deployment. Aside from financial applications, mobile SEs could be used to emulate other contactless cards that are in wide use, such as access cards, loyalty cards, and so on.

Mobile SEs could also be used to enhance the security of apps that deal with sensitive information or algorithms: The security-critical part of the app, such as credential storage or license verification, can be implemented inside the SE in order to guarantee that it’s impervious to reverse engineering and information extraction. Other apps that can benefit from being implemented in the SE are One Time Password (OTP) generators and, of course, credential storage (for shared secret keys, or private keys in a PKI).

While it’s possible to implement SE-enabled apps today with standard tools and technologies, using them in practice on current commercial Android devices isn’t straightforward. We’ll discuss this in detail in “[Android SE Execution Environment](ch11.html#android_se_execution_environment "Android SE Execution Environment")”, but let’s first explore the types of SEs available on mobile devices, and the level of support they have in Android.

## SE Form Factors in Mobile Devices

[Figure 11-1](ch11.html#android_nfc_and_se_components "Figure 11-1. Android NFC and SE components") shows a simplified block diagram of the components of an Android device as they relate to NFC and SE support, including the embedded SE (eSE) and the UICC. We’ll refer to the components in this diagram in our discussion of secure elements and host-based card emulation in the rest of this chapter.

In the following subsections, we briefly review the types of SEs available on Android devices, how they’re connected to other device components, and the methods the OS uses to communicate with each type of SE.

![Android NFC and SE components](figs/web/11fig01.png.jpg)

Figure 11-1. Android NFC and SE components

### UICC

Most mobile devices today have some kind of UICC. Although UICCs are smart cards that can host applications, because the UICC has traditionally only been connected to the baseband processor (not the application processor that runs the main device OS), they can’t be accessed directly from Android. All communication goes through the Radio Interface Layer (RIL), which is essentially a proprietary IPC interface to the baseband.

Communication with the UICC SE is carried out using extended AT commands (`AT+CCHO`, `AT+CCHC`, `AT+CGLA` as defined by 3GPP TS 27.007),^([[117](#ftn.ch11fn07)]) which the current Android telephony manager does not support. The SEEK for Android project^([[118](#ftn.ch11fn08)]) provides patches to implement the needed commands, allowing for communication with the UICC via the SmartCard API, which is a reference implementation of the SIMalliance Open Mobile API specification^([[119](#ftn.ch11fn09)]) (discussed in “[Using the OpenMobile API](ch11.html#using_the_openmobile_api "Using the OpenMobile API")”). However, as with most components that talk directly to the hardware in Android, the RIL consists of an open source part (*rild*), and a proprietary library (*libXXX-ril.so*). In order to support communication with the UICC secure element, support must be added both to the *rild* and to the underlying proprietary library. The choice of whether to add that support is left to hardware vendors.

As of this writing, the SmartCard API has not been integrated into mainline Android (although the AOSP source tree includes an empty *packages/ apps/SmartCardService/* directory). However, Android devices from major vendors ship with an implementation of the SmartCard API, which allows communication from the UICC to third-party applications (subject to various access restrictions).

The Single Wire Protocol (SWP) offers an alternative way to use the UICC as an SE. SWP is used to connect the UICC to a NFC controller, allowing the NFC controller to expose the UICC to external readers when in card emulation mode. The NFC controllers built into recent Nexus devices (such as the Broadcom BCM20793M in the Nexus 5) support SWP, but this functionality is disabled by default. (It can be enabled by changing the configuration file of the *libnfc-brcm* library on the Nexus 5.) A standard API to switch between the UICC, the embedded SE (if available), and HCE when in card emulation mode is currently not exposed, but the “off-host” routing functionality available in Android 4.4 can theoretically route commands to the UICC (see “[APDU Routing](ch11.html#apdu_routing "APDU Routing")” for details).

### microSD-Based SE

Another form factor for an SE is an *Advanced Security SD card (ASSD)*,^([[120](#ftn.ch11fn10)]) which is basically an SD card with an embedded SE chip. When connected to an Android device with an SD card slot, running a SEEK-patched Android version, the SE can be accessed via the SmartCard API. However, Android devices with an SD card slot are becoming the exceptions rather than the norm, so it’s unlikely that ASSD Android support will make it to the mainstream. Additionally, even when available, recent Android versions treat SD cards as secondary storage devices and allow access to them only via a very high-level, restrictive API.

### Embedded SE

An *embedded SE (eSE)* is not a distinct device but is usually integrated with the NFC controller and housed in the same enclosure. An example of an eSE is NXP’s PN65N chip, which combines the PN544 NFC radio controller with the P5CN072 SE (part of the SmartMX series).

The first mainstream Android device to feature an embedded SE was the Nexus S, which also introduced NFC support to Android and was built using the PN65N controller. Its successors, the Galaxy Nexus and the Nexus 4, also came equipped with an eSE. However, recent Google-branded devices, such as the Nexus 5 and Nexus 7 (2013), have deprecated the eSE in favor of host-based card emulation and do not include an eSE.

The embedded SE is connected to the NFC controller through a SignalIn/SignalOut connection (S2C), standardized as NFC Wired Interface (NFC-WI),^([[121](#ftn.ch11fn11)]) and has three modes of operation: off, wired, and virtual. In off mode, there’s no communication with the SE. In wired mode, the SE is visible to the Android OS as if it were a contactless smart card connected to the NFC reader. In virtual mode, the SE is visible to external readers as if the phone were a contactless smart card. These modes are mutually exclusive, so we can communicate with the SE either via the contactless interface (that is, from an external reader), or through the wired interface (that is, from an Android app). The next section shows how to use the wired mode to communicate with the eSE from an Android app.

## Accessing the Embedded SE

As of this writing, no public Android SDK API allows communication with the embedded SE, but recent Android versions include an optional library called *nfc_extras*, which offers a stable interface to the eSE. This section demonstrates how to configure Android to allow eSE access to certain Android applications, as well as how to use the *nfc_extras* library.

Card emulation, and consequently, internal APIs for accessing the embedded SE were introduced in Android 2.3.4 (the version that introduced Google Wallet). Those APIs are hidden from SDK applications and using them required system signature permissions (`WRITE_SECURE_SETTINGS` or `NFCEE_ADMIN`) in Android 2.3.4 and subsequent 2.3.x releases, as well as in the initial Android 4.0 release (API Level 14). A signature permission is quite restrictive because it allows only parties that control the platform signature keys to distribute apps that can use the eSE.

Android 4.0.4 (API Level 15) lifted this restriction by replacing the signature permission with signing certificate whitelisting at the OS level. While this still requires modifying core OS files, and thus vendor cooperation, there is no need to sign SE applications with the vendor key, which greatly simplifies distribution. Additionally, since the whitelist is maintained in a file, it can easily be updated using an OTA to add support for more SE applications.

### Granting Access to the eSE

The new whitelisting access control approach is implemented by the `NfceeAccessControl` class and enforced by the system `NfcService`. The `NfceeAccessControl` class reads the whitelist from */etc/nfcee_access.xml*, which is an XML file that stores a list of signing certificates and package names that are allowed to access the eSE. Access can be granted both to all apps signed by a particular certificate’s private key (if no package name is specified), or to a single package (app) only. [Example 11-5](ch11.html#contents_of_the_nfceeunderscoreaccessdot "Example 11-5. Contents of the nfcee_access.xml file") shows how the contents of the *nfcee_access.xml* file might appear:

Example 11-5. Contents of the nfcee_access.xml file

```
<?xml version="1.0" encoding="utf-8"?>
<resources >
    <signer android:signature="308204a830820390a003020102020900b399...">➊
        <package android:name="com.example.nfc">➋
        </package>
    </signer>
</resources>
```

This configuration allows SE access to the `com.example.nfc` package ➋ if it is signed by the specified signing certificate ➊. On production devices, this file usually contains only the Google Wallet app signing certificate, thus restricting eSE access to Google Wallet.

### Note

*As of April 2014, Google Wallet is supported only on Android 4.4 and later, and uses HCE rather than the eSE.*

After an application’s signing certificate has been added to *nfcee_access.xml*, no permissions other than the standard NFC permission are required to access the eSE. In addition to whitelisting the app’s signing certificate, the *nfc_extras* library must be explicitly added to the app’s manifest and marked as required with the `<uses-library>` tag in order to enable eSE access (because the library is optional, it’s not loaded by default), as shown in [Example 11-6](ch11.html#adding_the_nfcunderscoreextras_library_t "Example 11-6. Adding the nfc_extras library to AndroidManifest.xml") at ➊.

Example 11-6. Adding the nfc_extras library to AndroidManifest.xml

```
<manifest 
    package="com.example.nfc" ...>
    --*snip*--
    <uses-permission android:name="android.permission.NFC" />
    <application ...>
        --*snip*--
        <uses-library
            android:name="com.android.nfc_extras"➊
            android:required="true" />
    </application>
</manifest>
```

### Using the NfcExecutionEnvironment API

Android’s eSE access API isn’t based on a standard smart card communication API, such as JSR 177^([[122](#ftn.ch11fn12)]) or the Open Mobile API, but instead offers a very basic communication interface, implemented in the `NfcExecutionEnvironment` class. The class has only three public methods, as shown in [Example 11-7](ch11.html#nfcexecutionenvironment_api "Example 11-7. NfcExecutionEnvironment API").

Example 11-7. `NfcExecutionEnvironment` API

```
public class NfcExecutionEnvironment {
    public void open() throws EeIOException {...}

    public void close() throws IOException {...}

    public byte[] transceive(byte[] in) throws IOException {...}
}
```

This simple interface is sufficient to communicate with the SE, but in order to use it you first need to obtain an instance of the `NfcExecutionEnvironment` class. An instance can be obtained from the `NfcAdapterExtras` class, which is in turn accessed via its static `get()` method, as shown in [Example 11-8](ch11.html#using_the_nfcexecutionenvironmen-id00025 "Example 11-8. Using the NfcExecutionEnvironment API").

Example 11-8. Using the `NfcExecutionEnvironment` API

```
NfcAdapterExtras adapterExtras =
     NfcAdapterExtras.get(NfcAdapter.getDefaultAdapter(context));➊
NfcExecutionEnvironment nfceEe =
     adapterExtras.getEmbeddedExecutionEnvironment();➋
nfcEe.open();➌
byte[] emptySelectCmd = { 0x00, (byte) 0xa4, 0x04, 0x00, 0x00 };
byte[] response = nfcEe.transceive(emptySelectCmd);➍
nfcEe.close();➎
```

Here, we first obtain an `NfcAdapterExtras` instance ➊, and then call its `getEmbeddedExecutionEnvironment()` method in order to obtain an interface to the eSE ➋. To be able to communicate with the eSE, we first open a connection ➌, and then use the `transceive()` method to send a command and get a response ➍. Finally, we close the connection using the `close()` method ➎.

### eSE-Related Broadcasts

An SE-enabled app needs to be notified of NFC events such as RF field detection, as well as of events pertaining to the eSE and the applets installed on it, such as applet selection via the NFC interface, in order to be able to change state accordingly. Because disclosure of such events to malicious applications can lead to leaking of sensitive information and denial of service attacks, access to eSE-related events must be limited to trusted applications only.

In Android, global events are implemented by using broadcasts, and applications can create and register broadcast receivers that receive the broadcasts the app is interested in. Access to eSE-related broadcasts can be controlled with standard Android signature-based permissions, but this approach has the disadvantage that only apps signed with the platform certificate can receive eSE events, thus limiting SE-enabled apps to those created by the device manufacturer or mobile network operator (MNO). To avoid this limitation, Android uses the same mechanism employed to control eSE access; namely, whitelisting application certificates, in order to control the scope of applications that can receive eSE-related broadcasts. Any application whose signing certificate (and optionally package name) is registered in *nfcee_access.xml* can receive eSE-related broadcasts by registering a receiver like the one shown in [Example 11-9](ch11.html#declaring_a_broadcast_receiver_for_ese-r "Example 11-9. Declaring a broadcast receiver for eSE-related events in AndroidManifest.xml").

Example 11-9. Declaring a broadcast receiver for eSE-related events in AndroidManifest.xml

```
<receiver android:name="com.example.nfc.SEReceiver" >
  <intent-filter>
   <action android:name="com.android.nfc_extras.action.RF_FIELD_ON_DETECTED" />➊
   <action android:name="com.android.nfc_extras.action.RF_FIELD_OFF_DETECTED" />➋
   <action android:name="com.android.nfc_extras.action.APDU_RECEIVED" />➌
   <action android:name="com.android.nfc_extras.action.AID_SELECTED" />➍
   <action android:name="com.android.nfc_extras.action.MIFARE_ACCESS_DETECTED" />➎
   <action android:name="com.android.nfc_extras.action.EMV_CARD_REMOVAL" />➏
   <action android:name="com.android.nfc.action.INTERNAL_TARGET_DESELECTED" />➐
   <action android:name="android.intent.action.MASTER_CLEAR_NOTIFICATION" />➑
  </intent-filter>
</receiver>
```

As you can see, Android offers notifications for lower-level communication events, such as RF field detection ➊➋, APDU reception ➌, and applet selection ➍, as well as for higher-level events, such as MIFARE sector access ➎ and EMV card removal ➏. (APDUs are *Application Protocol Data Units*, the basic building block of smart card protocols; see “[SE Communication Protocols](ch11.html#se_communication_protocols "SE Communication Protocols")”. The `APDU_RECIEVED` broadcast is not implemented, because in practice the NFC controller routes incoming APDUs directly to the eSE, which makes them invisible to the OS.) SE-enabled apps register for these broadcasts in order to be able to change their internal state or start a related activity when each event occurs (for example, to start a PIN entry activity when an EMV applet is selected). The `INTERNAL_TARGET_DESELECTED` broadcast ➐ is sent when card emulation is deactivated, and the `MASTER_CLEAR_NOTIFICATION` broadcast ➑ is sent when the contents of the eSE are cleared. (Pre-HCE versions of Google Wallet offered users the option to clear the eSE remotely if their device was lost or stolen.)

## Android SE Execution Environment

The Android SE is essentially a smart card in a different package, so most standards and protocols originally developed for smart cards apply. Let’s briefly review the most important ones.

Smart cards have traditionally been filesystem-oriented and the main role of their OS has been to handle file access and enforce access permissions. Newer cards support a virtual machine running on top of the native OS that allows for the execution of “platform independent” applications called applets, which use a well-defined runtime library to implement their functionality. While different implementations of this paradigm exist, by far the most popular one is the Java Card runtime environment (JCRE). Applets are implemented in a restricted version of the Java language and use a limited runtime library, which offers basic classes for I/O, message parsing, and cryptographic operations. While the JCRE specification^([[123](#ftn.ch11fn13)]) fully defines the applet runtime environment, it does not specify how to load, initialize, and delete applets on actual physical cards (tools are only provided for the JCRE emulator).

Because one of the main applications of smart cards are various payment services, the application loading and initialization process (often referred to as *card personalization*) needs to be controlled, and only authorized entities should be able to alter the state of the card and installed applications. Visa originally developed a specification for securely managing applets, called Open Platform, which is now maintained and developed by the GlobalPlatform (GP) organization under the name GlobalPlatform Card Specification.^([[124](#ftn.ch11fn14)]) The gist of this specification is that each GP-compliant card has a mandatory *Issuer Security Domain (ISD)* component (informally referred to as the *Card Manager*) that offers a well-defined interface for card and application life cycle management. Executing ISD operations requires authentication using cryptographic keys saved on the card, and thus only an entity that knows those keys can change the state of the card (one of `OP_READY`, `INITIALIZED`, `SECURED`, `CARD_LOCKED`, or `TERMINATED`) or manage applets. Additionally, the GP card specification defines various secure communication protocols (called Secure Channels) that offer authentication, confidentiality, and message integrity when communicating with the card.

### SE Communication Protocols

As discussed in “[Using the NfcExecutionEnvironment API](ch11.html#using_the_nfcexecutionenvironment_api "Using the NfcExecutionEnvironment API")”, Android’s interface for communicating with the SE is the `byte[] transceive(byte[] command)` method of the `NfcExecutionEnvironment` class. The messages exchanged using this API are in practice APDUs, and their structure is defined in the *ISO/IEC 7816-4: Organization, security and commands for interchange* standard.^([[125](#ftn.ch11fn15)]) The reader (also known as a *Card Acceptance Device*, or *CAD*) sends command APDUs (sometimes referred to as *C-APDUs*) to the card, composed of a mandatory four-byte header with a command class (*CLA*), instruction (*INS*), and two parameters (*P1* and *P2*). This is followed by the optional command data length (*Lc*), the actual data, and finally the maximum number of response bytes expected, if any (*Le*). The card returns a response APDU (*R-APDU*) with a mandatory status word (*SW*, consisting of two bytes: *SW1* and *SW2*) and optional response data.

Historically, command APDU data has been limited to 255 bytes (total APDU length 261 bytes) and response APDU data to 256 bytes (total APDU length 258 bytes). Recent cards and readers support extended APDUs with data length up to 65536 bytes, but extended APDUs are not always usable, mostly for reasons of compatibility. The lower-level communication between the reader and the card is carried out by one of several transmission protocols, the most widely used of which are T=0 (byte-oriented) and T=1 (block-oriented). Both are defined in *ISO 7816-3: Cards with contacts — Electrical interface and transmission protocols*. The APDU exchange is not completely protocol-agnostic, because T=0 cannot directly send response data, but only notify the reader of the number of available bytes. Additional command APDUs (`GET RESPONSE`) need to be sent in order to retrieve the response data.

The original ISO 7816 standards were developed for contact cards, but the same APDU-based communication model is used for contactless cards as well. It’s layered on top of the wireless transmission protocol defined by ISO/IEC 14443-4, which behaves much like T=1 for contact cards.

### Querying the eSE Execution Environment

As discussed in “[Embedded SE](ch11.html#embedded_se "Embedded SE")”, the eSE in the Galaxy Nexus is a chip from NXP’s SmartMX series. It runs a Java Card–compatible operating system and comes with a GlobalPlatform-compliant ISD. The ISD is configured to require authentication for most card management operations, and the authentication keys are, naturally, not publicly available. Additionally, a number of subsequent failed authentication attempts (usually 10) will lock the ISD and make it impossible to install or remove applets, so trying to brute-force the authentication keys is not an option. However, the ISD does provide some information about itself and the runtime environment on the card without requiring authentication in order to make it possible for clients to adjust their behavior dynamically and be compatible with different cards.

Because both Java Card and GlobalPlatform define a multi-application environment, each application needs a unique identifier called the *Application Identifier (AID)*. The AID consists of a 5-byte Registered Application Provider Identifier (RID, also called a Resource Identifier) and a Proprietary Identifier eXtension (PIX), which can be up to 11 bytes long. Thus, the length of an AID can be 5 to 16 bytes long. Before being able to send commands to a particular applet, it needs to be made active, or selected, by issuing the `SELECT` (`CLA`=00, `INS`=A4) command with its AID. As all applications, the ISD is also identified by an AID, which varies between card manufacturers and GP implementations. We can find out the AID of the ISD by sending an empty `SELECT` command, which both selects the ISD and returns information about the card and the ISD configuration. An empty `SELECT` is simply a select without an AID specified, so the `SELECT` command APDU becomes `00 A4 04 00 00`. If we send this command using the `transcieve()` method of the `NfcExecutionEnvironment` class ([Example 11-8](ch11.html#using_the_nfcexecutionenvironmen-id00025 "Example 11-8. Using the NfcExecutionEnvironment API") at ➍), the returned response might look like [Example 11-10](ch11.html#galaxy_nexus_eseapostrophes_response_to "Example 11-10. Galaxy Nexus eSE’s response to empty SELECT") at ➋ (➊ is the `SELECT` command).

Example 11-10. Galaxy Nexus eSE’s response to empty `SELECT`

```
--> 00A4040000➊
<-- 6F658408A000000003000000A5599F6501FF9F6E06479100783300734A06072A86488
6FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A86488
6FC6B040215650B06092B8510864864020103660C060A2B060104012A026E0102 9000➋
```

The response includes a successful status (0x9000) and a long string of bytes. The format of this data is defined in “APDU Command Reference,” [Chapter 9](ch09.html "Chapter 9. Enterprise Security") of the GlobalPlatform Card Specification and, as with most things in the smart card world, is in tag-length-value (TLV) format. In TLV, each unit of data is described by a unique tag, followed by its length in bytes, and finally the actual data. Most structures are recursive, so the data can host another TLV structure, which in turns wraps another, and so on. The structure shown in [Example 11-10](ch11.html#galaxy_nexus_eseapostrophes_response_to "Example 11-10. Galaxy Nexus eSE’s response to empty SELECT") is called *File Control Information (FCI)* and in this case it wraps a Security Domain Management Data structure, which describes the ISD. When parsed, the FCI might look like [Example 11-11](ch11.html#parsed_fci_of_the_isd_on_the_ese_in_gala "Example 11-11. Parsed FCI of the ISD on the eSE in Galaxy Nexus").

Example 11-11. Parsed FCI of the ISD on the eSE in Galaxy Nexus

```
SD FCI: Security Domain FCI
   AID: a0 00 00 00 03 00 00 00➊
    RID: a0 00 00 00 03 (Visa International [US])
    PIX: 00 00 00

   Data field max length: 255
   Application prod. life cycle data: 479100783300
   Tag allocation authority (OID): globalPlatform 01
   Card management type and version (OID): globalPlatform 02020101
   Card identification scheme (OID): globalPlatform 03
   Global Platform version: 2.1.1➋
   Secure channel version: SC02 (options: 15)➌
   Card config details: 06092B8510864864020103➍
   Card/chip details: 060A2B060104012A026E0102➎
```

Here, the AID of the ISD is A0 00 00 00 03 00 00 00 ➊, the version of the GlobalPlatform implementation is 2.1.1 ➋, the supported Secure Channel protocol is SC02 ➌, and the last two fields of the structure contain some proprietary data about the card configuration (➍ and ➎). The only other GP command that doesn’t require authentication is `GET DATA`, which can be used to return additional data about the ISD configuration.

## UICC as a Secure Element

As discussed in “[SE Form Factors in Mobile Devices](ch11.html#se_form_factors_in_mobile_devices "SE Form Factors in Mobile Devices")”, the UICC in a mobile device can be used as a general-purpose SE when accessed using the Open Mobile API or a similar programming interface. This section gives a brief overview of UICCs and the applications they typically host, and then shows how to access the UICC via the Open Mobile API.

### SIM Cards and UICCs

The predecessor of the UICC is the SIM card, and UICCs are still colloquially referred to as “SIM cards.” *SIM* stands for *Subscriber Identity Module* and refers to a smart card that securely stores the subscriber identifier and the associated key used to identify and authenticate a device to a mobile network. SIMs were initially used on GSM networks and the original GSM standards were later extended to support 3G and LTE. Because SIMs are smart cards, they conform to ISO-7816 standards regarding physical characteristics and electrical interface. The first SIM cards were the same size as “regular” smart cards (Full-size, FF), but by far the most popular sizes today are Mini-SIM (2FF) and Micro-SIM (3FF), with Nano-SIM (4FF), which was introduced in 2012, also gaining market share.

Of course, not every smart card that fits in the SIM slot can be used in a mobile device, so the next question is: What makes a smart card a SIM card? Technically, it’s conformance to mobile communication standards such as 3GPP TS 11.11 and certification by the SIMalliance. In practice, it is the ability to run an application that allows it to communicate with the phone (referred to as *Mobile Equipment* or *Mobile Station* in related standards) and connect to a mobile network. While the original GSM standard did not distinguish between the physical smart card and the software required to connect to the mobile network, with the introduction of 3G standards, a clear distinction has been made. The physical smart card is referred to as a *Universal Integrated Circuit Card (UICC),* and different mobile network applications that run on it have been defined: GSM, CSIM, USIM, ISIM, and so on. A UICC can host and run more than one network application (hence the name *universal*), and thus can be used to connect to different networks. While network application functionality depends on the specific mobile network, their core features are quite similar: store network parameters securely and identify to the network, as well as authenticate the user (optionally) and store user data.

### UICC Applications

Let’s take GSM as an example and briefly review how a network application works. For GSM, the main network parameters are network identity (International Mobile Subscriber Identity, IMSI; tied to the SIM), phone number (MSISDN, used for routing calls and changeable), and a shared network authentication key *Ki*. To connect to the network, the phone needs to authenticate and negotiate a session key. Both authentication and session keys are derived using *Ki*, which is also known to the network and looked up by IMSI. The phone sends a connection request that includes its IMSI, which the network uses to find the corresponding *Ki*. The network then uses the *Ki* to generate a challenge (*RAND*), expected challenge response (*SRES*), and session key *Kc*. When those parameters have been generated, the network sends *RAND* to the phone and the GSM application running on the SIM card comes into play: the mobile passes the *RAND* to the SIM card, which generates its own *SRES* and *Kc*. The *SRES* is sent to the network and if it matches the expected value, encrypted communication is established using the session key *Kc*.

As you can see, the security of this protocol hinges solely on the secrecy of the *Ki*. Because all operations involving the *Ki* are implemented inside the SIM card, and it never comes in direct contact with the phone or the network, the scheme is kept reasonably secure. Of course, security depends on the encryption algorithms used as well, and major weaknesses that allow intercepted GSM calls to be decrypted using off-the-shelf hardware were found in the original versions of the A5/1 stream cipher (which was initially secret).

In Android, network authentication is implemented by the baseband processor (more on this in “[Accessing the UICC](ch11.html#accessing_the_uicc "Accessing the UICC")” below) and is never directly visible to the main OS.

### UICC Application Implementation and Installation

We’ve seen that UICCs need to run applications; now let’s see how those applications are implemented and installed. Initial smart cards were based on a filesystem model, where files (called *elementary files*, or *EF*) and directories (called *dedicated files*, or *DF*) were named with a two-byte identifier. Thus, developing “an application” involved selecting an ID for the DF that hosts the application’s files (called *ADF*), and specifying the formats and names of the EFs that store data. For example, the GSM application is under the *7F20* ADF, and the USIM ADF hosts the *EF_imsi*, *EF_keys*, *EF_sms*, and other required files.

Because practically all UICCs in use today are based on Java Card technology and implement GlobalPlatform card specifications, all network applications are implemented as Java Card applets and emulate the legacy file-based structure for backward compatibility. Applets are installed according to GlobalPlatform specifications by authenticating to the ISD and issuing `LOAD` and `INSTALL` commands.

One application management feature specific to SIM cards is support for OTA updates via binary SMS. This functionality is not used by all carriers, but it allows carriers to remotely install applets on SIM cards they’ve issued. OTA is implemented by wrapping card commands (APDUs) in SMS T-PDUs (transport protocol data units), which the phone forwards to the UICC. In most UICCs, this is the only way to load applets on the card, even during initial personalization.

The major use case for this OTA functionality is to install and maintain SIM Toolkit (STK) applications that can interact with the handset via standard “proactive” commands (which in reality are implemented via polling), and to display menus or even open web pages and send SMS. Android supports STK with a dedicated STK system app, which is automatically disabled if the UICC card has no STK applets installed.

### Accessing the UICC

As we discussed in “[UICC Applications](ch11.html#uicc_applications "UICC Applications")”, mobile network–related functionality in Android, including UICC access, is implemented by the baseband software. The main OS (Android) is limited in what it can do with the UICC by the features the baseband exposes. Android supports STK applications and can look up and store contacts on the SIM, so it’s clear that it has internal support for communicating to the SIM. However, the Android security overview explicitly states that “low-level access to the SIM card is not available to third-party apps.”^([[126](#ftn.ch11fn16)]) How can we use the SIM card (UICC) as an SE then? Some Android builds from major vendors, most notably Samsung, provide an implementation of the SIMalliance Open Mobile API, and an open source implementation (for compatible devices) of the API is available from the SEEK for Android project. The Open Mobile API aims to provide a unified interface for accessing SEs on Android, including the UICC.

To understand how the Open Mobile API works and the cause of its limitations, let’s review how access to the SIM card is implemented in Android. On Android devices, all mobile network functionality (dialing, sending SMS, and so on) is provided by the baseband processor (also referred to as *modem* or *radio*). Android applications and system services communicate with the baseband only indirectly via the Radio Interface Layer (RIL) daemon (*rild*). The *rild* in turn talks to the actual hardware by using a manufacturer-provided RIL HAL library, which wraps the proprietary interface that the baseband provides. The UICC card is typically connected only to the baseband processor (though sometimes also to the NFC controller via SWP), and thus all communication needs to go through the RIL.

While the proprietary RIL implementation can always access the UICC in order to perform network identification and authentication, as well as read and write contacts and access STK applications, support for transparent APDU exchange is not always available. As we mentioned in [UICC](ch11.html#uicc "UICC"), the standard way to provide this feature is to use extended AT commands such `AT+CSIM` (Generic SIM access) and `AT+CGLA` (Generic UICC Logical Channel Access), but some vendors implement APDU exchange using proprietary extensions, so support for the necessary AT commands doesn’t automatically provide UICC access.

SEEK for Android implements a resource manager service (`SmartCardService`) that can connect to any supported SE (eSE, ASSD, or UICC) and extensions to the Android telephony framework that allow for transparent APDU exchange with the UICC. Because access through the RIL is hardware- and HAL-dependent, you need both a compatible device and a build that includes the `SmartCardService` and related framework extensions, such as those found in most recent Samsung Galaxy devices.

### Using the OpenMobile API

The OpenMobile API is relatively small and defines classes that represent the card reader that an SE is connected to (`Reader`), a communication session with an SE (`Session`), and a basic (channel 0, as per ISO 7816-4) or logical channel with the SE (`Channel`). The `Channel` class allows applications to exchange APDUs with the SE using the `transmit()` method. The entry point to the API is the `SEService` class, which connects to the remote resource manager service (`SmartcardService`) and provides a method that returns a list of `Reader` objects available on the device. (For more information about the OpenMobile API and the architecture of the `SmartcardService`, refer to the SEEK for Android Wiki.^([[127](#ftn.ch11fn17)]))

In order to be able to use the OpenMobile API, applications need to request the `org.simalliance.openmobileapi.SMARTCARD` permission and add the *org.simalliance.openmobileapi* extension library to their manifest as shown in [Example 11-12](ch11.html#androidmanifestdotxml_configuration_requ "Example 11-12. AndroidManifest.xml configuration required to use the OpenMobile API").

Example 11-12. AndroidManifest.xml configuration required to use the OpenMobile API

```
<manifest ...>
    --*snip*--
    <uses-permission android:name="org.simalliance.openmobileapi.SMARTCARD" />

    <application ...>
        <uses-library
            android:name="org.simalliance.openmobileapi"
            android:required="true" />
     --*snip*--
    </application>
</manifest>
```

[Example 11-13](ch11.html#sending_a_command_to_the_first_se_using "Example 11-13. Sending a command to the first SE using the OpenMobile API") demonstrates how an application can use the OpenMobile API to connect and send a command to the first SE on the device.

Example 11-13. Sending a command to the first SE using the OpenMobile API

```
Context context = getContext();
SEService.CallBack callback = createSeCallback();
SEService seService = new SEService(context, callback);➊
Reader[] readers = seService.getReaders();➋
Session session = readers[0].openSession();➌
Channel channel = session.openLogicalChannel(aid);➍
byte[] command = { ... };
byte[] response = channel.transmit(command);➎
```

Here, the application first creates an `SEService` ➊ instance, which connects to the `SmartCardService` asynchronously and notifies the application via the `serviceConnected()` method (not shown) of the `SEService.CallBack` interface when the connection is established. The app can then get a list of the available SE readers using the `getReaders()` method ➋, and then open a session to the selected reader using the `openSession()` method ➌. If the device does not contain an eSE (or another form of SE besides the UICC), or the `SmartCardService` hasn’t been configured to use it, the list of readers contains a single `Reader` instance that represents the built-in UICC reader in the device. When the app has an open `Session` with the target SE, it calls the `openLogicalChannel()` method ➍ in order to obtain a `Channel`, which it then uses to send APDUs and receive responses using its `transmit()` method ➎.

# Software Card Emulation

*Software card emulation* (also referred to as *host-based card emulation* or *HCE*) allows commands received by the NFC controller to be delivered to the application processor (main OS), and to be processed by regular Android applications, instead of by applets installed on a hardware SE. Responses are then sent back to the reader via NFC, allowing an app to act as a virtual contactless smart card.

Before being officially added to the Android API, HCE was first available as an experimental feature of the CyanogenMod Android distribution.^([[128](#ftn.ch11fn18)]) Beginning with version 9.1, CyanogenMod integrated a set of patches (developed by Doug Yeager) that unlock the HCE functionality of the popular PN544 NFC controller and provide a framework interface to HCE. In order to support HCE, two new tag technologies (`IsoPcdA` and `IsoPcdB`, representing external contactless readers based on NFC Type A and Type B technology, respectively) were added to the NFC framework. (The letters *Pcd* stand for *Proximity Coupling Device*, which is just another technical term for contactless reader.)

The `IsoPcdA` and `IsoPcdB` classes reversed the role of `Tag` objects in the Android NFC API: because the external contactless reader is presented as a “tag,” “commands” you send from the phone are actually replies to the reader-initiated communication. Unlike the rest of Android’s NFC stack, this architecture was not event driven and required applications to handle blocking I/O while waiting for the reader to send its next command. Android 4.4 introduced a standard, event-driven framework for developing HCE applications, which we discuss next.

## Android 4.4 HCE Architecture

Unlike the R/W and P2P mode, which are only available to activities, HCE applications can work in the background and are implemented by defining a service that processes commands received from the external reader and returns responses. Such HCE services extend the `HostApduService` abstract framework class and implement its `onDeactivated()` and `processCommand()` methods. `HostApduService` itself is a very thin mediator class that enables twoway communication with the system `NfcService` by using `Messenger` objects.^([[129](#ftn.ch11fn19)]) For example, when the `NfcService` receives an APDU that needs to be routed (APDU routing is discussed in the next section) to a HCE service, it sends a `MSG_COMMAND_APDU` to `HostApduService`, which then extracts the APDU from the message and passes it to its concrete implementation by calling the `processCommand()` method. If `processCommand()` returns an APDU, `HostApduService` encapsulates it in a `MSG_RESPONSE_APDU` message and sends it to the `NfcService`, which in turn forwards it to the NFC controller. If the concrete HCE service cannot return a response APDU immediately, it returns `null` and sends the response later (when it is available) by calling the `sendResponseApdu()`, which sends the response to the `NfcService` wrapped in a `MSG_RESPONSE_APDU` message.

## APDU Routing

When the device is in card emulation mode, the NFC controller receives all APDUs coming from external readers and decides whether to send them to a physical SE (if any), or to an HCE service based on its internal APDU routing table. The routing table is AID-based and is populated using the metadata SE-enabled applications and HCE services declared in their application manifests. When the external reader sends a `SELECT` command that is not directly routed to the SE, the NFC controller forwards it to the `NfcService`, which extracts the target AID from the command and searches the routing table for a matching HCE service by calling the `resolveAidPrefix()` method of the `RegisteredAidCache` class.

If a matching service is found, `NfcService` binds to it and obtains a `Messenger` instance, which it then uses to send subsequent APDUs (wrapped in `MSG_COMMAND_APDU` messages, as discussed in the previous section). For this to work, the app’s HCE service needs to be declared in *AndroidManifest.xml* as shown in [Example 11-14](ch11.html#declaring_a_hce_service_in_androidmanife "Example 11-14. Declaring a HCE service in AndroidManifest.xml").

Example 11-14. Declaring a HCE service in AndroidManifest.xml

```
<?xml version="1.0" encoding="utf-8"?>
<manifest 
    package="com.example.hce" ...>
    --*snip*--
    <uses-permission android:name="android.permission.NFC" />

    <application ...>
        --*snip*--
        <service
            android:name=".MyHostApduService"➊
            android:exported="true"
            android:permission="android.permission.BIND_NFC_SERVICE" >➋
            <intent-filter>
                <action
                    android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE" />➌
            </intent-filter>

            <meta-data
                android:name="android.nfc.cardemulation.host_apdu_service"➍
                android:resource="@xml/apduservice" />
        </service>
        --*snip*--
    </application>
</manifest>
```

The application declares its HCE service ➊ as usual, using the `<service>` tag, but there are a few additional requirements. First, the service must be protected with the `BIND_NFC_SERVICE` system signature permission ➋, to guarantee that only system apps (in practice, only the `NfcService`) can bind to it. Next, the service needs to declare an intent filter that matches the `android.nfc.cardemulation.action.HOST_APDU_SERVICE` action ➌ so that it can be identified as a HCE service when scanning installed packages, and be bound to when a matching APDU is received. Finally, the service must have an XML resource metadata entry under the name *android.nfc.cardemulation.host_apdu_ service* ➍, which points to an XML resource file listing the AIDs that the service can handle. The contents of this file is used to build the AID routing table, which the NFC stack consults when it receives a `SELECT` command.

### Specifying Routing for HCE Services

For HCE applications, the XML file must include a `<host-apdu-service>` root element as shown in [Example 11-15](ch11.html#hce_service_aid_metadata_file "Example 11-15. HCE service AID metadata file").

Example 11-15. HCE service AID metadata file

```
<host-apdu-service

    android:description="@string/servicedesc"
    android:requireDeviceUnlock="false">➊
    <aid-group android:description="@string/aiddescription"➋
               android:category="other">➌
        <aid-filter android:name="A0000000010101"/>➍
    </aid-group>
</host-apdu-service>
```

The `<host-apdu-service>` tag has a `description` attribute and a `requireDeviceUnlock` attribute ➊, which specifies whether the corresponding HCE service should be activated when the device is locked. (The device’s screen must be on for NFC to work.) The root element contains one or more `<aid-group>` entries ➋, which each have a `category` attribute ➌ and contain one or more `<aid-filter>` ➍ tags that specify an AID in their `name` attribute (*A0000000010101* in this example).

An AID group defines a set of AIDs that is always handled by a particular HCE service. The NFC framework guarantees that if a single AID is handled by an HCE service, then all other AIDs in the group are also handled by the same service. If two or more HCE services define the same AID, the system shows a selection dialog letting the user choose which application should handle the incoming `SELECT` command. When an app is chosen, all subsequent commands are routed to it after the user confirms the selection by tapping on the dialog shown in [Figure 11-2](ch11.html#hce_application_selection_confirmation_d "Figure 11-2. HCE application selection confirmation dialog").

Each AID group is associated with a category (specified with the `category` attribute), which allows the system to set a default handler per category, rather than per AID. An application can check if a particular service is the default handler for a category by calling the `isDefaultServiceForCategory()` method of the `CardEmulation` class, and get the selection mode for a category by calling the `getSelectionModeForCategory()` method. As of this writing, only two categories are defined: `CATEGORY_PAYMENT` and `CATEGORY_OTHER`.

Android enforces a single active payment category in order to ensure that the user has explicitly selected which app should handle payment transactions. The default app for the payment category is selected in the Tap & pay screen of the system Settings app, as shown in [Figure 11-3](ch11.html#selecting_the_default_payment_applicatio "Figure 11-3. Selecting the default payment application in the Tap & pay screen"). (See the official HCE documentation^([[130](#ftn.ch11fn20)]) for more on payment applications.)

![HCE application selection confirmation dialog](figs/web/11fig02.png.jpg)

Figure 11-2. HCE application selection confirmation dialog

![Selecting the default payment application in the Tap & pay screen](figs/web/11fig03.png.jpg)

Figure 11-3. Selecting the default payment application in the Tap & pay screen

### Specifying Routing for SE Applets

If a device supports HCE and also has a physical SE, a `SELECT` command sent by an external reader can target either an HCE service, or an applet installed on the SE. Because Android 4.4 directs all AIDs not listed in the AID routing table to the host, the AIDs of applets installed on the SE must be explicitly added to the NFC controller’s routing table. This is accomplished with the same mechanism used for registering HCE services: by adding a service entry to the application’s manifest, and linking it to a meta-data XML file that specifies a list of AIDs that should be routed to the SE. When the route is established, command APDUs are sent directly to the SE (which processes them and returns a response via the NFC controller), so the service is used only as a marker and provides no functionality.

The Android SDK includes a helper service (`OffHostApduService`) that can be used to list AIDs that should be routed directly to the SE. This `OffHostApduService` class defines some useful constants, but is otherwise empty. An application can extend it and declare the resulting service component in its manifest as shown in [Example 11-16](ch11.html#declaring_an_off-host_apdu_service_in_an "Example 11-16. Declaring an off-host APDU service in AndroidManifest.xml").

Example 11-16. Declaring an off-host APDU service in AndroidManifest.xml

```
<manifest 
    package="com.example.hce" ...>
    --*snip*--
    <uses-permission android:name="android.permission.NFC" />

    <application ... >
        --*snip*--
        <service android:name=".MyOffHostApduService"
                 android:exported="true"
                 android:permission="android.permission.BIND_NFC_SERVICE">
        <intent-filter>
            <action
                android:name="android.nfc.cardemulation.action.OFF_HOST_APDU_SERVICE"/>➊
        </intent-filter>
        <meta-data
            android:name="android.nfc.cardemulation.off_host_apdu_service"➋
            android:resource="@xml/apduservice"/>
    </service>
    --*snip*--
    </application>
</manifest>
```

The service declaration is similar to that of [Example 11-14](ch11.html#declaring_a_hce_service_in_androidmanife "Example 11-14. Declaring a HCE service in AndroidManifest.xml"), except that the declared intent action is *android.nfc.cardemulation.action.OFF_HOST_ APDU_SERVICE* ➊ and the XML metadata name is *android.nfc.cardemulation.off_host_apdu_service* ➋. The metadata file is also slightly different, as shown in [Example 11-17](ch11.html#off-host_apdu_service_metadata_file "Example 11-17. Off-host APDU service metadata file").

Example 11-17. Off-host APDU service metadata file

```
<offhost-apdu-service

    android:description="@string/servicedesc">➊
    <aid-group android:description="@string/se_applets"
               android:category="other">➋
        <aid-filter android:name="F0000000000001"/>➌
        <aid-filter android:name="F0000000000002"/>➍
    </aid-group>
</offhost-apdu-service>
```

As you can see, the format is the same as that of an HCE service, but the root element of the file is `<offhost-apdu-service>` ➊ instead of `<host-apdu-service>`. Another subtle difference is that `<offhost-apdu-service>` does not support the `requireDeviceUnlock` attribute, because transactions are sent directly to the SE and therefore the host cannot intervene regardless of the state of the lockscreen. The AIDs of the applets residing on the SE (➌ and ➍) are included in a `<aid-group>` ➋. Those AIDs are sent directly to the NFC controller, which saves them in its internal routing table in order to be able to send matching APDUs directly to the SE, without interacting with the Android OS. If the received APDU is not in the NFC controller’s routing table, it forwards it to the `NfcService`, which sends it to the matching HCE service, or returns an error if no matches are found.

## Writing an HCE Service

When the HCE service of an application has been declared in its manifest as shown in [Example 11-14](ch11.html#declaring_a_hce_service_in_androidmanife "Example 11-14. Declaring a HCE service in AndroidManifest.xml"), HCE functionality can be added by extending the `HostApduService` base class and implementing its abstract methods as shown in [Example 11-18](ch11.html#implementing_a_hostapduservice "Example 11-18. Implementing a HostApduService").

Example 11-18. Implementing a `HostApduService`

```
public class MyHostApduService extends HostApduService {
    --*snip*--
    static final int OFFSET_CLA = 0;➊
    static final int OFFSET_INS = 1;
    static final int OFFSET_P1 = 2;
    static final int OFFSET_P2 = 3;
    --*snip*--
    static final short SW_SUCCESS = (short) 0x9000;➋
    static final short SW_CLA_NOT_SUPPORTED = 0x6E00;
    static final short SW_INS_NOT_SUPPORTED = 0x6D00;
    --*snip*--
    static final byte[] SELECT_CMD = { 0x00, (byte) 0xA4,
            0x04, 0x00, 0x06, (byte) 0xA0,
            0x00, 0x00, 0x00, 0x01, 0x01, 0x01 };➌

    static final byte MY_CLA = (byte) 0x80;➍
    static final byte INS_CMD1 = (byte) 0x01;
    static final byte INS_CMD2 = (byte) 0x02;

    boolean selected = false;

    public byte[] processCommandApdu(byte[] cmd, Bundle extras) {
        if (!selected) {
            if (Arrays.equals(cmd, SELECT_CMD)) {➎
                selected = true;

                return toBytes(SW_SUCCESS);
            }
            --*snip*-
        }

        if (cmd[OFFSET_CLA] != MY_CLA) {➏
            return toBytes(SW_CLA_NOT_SUPPORTED);
        }

        byte ins = cmd[OFFSET_INS];➐
        switch (ins) {
            case INS_CMD1:➑
                byte p1 = cmd[OFFSET_P1];
                byte p2 = cmd[OFFSET_P2];
                --*snip*--
                return toBytes(SW_SUCCESS);
            case INS_CMD2:
                --*snip*--
                return null;➒
            default:
                return toBytes(SW_INS_NOT_SUPPORTED);
        }
    }

    @Override
    public void onDeactivated(int reason) {
        --*snip*--
        selected = false;➊
    }
    --*snip*--
}
```

Here, the example HCE service first declares a few constants that will be helpful when accessing APDU data ➊ and returning a standard status result ➋. The service defines the `SELECT` command that is used to activate it, including the AID ➌. The next few constants ➍ declare the instruction class (*CLA*) and instructions that the service can handle.

When the HCE service receives an APDU, it passes it to the `processCommandApdu()` method as a byte array, which the service analyzes. If the service hasn’t been selected yet, the `processCommandApdu()` method checks if the APDU contains a `SELECT` command ➎, and sets the `selected` flag if it does. If the APDU contains some other command, the code checks to see if it has a class byte (*CLA*) the services supports ➏, and then extracts the instruction byte (*INS*) included in the command ➐. If the command APDU contains the `INS_CMD1` instruction ➑, the service extracts the *P1* and *P2* parameters, possibly parses the data included in the APDU (not shown), sets some internal state, and returns a success status.

If the command includes `INS_CMD2`, which in our example maps to a hypothetical operation that requires some time to process (for example, asymmetric key generation), the service starts a worker thread (not shown), and returns `null` ➒ in order not to block the main thread of the application. When the worker thread completes execution, it can return its result using the inherited `sendResponseApdu()` (defined in the parent `HostApduService` class). When another service or SE applet is selected, the system calls the `onDeactivated()` method, which should release any used resources before returning, but in our example simply sets the `selected` flag to `false` ➓.

Because an HCE service essentially parses command APDUs and returns responses, the programming model is very similar to that of Java Card applets. However, because a HCE service lives inside a regular Android application, it does not execute in a constrained environment and can take advantage of all available Android features. This makes it easy to implement complex functionality, but also impacts the security of HCE apps, as discussed next.

## Security of HCE Applications

Because any Android application can declare an HCE service and receive and process APDUs, the system guarantees that a malicious application cannot inject rogue APDU commands into an HCE service by requiring the `BIND_NFC_SERVICE` system signature permission in order to bind to HCE services. Additionally, Android’s sandboxing model ensures that other applications cannot access sensitive data stored by the HCE application by reading its files or calling any data access APIs it might expose without permission (assuming such APIs have been properly secured, of course).

Nevertheless, a malicious application that manages to obtain root privileges on a device (for example, by exploiting a privilege escalation vulnerability) can both inspect and inject APDUs targeted at an HCE service, and read its private data. The HCE application can take some measures to detect this situation, for example by inspecting the identity and signing certificate of the caller of its `processCommandApdu()` method, but such measures can ultimately be defeated given unconstrained access to the OS. Like all applications that store sensitive data, HCE applications should also take steps to protect stored data, such as by encrypting it on disk or by storing it in the system credential store in the case of cryptographic keys. Another way to protect both the code and data of HCE applications is to forward all received commands to a remote server, over an encrypted channel, and relay only its replies. However, because most of these measures are implemented in software, they can ultimately be disabled or bypassed by a sufficiently sophisticated malicious application with root access.

In contrast, hardware security elements offer physical tamper resistance, reduced attack surface due to their constrained functionality, and tight control over installed applets. Therefore, physical SEs are much harder to attack and provide much stronger protection of sensitive data used in typical card emulation scenarios like contactless payments, even when the default security guarantees of the host OS have been bypassed.

### Note

*For a detailed discussion of the difference in security level of card emulation applications when implemented in secure elements as opposed to in software using HCE, see the “HCE vs embedded secure element” blog post series by Cem Paya (who worked on the original eSE-backed Google Wallet implementation).*^([[131](#ftn.ch11fn21)])

# Summary

Android supports the three NFC modes: reader/writer, point-to-point, and card emulation. In reader/writer mode, Android devices can access NFC tags, contactless cards, and NFC emulation devices, while the point-to-point mode provides simple data exchange functionality. The card emulation mode can be backed either by a physical secure element (SE) such as a UICC, one that is integrated with the NFC controller (embedded SE), or by regular Android applications since Android 4.4\. Hardware security elements provide the highest security by offering physical tamper resistance and stringent control over SE application (typically implemented as Java Card applets) management. However, because the authentication keys required to install an application on an SE are typically controlled by a single entity (such as the device manufacturer or MNO), distributing SE applications can be problematic. Host-based card emulation (HCE), introduced in Android 4.4, makes it easy to develop and distribute applications that work in card emulation mode, but it relies solely on the OS to enforce security and therefore offers weaker protection of sensitive application code and data.

* * *

^([[111](#ch11fn01)]) The NDEF format and its implementation using various tag technologies are described in the NFC Forum specification, available on its website: *[http://nfc-forum.org/our-work/specifications-and-application-documents/specifications/nfc-forum-technical-specifications/](http://nfc-forum.org/our-work/specifications-and-application-documents/specifications/nfc-forum-technical-specifications/)*

^([[112](#ch11fn02)]) Official versions of all ISO standards can be purchased on its website, *[http://www.iso.org/iso/home/store/catalogue_ics.htm](http://www.iso.org/iso/home/store/catalogue_ics.htm)*. Draft versions of standards can usually be obtained from the website of the standard working group.

^([[113](#ch11fn03)]) Google, *Android API Reference*, “TagTechnology,” *[https://developer.android.com/reference/android/nfc/tech/TagTechnology.html](https://developer.android.com/reference/android/nfc/tech/TagTechnology.html)*

^([[114](#ch11fn04)]) Google, *Android API Reference*, “NfcAdapter,” *[https://developer.android.com/reference/android/nfc/NfcAdapter.html](https://developer.android.com/reference/android/nfc/NfcAdapter.html)*

^([[115](#ch11fn05)]) NFC Forum, “NFC Forum Technical Specifications,” *[http://nfc-forum.org/our-work/specifications-and-application-documents/specifications/nfc-forum-technical-specifications/](http://nfc-forum.org/our-work/specifications-and-application-documents/specifications/nfc-forum-technical-specifications/)*

^([[116](#ch11fn06)]) Google, *Android API Guides*, “NFC Basics,” *[https://developer.android.com/guide/topics/connectivity/nfc/nfc.html#p2p](https://developer.android.com/guide/topics/connectivity/nfc/nfc.html#p2p)*

^([[117](#ch11fn07)]) 3GPP, *AT command set for User Equipment (UE)*, *[http://www.3gpp.org/ftp/Specs/html-info/27007.htm](http://www.3gpp.org/ftp/Specs/html-info/27007.htm)*

^([[118](#ch11fn08)]) “Secure Element Evaluation Kit for the Android platform,” *[https://code.google.com/p/seek-for-android/](https://code.google.com/p/seek-for-android/)*

^([[119](#ch11fn09)]) SIMalliance Limited, *Open Mobile API Specification v2.05*, *[http://www.simalliance.org/en?t=/documentManager/sfdoc.file.supply&fileID=1392314878580](http://www.simalliance.org/en?t=/documentManager/sfdoc.file.supply&fileID=1392314878580)*

^([[120](#ch11fn10)]) SD Association, “Advanced Security SD Card: ASSD,” *[https://www.sdcard.org/developers/overview/ASSD/](https://www.sdcard.org/developers/overview/ASSD/)*

^([[121](#ch11fn11)]) ECMA International, *ECMA-373: Near Field Communication Wired Interface (NFC-WI)*, *[http://www.ecma-international.org/publications/files/ECMA-ST/ECMA-373.pdf](http://www.ecma-international.org/publications/files/ECMA-ST/ECMA-373.pdf)*

^([[122](#ch11fn12)]) Oracle, “JSR 177: Security and Trust Services API for J2METM,” *[https://jcp.org/en/jsr/detail?id=177](https://jcp.org/en/jsr/detail?id=177)*

^([[123](#ch11fn13)]) Oracle, “Java Card Classic Platform Specification 3.0.4,” *[http://www.oracle.com/technetwork/java/javacard/specs-jsp-136430.html](http://www.oracle.com/technetwork/java/javacard/specs-jsp-136430.html)*

^([[124](#ch11fn14)]) GlobalPlatform, “Card Specifications,” *[http://www.globalplatform.org/specificationscard.asp](http://www.globalplatform.org/specificationscard.asp)*

^([[125](#ch11fn15)]) A summary of ISO 7816 and other smart card-related standards is available on CardWerk’s website: *[http://www.cardwerk.com/smartcards/smartcard_standards.aspx](http://www.cardwerk.com/smartcards/smartcard_standards.aspx)*

^([[126](#ch11fn16)]) Google, *Android Security Overview*, “SIM Card Access,” *[https://source.android.com/devices/tech/security/#sim-card-access](https://source.android.com/devices/tech/security/#sim-card-access)*

^([[127](#ch11fn17)]) *SEEK for Android*, “SmartCardAPI*,” [https://code.google.com/p/seek-for-android/wiki/SmartcardAPI](https://code.google.com/p/seek-for-android/wiki/SmartcardAPI)*

^([[128](#ch11fn18)]) CyanogenMod*, [http://www.cyanogenmod.org/](http://www.cyanogenmod.org/)*

^([[129](#ch11fn19)]) Google, *Android API Reference*, “Messenger,” *[https://developer.android.com/reference/android/os/Messenger.html](https://developer.android.com/reference/android/os/Messenger.html)*

^([[130](#ch11fn20)]) Google*, Host-based Card Emulation*, “Payment Applications,” *[https://developer.android.com/guide/topics/connectivity/nfc/hce.html#PaymentApps](https://developer.android.com/guide/topics/connectivity/nfc/hce.html#PaymentApps)*

^([[131](#ch11fn21)]) Cem Paya*, Random Oracle*, “HCE vs embedded secure element,” parts I to VI, *[http://randomoracle.wordpress.com/2014/03/08/hce-vs-embedded-secure-element-comparing-risks-part-i/](http://randomoracle.wordpress.com/2014/03/08/hce-vs-embedded-secure-element-comparing-risks-part-i/)*
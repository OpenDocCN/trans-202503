# Chapter 9. Enterprise Security

Initial Android versions were mostly consumer-oriented, with limited enterprise features. However, as the platform has grown in popularity, Android devices have entered the workplace and are increasingly used to access corporate email, customer information, and other company data. As a result of this trend, the need for increased platform security and tools that allow effective management of employee devices has steadily grown. While Android’s primary focus remains general-purpose consumer devices, recent versions have introduced numerous enterprise features and Android will likely become even more enterprise-friendly as it develops.

In this chapter, we discuss Android’s major enterprise-oriented features and demonstrate how they can be used to both increase device security and provide centralized device policy management. We’ll begin with device administration, and show how it can be integrated into third-party applications. We then look into Android’s VPN support and describe the APIs that allow new VPN solutions to be developed as third-party, user-installed applications. Next we show how Android implements different authentication methods supported by the EAP authentication framework and describe how it manages credentials. Finally, we demonstrate how to add an EAP profile programmatically using the extended Wi-Fi management APIs added in Android 4.3.

# Device Administration

Android 2.2 introduced support for a Device Administration API, which makes it possible to develop applications that can both enforce a systemwide security policy and dynamically adapt their features based on the device’s current security level. Such applications are called *device administrators*. Device administrators must be explicitly enabled in the device’s security settings and cannot be uninstalled if they are active. When enabled, they’re granted special privileges that allow them to lock the device, change the lockscreen password, and even wipe the device (delete all user data). Device administrators are often coupled with a specific type of enterprise account (such as a Microsoft Exchange or Google Apps account), which allows enterprise administrators to control access to corporate data by allowing access only to devices that conform to the required security policy. Security policies can be static and built into the device administrator application, or they can be configured on the server side and sent to the device as part of a provisioning or synchronization protocol.

As of version 4.4, Android supports the policy types listed in [Table 9-1](ch09.html#supported_device_administration_policies "Table 9-1. Supported Device Administration Policies"). The policy constants are defined in the `DeviceAdminInfo` class.^([[87](#ftn.ch09fn01)])

Table 9-1. Supported Device Administration Policies

| Policy Constant/XML Tag | Value (bit to set) | Description | API Level |
| --- | --- | --- | --- |
| `USES_POLICY_LIMIT_PASSWORD <limit-password>` | 0 | Limit the passwords that the user can select by setting a minimum length or complexity. | 8 |
| `USES_POLICY_WATCH_LOGIN <watch-login>` | 1 | Watch login attempts by a user. | 8 |
| `USES_POLICY_RESET_PASSWORD <reset-password>` | 2 | Reset a user’s password. | 8 |
| `USES_POLICY_FORCE_LOCK <force-lock>` | 3 | Force the device to lock, or limit the maximum lock timeout. | 8 |
| `USES_POLICY_WIPE_DATA <wipe-data>` | 4 | Factory reset the device, erasing all user data. | 8 |
| `USES_POLICY_SETS_GLOBAL_PROXY <set-global-proxy>` | 5 | Specify the device global proxy. (This is hidden from SDK applications.) | 9 |
| `USES_POLICY_EXPIRE_PASSWORD <expire-password>` | 6 | Force the user to change their password after an administrator-defined time limit. | 11 |
| `USES_ENCRYPTED_STORAGE <encrypted-storage>` | 7 | Require stored data to be encrypted. | 11 |
| `USES_POLICY_DISABLE_CAMERA <disable-camera>` | 8 | Disable the use of all device cameras. | 14 |
| `USES_POLICY_DISABLE_KEYGUARD_FEATURES <disable-keyguard-features>` | 9 | Disable the use of keyguard features such as lockscreen widgets or camera support. | 17 |

Each device administration application must list the policies it intends to use in a metadata file (see “[Privilege Management](ch09.html#privilege_management "Privilege Management")” for details). The list of supported policies is displayed to the user when they activate the administrator app, as shown in [Figure 9-1](ch09.html#device_administrator_activation_screen "Figure 9-1. Device administrator activation screen").

## Implementation

Now that we know which policies can be enforced with the Device Administration API, let’s look at the internal implementation. Like most public Android APIs, a manager class called `DevicePolicyManager`^([[88](#ftn.ch09fn02)]) exposes part of the functionality of the underlying system service, `DevicePolicyManagerService`. However, because the `DevicePolicyManager` facade class defines constants and translates service exceptions to return codes but otherwise adds little functionality, we’ll focus on the `DevicePolicyManagerService` class.

![Device administrator activation screen](figs/web/09fig01.png.jpg)

Figure 9-1. Device administrator activation screen

Like most system services, `DevicePolicyManagerService` is started by and runs within the *system_server* process as the *system* user, and thus can execute almost all Android privileged actions. Unlike most system services, it can grant access to certain privileged actions (such as changing the lockscreen password) to third-party applications, which do not need to hold any special system permissions. This makes it possible for users to enable and disable device administrators on demand, and guarantees that device administrators can only enforce policies that they have explicitly declared. However, this level of flexibility cannot be easily implemented with standard Android permissions that are only granted at install time and cannot be revoked (with some exceptions, as discussed in [Chapter 2](ch02.html "Chapter 2. Permissions")). Therefore, `DevicePolicyManagerService` employs a different method for privilege management.

Another interesting aspect of Android’s device administration implementation relates to how policies are managed and enforced. We describe device administrator privilege management and policy enforcement in detail next.

### Privilege Management

At runtime, the `DevicePolicyManagerService` keeps an internal, on-memory list of policy structures for each device user. (Policies are also persisted on disk in an XML file, as described in the next section.)

Each policy structure contains the currently effective policy for a certain user and a list of metadata about each active device administrator. Because each user can enable more than one application with device administrator functionality, the currently active policy is calculated by selecting the strictest defined policy among all administrators. The metadata about each active device administrator contains information about the declaring application, and a list of declared policies (represented by a bitmask).

The `DevicePolicyManagerService` decides whether to grant access to privileged operations to a calling application based on its internal list of active policies: if the calling application is currently an active device administrator, and it has requested the policy that corresponds to the current request (API call), only then is the request granted and the operation executed. In order to confirm that an active administrator component really belongs to the calling application, `DevicePolicyManagerService` compares the UID of the calling process (returned by `Binder.getCallingUid()`) with the UID associated with the target administrator component. For example, an application that calls the `resetPassword()` needs to be an active device administrator, have the same UID as the registered administrator component, and have requested the `USES_POLICY_RESET_PASSWORD` policy in order for the call to succeed.

Policies are requested by adding an XML resource file that lists all policies that a device administrator application wants to use as children of the `<uses-policies>` tag. Before a device administrator is activated, the system parses the XML file and displays a dialog similar to the one in [Figure 9-1](ch09.html#device_administrator_activation_screen "Figure 9-1. Device administrator activation screen"), allowing the user to review the requested policies before enabling the administrator. Much like Android permissions, administrator policies are granted on an all-or-nothing basis, and there is no way to selectively enable only certain policies. A resource file that requests all policies might look like [Example 9-1](ch09.html#declaring_policies_in_a_device_administr "Example 9-1. Declaring policies in a device administrator application") (for the policy corresponding to each tag, see the first column of [Table 9-1](ch09.html#supported_device_administration_policies "Table 9-1. Supported Device Administration Policies")). You can find more details about adding this file to a device administrator application in “[Adding a Device Administrator](ch09.html#adding_a_device_administrator "Adding a Device Administrator")”.

Example 9-1. Declaring policies in a device administrator application

```
<?xml version="1.0" encoding="utf-8"?>
<device-admin >
    <uses-policies>
        <limit-password />
        <watch-login />
        <reset-password />
        <force-lock />
        <wipe-data />
        <expire-password />
        <encrypted-storage />
        <disable-camera />
        <disable-keyguard-features />
        <set-global-proxy />
    </uses-policies>
</device-admin>
```

In order to be notified about policy-related system events and to be allowed access to the Device Administration API, device administrators must be activated first. This is achieved by calling the `setActiveAdmin()` method of the `DevicePolicyManagerService`. Because this method requires the `MANAGE_DEVICE_ADMINS` permission, which is a system signature permission, only system applications can add a device administrator without user interaction.

User-installed device administrator applications can only request to be activated by starting the `ACTION_ADD_DEVICE_ADMIN` implicit intent with code similar to [Example 9-2](ch09.html#requesting_device_administrator_activati "Example 9-2. Requesting device administrator activation"). The only handler for this intent is the system Settings application, which holds the `MANAGE_DEVICE_ADMINS` permission. Upon receiving the intent, the Settings applications checks whether the requesting application is a valid device administrator, extracts the requested policies, and builds the confirmation dialog shown in [Figure 9-1](ch09.html#device_administrator_activation_screen "Figure 9-1. Device administrator activation screen"). The user pressing the Activate button calls the `setActiveAdmin()` method, which adds the application to the list of active administrators for the current device user.

Example 9-2. Requesting device administrator activation

```
Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
ComponentName admin = new ComponentName(this, MyDeviceAdminReceiver.class);
intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin);
intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Required for corporate email access.");
startActivityForResult(intent, REQUEST_CODE_ENABLE_ADMIN);
```

### Policy Persistence

When a device administrator is activated, deactivated, or its policies are updated, changes are written to the *device_policies.xml* file for the target user. For the owner user, that file is stored under */data/system/*, and for all other users it’s written to the user’s system directory (*/data/users/<user-ID>/*). The file is owned by and only modifiable by the *system* user (file permissions 0600).

The *device_policies.xml* file contains information about each active administrator and its policies, as well some global information about the current lockscreen password. The file might look like [Example 9-3](ch09.html#contents_of_the_devicesunderscorepolicie "Example 9-3. Contents of the devices_policies.xml file").

Example 9-3. Contents of the devices_policies.xml file

```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<policies>
  <admin name="com.google.android.gms/com.google.android.gms.mdm.receivers.MdmDeviceAdminReceiver">➊
    <policies flags="28" />
  </admin>
  <admin name="com.example.android.apis/com.example.android.apis.app.DeviceAdminSampleReceiver">➋
    <policies flags="1023" />➌
    <password-quality value="327680" />➍
    <min-password-length value="6" />
    <min-password-letters value="2" />
    <min-password-numeric value="2" />
    <max-time-to-unlock value="300000" />
    <max-failed-password-wipe value="100" />
    <encryption-requested value="true" />
    <disable-camera value="true" />
    <disable-keyguard-features value="1" />
</admin>
<admin name="com.android.email/com.android.email.SecurityPolicy$PolicyAdmin">➎
  <policies flags="475" />
</admin>
<password-owner value="10076" />➏
<active-password quality="327680" length="6"
                 uppercase="0" lowercase="3"
                 letters="3" numeric="3" symbols="0" nonletter="3" />➐
</policies>
```

This example has three active device administrators, each represented by an `<admin>` element (➊, ➋, and ➎). The policies of each administrator app are stored in the `flags` attribute of the `<policies>` tag ➌.

A policy is considered enabled if its corresponding bit is set (see the Value column of [Table 9-1](ch09.html#supported_device_administration_policies "Table 9-1. Supported Device Administration Policies")). For example, because the *DeviceAdminSample* application has requested all currently available policies, its `flags` attribute has the value 1023 (0x3FF, or 1111111111 in binary).

If the administrator defines password quality restrictions (for example, alphanumeric or complex), they are persisted as the `value` attribute of the `<password-quality>` tag ➍. In this example, the value 327680 (0x50000) corresponds to `PASSWORD_QUALITY_ALPHANUMERIC`. (Password quality constants are defined in the `DevicePolicyManager` class.)

The values of other policy requirements, such as password length and device encryption, are also stored as children of each `<admin>` element. If the password has been set programmatically by using the `resetPassword()` method, *device_policies.xml* contains a `<password-owner>` tag that stores the UID of the application that sets the password in its `value` attribute ➏. Finally, the `<active-password>` tag contains details about the complexity of the current password ➐.

### Policy Enforcement

Device administrator policies have different granularity and can be enforced either for the current user or for all users on a device. Some policies are not enforced by the system at all—the system only notifies the declaring administration application, which is then responsible for taking an appropriate action. In this section, we describe how each type of policy is implemented and enforced.

**`USES_POLICY_LIMIT_PASSWORD`**

After one or more password restrictions have been set, users cannot enter a password that does not fulfill the current policy. However, the system does not require passwords to be changed immediately, so the current password remains in effect until changed. Administrator applications can prompt the user for a new password by starting an implicit intent with the `DevicePolicyManager.ACTION_SET_NEW_PASSWORD` action.

Because each device user has a separate unlock password, password quality policies are applied per-user. When password quality is set, unlock methods that do not allow for a password of the desired quality are disabled. For example, setting password quality to `PASSWORD_ QUALITY_ALPHANUMERIC` disables the Pattern and PIN unlock methods, as shown in [Figure 9-2](ch09.html#setting_a_password_quality_policy_disabl "Figure 9-2. Setting a password quality policy disables incompatible unlock methods").

![Setting a password quality policy disables incompatible unlock methods](figs/web/09fig02.png.jpg)

Figure 9-2. Setting a password quality policy disables incompatible unlock methods

**`USES_POLICY_WATCH_LOGIN`**

This policy enables device administrators to receive notifications about the outcome of login attempts. Notifications are sent with the `ACTION_PASSWORD_FAILED` and `ACTION_PASSWORD_SUCCEEDED` broadcasts. Broadcast receivers that derive from `DeviceAdminReceiver` are automatically notified via the `onPasswordFailed()` and `onPasswordSucceeded()` methods.

**`USES_POLICY_RESET_PASSWORD`**

This policy enables administrator applications to set the current user’s password via the `resetPassword()` API. The specified password must satisfy the current password quality requirements and takes effect immediately. Note that if the device is encrypted, setting the lockscreen password for the owner user also changes the device encryption password. ([Chapter 10](ch10.html "Chapter 10. Device Security") provides more detail on device encryption.)

**`USES_POLICY_FORCE_LOCK`**

This policy allows administrators to lock the device immediately by calling the `lockNow()` method, or to specify the maximum time for user inactivity until the device locks automatically via `setMaximumTimeToLock()`. Setting the maximum time to lock takes effect immediately and limits the inactivity sleep time that users can set via the system Display settings.

**`USES_POLICY_WIPE_DATA`**

This policy allows device administrators to wipe user data by calling the `wipeData()` API. Applications that also request the `USES_POLICY_WATCH_LOGIN` policy can set the number of failed login attempts before the device is wiped automatically via the `setMaximumFailedPasswordsForWipe()` API. When the number of failed passwords is set to a value greater than zero, the lockscreen implementation notifies the `DevicePolicyManagerService` and displays a warning dialog after each failed attempt, and triggers a data wipe once the threshold is reached. If the wipe is triggered by an unsuccessful login attempt by the owner user, a full device wipe is performed. If, on the other hand, the wipe is triggered by a secondary user, only that user (and any associated data) is deleted and the device switches to the owner user.

### Note

*Full device wipe is not immediate, but is implemented by writing a `wipe_data` command in the* cache *partition and rebooting into recovery mode. The recovery OS is responsible for executing the actual device wipe. Therefore, if the device has a custom recovery image that ignores the wipe command, or if the user manages to boot into a custom recovery and delete or modify the command file, the device wipe might not be executed. ([Chapter 10](ch10.html "Chapter 10. Device Security") and [Chapter 13](ch13.html "Chapter 13. System Updates and Root Access") discuss recovery images in more detail.)*

**`USES_POLICY_SETS_GLOBAL_PROXY`**

As of Android 4.4, this policy is not available to third-party applications. It allows device administrators to set the global proxy server host (`Settings.Global.GLOBAL_HTTP_PROXY_HOST`), port (`GLOBAL_HTTP_PROXY_PORT`), and the list of excluded hosts (`GLOBAL_HTTP_PROXY_EXCLUSION_LIST`) by writing to the global system settings provider. Only the device owner is allowed to set global proxy settings.

**`USES_POLICY_EXPIRE_PASSWORD`**

This policy allows administrators to set the password expiration timeout via the `setPasswordExpirationTimeout()` API. If an expiration timeout is set, the system registers a daily alarm that checks for password expiration. If the password has already expired, `DevicePolicyManagerService` posts daily password change notifications until it is changed. Device administrators are notified about password expiration status via the `Dev iceAdminReceiver.onPasswordExpiring()` method.

**`USES_ENCRYPTED_STORAGE`**

This policy allows administrators to request that device storage be encrypted via the `setStorageEncryption()` API. Only the owner user can request storage encryption. Requesting storage encryption does not automatically start the device encryption process if the device is not encrypted; device administrators must check the current storage status by using the `getStorageEncryptionStatus()` API (which checks the *ro.crypto.state* read-only system property), and start the encryption process. Device encryption can be kicked off by starting the associated system activity with the `ACTION_START_ENCRYPTION` implicit intent.

**`USES_POLICY_DISABLE_CAMERA`**

This policy allows device administrators to disable all cameras on the device via the `setCameraDisabled()` API. Camera is disabled by setting the *sys.secpolicy.camera.disabled* system property to 1\. The native system `CameraService` checks this property and disallows all connections if it is set to 1, effectively disabling the camera for all users of the device.

**`USES_POLICY_DISABLE_KEYGUARD_FEATURES`**

This policy allows administrators to disable keyguard customizations such as lockscreen widgets by calling the `setKeyguardDisabledFeatures()` method. The system keyguard implementation checks if this policy is in effect and disables the corresponding features for the target user.

## Adding a Device Administrator

As with other applications, device administrators can either be included in the system image or they can be installed by users. If an administrator is part of the system image, it can be set as the *device owner app* in Android 4.4 and later, which is a special kind of device admin that cannot be disabled by the user and cannot be uninstalled. In this section, we’ll show how to implement a device admin app and then demonstrate how a system app can be set as the device owner.

### Implementing a Device Administrator

A device administrator application needs to declare a broadcast receiver that requires the `BIND_DEVICE_ADMIN` permission (➊ in [Example 9-4](ch09.html#device_administrator_broadcast_receiver "Example 9-4. Device administrator broadcast receiver declaration")), declares an XML resource file that lists the policies it uses ➋, and responds to the `ACTION_DEVICE_ADMIN_ENABLED` intent ➌. [Example 9-1](ch09.html#declaring_policies_in_a_device_administr "Example 9-1. Declaring policies in a device administrator application") shows a sample policy declaration.

Example 9-4. Device administrator broadcast receiver declaration

```
<?xml version="1.0" encoding="utf-8"?>
<manifest 
    package="com.example.deviceadmin">
    --*snip*--
    <receiver android:name=".MyDeviceAdminReceiver"
        android:label="@string/device_admin"
        android:description="@string/device_admin_description"
        android:permission="android.permission.BIND_DEVICE_ADMIN">➊
        <meta-data android:name="android.app.device_admin"
                   android:resource="@xml/device_admin_policy" />➋
        <intent-filter>
           <action android:name="android.app.action.DEVICE_ADMIN_ENABLED" />➌
        </intent-filter>
    </receiver>
    --*snip*--
</manifest>
```

The Android SDK provides a base class that you can derive your receiver from, namely `android.app.admin.DeviceAdminReceiver`. This class defines a number of callback methods that you can override in order to handle the device policy-related broadcasts sent by the system. The default implementations are empty, but at a minimum you should override the `onEnabled()` and `onDisabled()` methods in order to be notified when the administrator is enabled or disabled. Device administrators cannot use any privileged APIs before `onEnabled()` is called or after `onDisabled()` is called.

You can use the `isAdminActive()` API at any time to see if an application is currently an active device administrator. As mentioned in “[Privilege Management](ch09.html#privilege_management "Privilege Management")”, an administrator cannot activate itself automatically, but must start a system activity to prompt for user confirmation with code similar to [Example 9-2](ch09.html#requesting_device_administrator_activati "Example 9-2. Requesting device administrator activation"). However, when already active, an administrator can deactivate itself by calling the `removeActiveAdmin()` method.

### Note

*See the official Device Administration API guide*^([[89](#ftn.ch09fn03)]) *for more details and a full working example application.*

### Setting the Device Owner

A device administrator application that’s part of the system image (that is, its APK file is installed on the *system* partition) can be set as the device owner by calling the `setDeviceOwner(String packageName, String ownerName)` method (not visible in the public SDK API). The first parameter in this method specifies the package name of the target application, and the second specifies the name of the owner to be displayed in the UI. While this method requires no special permissions, it can only be called before a device is provisioned (that is, if the global setting `Settings.Global.DEVICE_PROVISIONED` is set to 0), which means that it can only be called by system applications that execute as part of device initialization.

A successful call to this method writes a *device_owner.xml* file (like the one in [Example 9-5](ch09.html#contents_of_the_deviceunderscoreownerdot "Example 9-5. Contents of the device_owner.xml file")) to */data/system/*. Information about the current device owner can be obtained using the `getDeviceOwner()`, `isDeviceOwner()` (which is exposed as `isDeviceOwnerApp()` in the Android SDK API) and `getDeviceOwnerName()` methods.

Example 9-5. Contents of the device_owner.xml file

```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<device-owner package="com.example.deviceadmin" name="Device Owner" />
```

When a device owner is activated, either as part of the provisioning process or by the user, it cannot be disabled and uninstalled, as shown in [Figure 9-3](ch09.html#device_owner_administrator_cannot_be_dis "Figure 9-3. A device owner administrator cannot be disabled.").

![A device owner administrator cannot be disabled.](figs/web/09fig03.png.jpg)

Figure 9-3. A device owner administrator cannot be disabled.

### Managed Devices

A device with an owner administrator installed is called a *managed device*, and it reacts differently to configuration changes that affect device security than unmanaged devices. As discussed in [Chapter 6](ch06.html "Chapter 6. Network Security and PKI") and [Chapter 7](ch07.html "Chapter 7. Credential Storage"), Android allows users to install certificates in the system trust store either via the system Settings application, or by using third-party applications that call the `KeyChain` API. If there are user-installed certificates in the system trust store, as of version 4.4 Android shows a warning (see [Figure 6-6](ch06.html#network_monitoring_warning_in_android_4d "Figure 6-6. Network monitoring warning in Android 4.4")) notifying users that their communications can be monitored.

Enterprise networks often require trusted certificates (for example, the root certificate of a corporate PKI) to be installed in order to access enterprise services. Such certificates can be silently installed or removed by device administrators that hold the `MANAGE_CA_ CERTIFICATES` system permissions via the `installCaCert()` and `uninstallCaCert()` methods of the `DevicePolicyManager` class (these methods are reserved for system applications and aren’t visible in the public SDK API). If an additional trusted certificate is installed on a managed device, the network monitoring warning changes to a less scary information message, as shown in [Figure 9-4](ch09.html#network_monitoring_information_message_s "Figure 9-4. Network monitoring information message shown on managed devices").

## Enterprise Account Integration

As mentioned in “[Device Administration](ch09.html#device_administration "Device Administration")”, device administrator applications are often coupled with enterprise accounts, in order to allow some control over devices that access company data. In this section, we’ll discuss two such implementations: one in the stock Email application, which works with Microsoft Exchange ActiveSync accounts, and the other in the dedicated Google Apps Device Policy application, which works with corporate Google accounts.

![Network monitoring information message shown on managed devices](figs/web/09fig04.png.jpg)

Figure 9-4. Network monitoring information message shown on managed devices

### Microsoft Exchange ActiveSync

*Microsoft Exchange ActiveSync* (usually abbreviated as *EAS*) is a protocol that supports email, contacts, calendar, and task synchronization from a groupware server to a mobile device. It’s supported both by Microsoft’s own Exchange Server, and by most competing products, including Google Apps.

The Email application included in Android supports ActiveSync accounts and data synchronization via dedicated account authenticators (see [Chapter 8](ch08.html "Chapter 8. Online Account Management")) and sync adapters. In order to allow enterprise administrators to enforce a security policy on devices that access email and other corporate data, the Email application doesn’t allow synchronization until the built-in device administrator is enabled by the user. The administrator can set lockscreen password rules, erase all data, require storage encryption, and disable device cameras, as shown in [Figure 9-5](ch09.html#device_administrator_policies_required_f "Figure 9-5. Device administrator policies required for using an EAS account"). However, the policies are not built into the app but fetched from the service using the EAS Provision protocol.

![Device administrator policies required for using an EAS account](figs/web/09fig05.png.jpg)

Figure 9-5. Device administrator policies required for using an EAS account

### Google Apps

The corporate version of Google’s Gmail service, Google Apps, also supports setting mobile device security policies. If the feature is enabled by the domain administrator, Google Apps account holders can also remotely locate, ring, lock, or wipe their Android devices. Domain administrators can also selectively delete a Google Apps account and all of its associated content from a managed device, without performing a full wipe. Both security policy enforcement and remote device management are implemented in the dedicated Google Apps Device Policy application (see ➎ in [Example 9-3](ch09.html#contents_of_the_devicesunderscorepolicie "Example 9-3. Contents of the devices_policies.xml file")).

When first started, the application requests that the user enable the built-in device administrator and displays the current domain policy settings as shown in [Figure 9-6](ch09.html#policy_enforcement_confirmation_in_the_g "Figure 9-6. Policy enforcement confirmation in the Google Apps Device Policy application").

Domain administrators define policies in the Google Apps admin console (see [Figure 9-7](ch09.html#google_apps_device_policy_management_ui "Figure 9-7. Google Apps device policy management UI")), and policy settings are pushed to devices using Google’s proprietary sync protocol.

While free Google accounts do not support setting a device policy, Google experience devices can use the basic device administrator built into Google Play Services (see ➊ in [Example 9-3](ch09.html#contents_of_the_devicesunderscorepolicie "Example 9-3. Contents of the devices_policies.xml file")). This administrator allows Google account holders to remotely locate or wipe their devices using the Android Device Manager website or the associated Android application.

![Policy enforcement confirmation in the Google Apps Device Policy application](figs/web/09fig06.png.jpg)

Figure 9-6. Policy enforcement confirmation in the Google Apps Device Policy application

![Google Apps device policy management UI](figs/web/09fig07.png.jpg)

Figure 9-7. Google Apps device policy management UI

# VPN Support

A *Virtual Private Network (VPN)* allows a private network to be extended across a public network without requiring a dedicated physical connection, thus enabling all connected devices to send and receive data as if colocated and physically connected to the same private network. When a VPN is used to allow individual devices to connect to a target private network, it’s referred to as a *remote access VPN*, and when used to connect two remote networks, as a *site-to-site VPN*.

Remote-access VPNs can connect fixed devices with a static IP address, such as a computer in a remote office, but configurations where mobile clients use variable network connections and dynamic addresses are much more common. Such a configuration is often called a *road warrior* configuration and is the configuration most commonly used with Android VPN clients.

In order to ensure that data transmitted over a VPN remains private, VPNs typically authenticate remote clients and provide data confidentiality and integrity by using a secure tunneling protocol. VPN protocols are complex because they work at multiple network layers simultaneously and often involve multiple levels of encapsulation in order to be compatible with various network configurations. A thorough discussion of them is beyond the scope of his book, but in the following sections you’ll find a brief overview of the major types of VPN protocols, with a focus on the ones available on Android.

## PPTP

The *Point-to-Point Tunneling Protocol (PPTP)* uses a TCP control channel to establish connections and the Generic Routing Encapsulation (GRE) tunneling protocol to encapsulate Point-to-Point Protocol (PPP) packets. Several authentication methods such as Password Authentication Protocol (PAP), Challenge-Handshake Authentication Protocol (CHAP), and its Microsoft extension MS-CHAP v1/v2, as well as EAP-TLS, are supported, but only EAP-TLS is currently considered secure.

The PPP payload can be encrypted using the Microsoft Point-to-Point Encryption (MPPE) protocol, which uses the RC4 stream cipher. Because MPPE does not employ any form of ciphertext authentication, it is vulnerable to bit-flipping attacks. In addition, multiple problems with the RC4 cipher have been uncovered in recent years, which further reduces the security of MMPE and PPTP.

## L2TP/IPSec

The *Layer 2 Tunneling Protocol (L2TP)* is similar to PPTP and exists at the data link layer (Layer 2 in the OSI model). Because L2TP provides no encryption or confidentiality of its own (it relies on the tunneled protocol to implement these features), an L2TP VPN is typically implemented using a combination of L2TP and the Internet Protocol Security (IPSec) protocol suite, which adds authentication, confidentiality, and integrity.

In an L2TP/IPSec configuration, a secure channel is first established using IPSec, and an L2TP tunnel is then established over the secure channel. L2TP packets are always wrapped inside IPSec packets and are therefore secure. An IPSec connection requires establishing a *Security Association (SA)*, which is a combination of cryptographic algorithm and mode, encryption key, and other parameters required to establish a secure channel.

SAs are established using the Internet Security Association and Key Management Protocol (ISAKMP). ISAKMP does not define a particular key exchange method and is typically implemented either by manual configuration of pre-shared secrets, or by using the Internet Key Exchange (IKE and IKEv2) protocol. IKE uses X.509 certificates for peer authentication (much like SSL), and a Diffie-Hellman key exchange in order to establish a shared secret, which is used to derive the actual session encryption keys.

## IPSec Xauth

*IPSec Extended Authentication (Xauth)* extends IKE to include additional user authentication exchanges. This allows an existing user database or a RADIUS infrastructure to be used to authenticate remote access clients, and makes it possible to integrate two-factor authentication.

*Mode-configuration (Modecfg)* is another IPSec extension that is often used in a remote access scenario. Modecfg allows VPN servers to push network configuration information such as the private IP address and DNS server addresses to clients. When used in combination, Xauth and Modecfg make it possible to create a pure-IPSec VPN solution, which doesn’t rely on additional protocols for authentication and tunneling.

## SSL-Based VPNs

SSL-based VPNs use SSL or TLS (see [Chapter 6](ch06.html "Chapter 6. Network Security and PKI")) to establish a secure connection and tunnel network traffic. No single standard defines SSL-based VPNs, and different implementations use different strategies in order to establish a secure channel and encapsulate packets.

OpenVPN is a popular open source application that uses SSL for authentication and key exchange (preconfigured shared static keys are also supported), and a custom encryption protocol^([[90](#ftn.ch09fn04)]) to encrypt and authenticate packets. OpenVPN multiplexes the SSL session used for authentication and key exchange, and the encrypted packets stream over a single UDP (or TCP) port. The multiplexing protocol provides a reliable transport layer for SSL on top of UDP, but it tunnels encrypted IP packets over UDP without adding reliability. Reliability is provided by the tunneled protocol itself, which is usually TCP.

The main advantages of OpenVPN over IPSec are that it is much simpler and can be implemented entirely in userspace. IPSec, on the other hand, requires kernel-level support and implementation of multiple interoperating protocols. Additionally, it’s easier to get OpenVPN traffic through firewalls, NAT, and proxies because it uses the common network protocols TCP and UDP and can multiplex tunneled traffic over a single port.

The following sections examine Android’s built-in VPN support and the APIs it provides for applications that want to implement additional VPN solutions. We’ll also review the components that make up Android’s VPN infrastructure and show how it protects VPN credentials.

## Legacy VPN

Prior to Android 4.0, VPN support was entirely built into the platform and wasn’t extensible. Support for new VPN types could only be added as part of platform updates. To distinguish it from application-based implementations, built-in VPN support is referred to as *legacy VPN*.

Early Android versions supported different VPN configurations based on PPTP and L2TP/IPsec, with support for “pure-IPSec” VPNs using IPSec Xauth added in version 4.0\. In addition to new built-in VPN configurations, Android 4.0 also introduced application-based VPNs by supplying the base platform class `VpnService`, which applications could extend in order to implement a new VPN solution.

Legacy VPN is controlled via the system Settings application and is only available to the owner (also called the primary user) on multi-user devices. [Figure 9-8](ch09.html#legacy_vpn_profile_definition_dialog "Figure 9-8. Legacy VPN profile definition dialog") shows the dialog for adding a new IPSec legacy VPN profile.

### Implementation

![Legacy VPN profile definition dialog](figs/web/09fig08.png.jpg)

Figure 9-8. Legacy VPN profile definition dialog

Legacy VPNs are implemented using a combination of kernel drivers as well as native daemons, commands, and system services. The lower-level implementation of PPTP and L2TP tunneling uses an Android-specific PPP daemon called *mtpd* and the PPPoPNS and PPPoLAC (only available in Android kernels) kernel drivers.

Because legacy VPNs support only a single VPN connection per device, *mtpd* can create only a single session. IPSec VPNs leverage the built-in kernel support for IPSec and a modified *racoon* IKE key management daemon (part of the IPSec-Tools^([[91](#ftn.ch09fn05)]) utilities package that complements the Linux kernel IPSec implementation; *racoon* supports only IKEv1). [Example 9-6](ch09.html#racoon_and_mtpd_definition_in_initdotrc "Example 9-6. racoon and mtpd definition in init.rc") shows how these two daemons are defined in *init.rc*.

Example 9-6. racoon and mtpd definition in init.rc

```
service racoon /system/bin/racoon➊
    class main
    socket racoon stream 600 system system➋
    # IKE uses UDP port 500\. Racoon will setuid to vpn after binding the port.
    group vpn net_admin inet➌
    disabled
    oneshot

service mtpd /system/bin/mtpd➍
    class main
    socket mtpd stream 600 system system➎
    user vpn
    group vpn net_admin inet net_raw➏
    disabled
    oneshot
```

Both *racoon* ➊ and *mtpd* ➍ create control sockets (➋ and ➎), which are only accessible by the *system* user and are not started by default. Both daemons have *vpn*, *net_admin* (mapped by the kernel to the `CAP_NET_ADMIN` Linux capability), and *inet* added to their supplementary groups (➌ and ➏), which allow them to create sockets and control network interface devices. The *mtpd* daemon also receives the *net_raw* group (mapped to the `CAP_NET_RAW` Linux capability), which allows it to create GRE sockets (used by PPTP).

When a VPN is started via the system Settings app, Android starts the *racoon* and *mtpd* daemons and sends them control commands via their local sockets in order to establish the configured connection. The daemons create the requested VPN tunnel, and then create and configure a tunnel network interface with the received IP address and network mask. While *mtpd* performs interface configuration internally, *racoon* uses the helper command `ip-up-vpn` to bring up the tunnel interface, which is usually *tun0*.

In order to communicate connection parameters back to the framework, VPN daemons write a *state* file in */data/misc/vpn/* as shown in [Example 9-7](ch09.html#contents_of_the_vpn_state_file "Example 9-7. Contents of the VPN state file").

Example 9-7. Contents of the VPN state file

```
# **cat /data/misc/vpn/state**
tun0➊
10.8.0.1/24➋
192.168.1.0/24➌
192.168.1.1➍
example.com➎
```

The file contains the tunnel interface name ➊, its IP address and mask ➋, configured routes ➌, DNS servers ➍, and search domains ➎, with each on a new line.

After the VPN daemons start running, the framework parses the *state* file and calls the system `ConnectivityService` in order to configure routing, DNS servers, and search domains for the newly established VPN connection. In turn, `ConnectivityService` sends control commands via the local control socket of the *netd* daemon, which can modify the kernel’s packet filtering and routing tables because it runs as root. Traffic from all applications started by the owner user and restricted profiles is routed through the VPN interface by adding a firewall rule that matches the application UID and corresponding routing rules. (We discuss per-application traffic routing and multi-user support in detail in “[Multi-User Support](ch09.html#multi-user_support-id00019 "Multi-User Support")”).

### Profile and Credential Storage

Each VPN configuration created via the Settings app is called a *VPN profile* and is saved on disk in encrypted form. Encryption is performed by the Android credential storage daemon *keystore*, with a device-specific key. (See [Chapter 7](ch07.html "Chapter 7. Credential Storage") for more on credential storage implementation.)

VPN profiles are serialized by concatenating all configured properties, which are delimited by a *NUL* character (*\0*) in a single profile string that is saved to the system keystore as a binary blob. VPN profile filenames are generated by appending the current time in milliseconds (in hexadecimal format) to the *VPN_* prefix. For example, [Example 9-8](ch09.html#contents_of_the_keystore_directory_when "Example 9-8. Contents of the keystore directory when VPN profiles are configured") shows the *keystore* directory of a user with three configured VPN profiles (file timestamps omitted):

Example 9-8. Contents of the `keystore` directory when VPN profiles are configured

```
# **ls -l /data/misc/keystore/user_0**
-rw------- keystore keystore      980 1000_CACERT_cacert➊
-rw------- keystore keystore       52 1000_LOCKDOWN_VPN➋
-rw------- keystore keystore      932 1000_USRCERT_vpnclient➌
-rw------- keystore keystore     1652 1000_USRPKEY_vpnclient➍
-rw------- keystore keystore      116 1000_VPN_144965b85a6➎
-rw------- keystore keystore       84 1000_VPN_145635c88c8➏
-rw------- keystore keystore      116 1000_VPN_14569512c80➐
```

The three VPN profiles are stored in the *1000_VPN_144965b85a6* ➎, *1000_VPN_145635c88c8* ➏, and *1000_VPN_14569512c80* ➐ files. The *1000_* prefix represents the owner user, which is *system* (UID 1000). Because VPN profiles are owned by the *system* user, only system applications can retrieve and decrypt profile contents.

[Example 9-9](ch09.html#contents_of_vpn_profile_files "Example 9-9. Contents of VPN profile files") shows the decrypted contents of the three VPN profile files. (The *NUL* character has been replaced with vertical bar [`|`] for readability.)

Example 9-9. Contents of VPN profile files

```
psk-vpn|1|vpn1.example.com|test1|pass1234||||true|l2tpsecret|l2tpid|PSK|||➊
pptpvpn|0|vpn2.example.com|user1|password||||true||||||➋
certvpn|4|vpn3.example.com|user3|password||||true||||vpnclient|cacert|➌
```

The profile files contain all fields shown in the VPN profile edit dialog (see [Figure 9-8](ch09.html#legacy_vpn_profile_definition_dialog "Figure 9-8. Legacy VPN profile definition dialog")), with missing properties represented by an empty string. The first five fields represent the name of the VPN, the type of VPN, the VPN gateway host, the username, and the password, respectively. In [Example 9-9](ch09.html#contents_of_vpn_profile_files "Example 9-9. Contents of VPN profile files"), the first VPN profile ➊ is for an L2TP/IPsec VPN with pre-shared key (type 1); the second profile ➋ is for a PPTP VPN (type 0), and the last one ➌ is for a IPSec VPN that uses certificates and Xauth authentication (type 4).

In addition to the username and password, VPN profile files also contain all other credentials required to connect to the VPN. In the case of the first VPN profile ➊ in [Example 9-9](ch09.html#contents_of_vpn_profile_files "Example 9-9. Contents of VPN profile files"), the additional credential is the pre-shared key required to establish an IPSec secure connection (represented by the *PSK* string in this example). In the case of the third profile ➌, the additional credentials are the user’s private key and certificate. However, as you can see in the listing, the full key and certificate are not included; instead, the profile contains only the alias (*vpnclient*) of the key and certificate (both share a common alias). The private key and certificate are stored in the system credential store, and the alias included in the VPN profile serves only as an identifier, which is used to access or retrieve the key and certificate.

### Accessing Credentials

The *racoon* daemon, which originally used keys and certificates stored in PEM files, was modified to use Android’s *keystore* OpenSSL engine. As discussed in [Chapter 7](ch07.html "Chapter 7. Credential Storage"), the *keystore* engine is a gateway to the system credential store, which can take advantage of hardware-backed credential store implementations when available. When passed a key alias, it uses the corresponding private key to sign authentication packets, without extracting the key from the keystore.

The VPN profile ➌ in [Example 9-9](ch09.html#contents_of_vpn_profile_files "Example 9-9. Contents of VPN profile files") also contains the alias of the CA certificate (*cacert*), which is used as a trust anchor when validating the server’s certificate. At runtime, the framework retrieves the client certificate (➌ in [Example 9-8](ch09.html#contents_of_the_keystore_directory_when "Example 9-8. Contents of the keystore directory when VPN profiles are configured")) and the CA certificate (➊ in [Example 9-8](ch09.html#contents_of_the_keystore_directory_when "Example 9-8. Contents of the keystore directory when VPN profiles are configured")) from the system keystore and passes them to *racoon* via the control socket, along with other connection parameters. The private key blob (➍ in [Example 9-8](ch09.html#contents_of_the_keystore_directory_when "Example 9-8. Contents of the keystore directory when VPN profiles are configured")) is never directly passed to the *racoon* daemon, only its alias (*vpnclient*).

### Note

*While private keys are protected by hardware on devices with a hardware-backed keystore, pre-shared keys or passwords stored in a VPN profile content are not. The reason for this is that as of this writing, Android doesn’t support importing symmetric keys in the hardware-backed keystore; it only supports asymmetric keys (RSA, DSA, and EC). As a result, credentials for VPNs that use pre-shared keys are stored in the VPN profile in plaintext form and can be extracted from devices that allow root access after the profile is decrypted on memory.*

### Always-On VPN

Android 4.2 and later supports an *always-on* VPN configuration, which blocks all network connections from applications until a connection to the specified VPN profile is established. This prevents applications from sending data across insecure channels, such as public Wi-Fi networks.

Setting up an always-on VPN requires setting up a VPN profile that specifies the VPN gateway as an IP address, and specifies an explicit DNS server IP address. This explicit configuration is required in order to make sure that DNS traffic isn’t sent to the locally configured DNS server, which is blocked when an always-on VPN is in effect. The VPN profile selection dialog is shown in [Figure 9-9](ch09.html#always-on_vpn_profile_selection_dialog "Figure 9-9. Always-on VPN profile selection dialog").

The profile selection is saved with other VPN profiles in the encrypted file *LOCKDOWN_VPN* (➋ in [Example 9-8](ch09.html#contents_of_the_keystore_directory_when "Example 9-8. Contents of the keystore directory when VPN profiles are configured")) which contains only the name of the selected profile; in our example, *144965b85a6*. If the *LOCKDOWN_VPN* file is present, the system automatically connects to the specified VPN when the device boots. If the underlying network connection reconnects or changes (for example, when switching Wi-Fi hotspots), the VPN is automatically restarted.

![Always-on VPN profile selection dialog](figs/web/09fig09.png.jpg)

Figure 9-9. Always-on VPN profile selection dialog

An always-on VPN guarantees that all traffic goes through the VPN by installing firewall rules that block all packets except those which go through the VPN interface. The rules are installed by the `LockdownVpnTracker` class (always-on VPN is referred to as *lockdown VPN* in Android source code), which monitors VPN state and adjusts the current firewall state by sending commands to the *netd* daemon, which in turn executes the `iptables` utility in order to modify the kernels packet filtering tables. For example, when an always-on L2TP/IPSec VPN has connected to a VPN server with IP address 11.22.33.44 and has created a tunnel interface *tun0* with IP address 10.1.1.1, the installed firewall rules (as reported by `iptables`; some columns have been omitted for brevity) might look like [Example 9-10](ch09.html#always-on_vpn_firewall_rules "Example 9-10. Always-on VPN firewall rules").

Example 9-10. Always-on VPN firewall rules

```
# **iptables -v -L n**
--*snip*--
Chain fw_INPUT (1 references)
 target     prot opt in     out    source      destination
 RETURN     all  --  *      *      0.0.0.0/0   10.1.1.0/24➊
 RETURN     all  --  tun0   *      0.0.0.0/0   0.0.0.0/0➋
 RETURN     udp  --  *      *      11.22.33.44 0.0.0.0/0    udp spt:1701➌
 RETURN     tcp  --  *      *      11.22.33.44 0.0.0.0/0    tcp spt:1701
 RETURN     udp  --  *      *      11.22.33.44 0.0.0.0/0    udp spt:4500
 RETURN     tcp  --  *      *      11.22.33.44 0.0.0.0/0    tcp spt:4500
 RETURN     udp  --  *      *      11.22.33.44 0.0.0.0/0    udp spt:500
 RETURN     tcp  --  *      *      11.22.33.44 0.0.0.0/0    tcp spt:500
 RETURN     all  --  lo     *      0.0.0.0/0   0.0.0.0/0
 DROP       all  --  *      *      0.0.0.0/0   0.0.0.0/0➍

Chain fw_OUTPUT (1 references)
 target     prot opt in     out    source      destination
 RETURN     all  --  *      *      10.1.1.0/24 0.0.0.0/0➎
 RETURN     all  --  *      tun0   0.0.0.0/0   0.0.0.0/0➏
 RETURN     udp  --  *      *      0.0.0.0/0   11.22.33.44  udp dpt:1701➐
 RETURN     tcp  --  *      *      0.0.0.0/0   11.22.33.44  tcp dpt:1701
 RETURN     udp  --  *      *      0.0.0.0/0   11.22.33.44  udp dpt:4500
 RETURN     tcp  --  *      *      0.0.0.0/0   11.22.33.44  tcp dpt:4500
 RETURN     udp  --  *      *      0.0.0.0/0   11.22.33.44  udp dpt:500
 RETURN     tcp  --  *      *      0.0.0.0/0   11.22.33.44  tcp dpt:500
 RETURN     all  --  *      lo     0.0.0.0/0   0.0.0.0/0
 REJECT     all  --  *      *      0.0.0.0/0   0.0.0.0/0   reject-with icmp-port-unreachable➑
--*snip*--
```

As you can see in the listing, all traffic to and from the VPN network is allowed (➊ and ➎), as is all traffic on the tunnel interface (➋ and ➏). Traffic to and from the VPN server (➌ and ➐) is allowed only on the ports used by IPSec (500 and 4500) and L2TP (1701). All other incoming traffic is dropped ➍, and all other outgoing traffic is rejected ➑.

## Application-Based VPNs

Android 4.0 added a `VpnService` public API^([[92](#ftn.ch09fn06)]) that third-party applications can use to build VPN solutions that are neither built into the OS nor require system-level permissions. The `VpnService` and associated `Builder` class let applications specify network parameters such as interface IP address and routes, which the system uses to create and configure a virtual network interface. Applications receive a file descriptor associated with that network interface and can tunnel network traffic by reading from or writing to the file descriptor of the interface.

Each read retrieves an outgoing IP packet, and each write injects an incoming IP packet. Because raw access to network packets effectively lets applications intercept and modify network traffic, application-based VPNs cannot be started automatically and always require user interaction. Additionally, an ongoing notification is shown while a VPN is connected. The connection warning dialog for an application-based VPN might look like [Figure 9-10](ch09.html#application-based_vpn_connection_warning "Figure 9-10. Application-based VPN connection warning dialog").

![Application-based VPN connection warning dialog](figs/web/09fig10.png.jpg)

Figure 9-10. Application-based VPN connection warning dialog

### Declaring a VPN

An application-based VPN is implemented by creating a service component that extends the `VpnService` base class and registering it in the application manifest, as shown in [Example 9-11](ch09.html#registering_a_vpn_service_in_the_applica "Example 9-11. Registering a VPN service in the application manifest").

Example 9-11. Registering a VPN service in the application manifest

```
<?xml version="1.0" encoding="utf-8"?>
<manifest 
    package="com.example.vpn">
    --*snip*--
    <application android:label="@string/app">
         --*snip*--
         <service android:name=".MyVpnService"
                  android:permission="android.permission.BIND_VPN_SERVICE">➊
            <intent-filter>
                <action android:name="android.net.VpnService"/>➋
            </intent-filter>
        </service>
    </application>
</manifest>:
```

The service must have an intent filter that matches the *android.net.VpnService* intent action ➋ so that the system can bind to the service and control it. In addition, the service must require the `BIND_VPN_SERVICE` system signature permission ➊, which guarantees that only system applications can bind to it.

### Preparing the VPN

To register a new VPN connection with the system, the application first calls `VpnService.prepare()` in order to be granted permission to run, and then calls the `establish()` method in order to create a network tunnel (discussed in the next section). The `prepare()` method returns an intent that’s used to start the warning dialog shown in [Figure 9-10](ch09.html#application-based_vpn_connection_warning "Figure 9-10. Application-based VPN connection warning dialog"). The dialog serves to obtain the user’s permission and ensure that only one VPN connection per user is running at any time. If `prepare()` is called while a VPN connection created by another application is running, that connection is terminated. The `prepare()` method saves the package name of the calling application, and only that application is allowed to start a VPN connection until the method is called again, or the system tears down the VPN connection (for example, if the VPN app’s process crashes). When a VPN connection is deactivated for any reason, the system calls the `onRevoke()` method of the current VPN application’s `VpnService` implementation.

### Establishing a VPN Connection

After a VPN application has been prepared and granted permission to run, it can start its `VpnService` component, which would then typically create a tunnel to the VPN gateway and negotiate the network parameters for the VPN connection. Next, it sets up the `VpnService.Builder` class using those parameters and calls `VpnService.establish()` in order to receive a file descriptor to read and write packets. The `establish()` method first ensures that it’s being called by the application currently granted permission to establish a VPN connection by comparing the UID of the caller to the granted application’s UID. `establish()` then checks whether the current Android user is allowed to create VPN connections, and verifies that the service requires the `BIND_VPN_SERVICE` permission; if the service doesn’t require that permission, it’s considered insecure and a `SecurityException` is thrown. Next, the `establish()` method creates and configures a tunnel interface using native code, and sets up routing and DNS servers.

### Notifying the User About the VPN Connection

The last step in establishing a VPN connection is to show an ongoing notification that tells the user that network traffic is been tunneled through a VPN, which allows them to monitor and control the connection via the associated control dialog. The dialog for the OpenVPN for Android application is shown in [Figure 9-11](ch09.html#application-based_vpn_management_dialog "Figure 9-11. Application-based VPN management dialog").

This dialog is part of the dedicated package `com.android.vpndialogs`, which is the only package explicitly allowed to manage application-based VPN connections, other than the *system* user. This ensures that a VPN connection can only be started and managed via the system-mandated UI.

Using the application-based VPN framework, applications are free to implement network tunneling, with any required authentication and encryption methods. Because all packets the device sends or receives pass through the VPN application, it can be used not only for tunneling but also for traffic logging, filtering, or modification (such as removing advertisements).

### Note

*For a full-featured implementation of an application-based VPN that takes advantage of Android’s credential store to manage authentication keys and certificates, see the source code for OpenVPN for Android.*^([[93](#ftn.ch09fn07)]) *This application implements an SSL VPN client that is fully compatible with the OpenVPN server.*

## Multi-User Support

As mentioned earlier, on multi-user devices, legacy VPNs can be controlled only by the owner user. However, with its introduction of multi-user support, Android 4.2 and higher allows all secondary users (with the exception of restricted profiles, which must share the primary user’s VPN connection) to start application-based VPNs. While this change technically allowed each user to start their own VPN, because only one application-based VPN could be activated at a time, traffic for all device users was routed through the currently active VPN regardless of who started it. Android 4.4 finally brought full multi-user VPN support by introducing *per-user VPN*, which allows traffic from any user to be routed through their VPN, thus isolating it from other users’ traffic.

### Linux Advanced Routing

![Application-based VPN management dialog](figs/web/09fig11.png.jpg)

Figure 9-11. Application-based VPN management dialog

Android uses several advanced packet filtering and routing features of the Linux kernel in order to implement per-user VPNs. These features (implemented by the *netfilter* kernel framework) include the *owner* module of the Linux *iptables* tool, which allows matching of locally generated packets based on the UID, GID, or PID of the process that created them. For example, the command shown at ➊ in [Example 9-12](ch09.html#using_owner_matching_and_packet_marking "Example 9-12. Using owner matching and packet marking with iptables") creates a packet-filtering rule that drops all outgoing packets generated by the user with UID 1234.

Example 9-12. Using owner matching and packet marking with iptables

```
# iptables -A OUTPUT -m owner --uid-owner 1234 -j DROP➊
# iptables -A PREROUTING -t mangle -p tcp --dport 80 -j MARK --set-mark 0x1➋
# ip rule add fwmark 0x1 table web➌
# ip route add default via 1.2.3.4 dev em3 table web➍
```

Another important netfilter feature is the ability to mark packets that match a certain selector with a specified number (called a *mark*). For example, the rule at ➋ marks all packets destined for port 80 (which is typically used by a web server) with the mark 0x1\. This mark can then be matched in later filtering or routing rules in order to, for example, send marked packets through a particular interface by adding a routing rule that sends marked packets to a predefined routing table, which is *web* in our example ➌. Finally, a route that sends packets matching the *web* table to the *em3* interface can be added with the command shown at ➍.

### Multi-User VPN Implementation

Android uses these packet filtering and routing features to mark packets originating from all apps of a particular Android user and send them through the tunneling interface created by the VPN app started by that user. When the owner user starts a VPN, that VPN is shared with any restricted profiles on the device that cannot start their own VPNs by matching all packets originating from restricted profiles and routing them through the owner’s VPN tunnel.

This split-routing is implemented at the framework level by the `NetworkManagementService`, which provides APIs to manage package matching and routing by UID or UID range. `NetworkManagementService` implements those APIs by sending commands to the native *netd* daemon which runs as root, and thus can modify the kernel’s packet filtering and routing tables. *netd* manipulates the kernel’s filtering and routing configuration by calling the *iptables* and *ip* userland utilities.

Let’s illustrate Android’s per-user VPN routing with an example as shown in [Example 9-13](ch09.html#packet_matching_rules_for_vpns_started_b "Example 9-13. Packet matching rules for VPNs started by two different device users"). The primary user (user ID 0) and the first secondary user (user ID 10) have each started an application-based VPN. The owner user’s VPN is assigned the *tun0* tunneling interface, and the secondary user’s VPN is assigned the *tun1* interface. The device also has a restricted profile with user ID 13\. [Example 9-13](ch09.html#packet_matching_rules_for_vpns_started_b "Example 9-13. Packet matching rules for VPNs started by two different device users") shows the state of the kernel’s packet filtering tables when both VPNs are connected (with some details omitted).

Example 9-13. Packet matching rules for VPNs started by two different device users

```
**# iptables -t mangle -L –n**
--*snip*--
Chain st_mangle_OUTPUT (1 references)
target     prot opt source               destination
RETURN     all  --  0.0.0.0/0            0.0.0.0/0           mark match 0x1➊
RETURN     all  --  0.0.0.0/0            0.0.0.0/0           owner UID match 1016➋
--*snip*--
st_mangle_tun0_OUTPUT  all  --  0.0.0.0/0           0.0.0.0/0           [goto] owner UID match
0-99999➌
st_mangle_tun0_OUTPUT  all  --  0.0.0.0/0           0.0.0.0/0           [goto] owner UID match
1300000-1399999➍
st_mangle_tun1_OUTPUT  all  --  0.0.0.0/0           0.0.0.0/0           [goto] owner UID match
1000000-1099999➎

Chain st_mangle_tun0_OUTPUT (3 references)
target     prot opt source               destination
MARK       all  --  0.0.0.0/0            0.0.0.0/0           MARK and 0x0
MARK       all  --  0.0.0.0/0            0.0.0.0/0           MARK set 0x3c➏

Chain st_mangle_tun1_OUTPUT (2 references)
target     prot opt source               destination
MARK       all  --  0.0.0.0/0            0.0.0.0/0           MARK and 0x0
MARK       all  --  0.0.0.0/0            0.0.0.0/0           MARK set 0x3d➐
```

Outgoing packets are first sent to the *st_mangle_OUTPUT* chain, which is responsible for matching and marking packets. Packets exempt from peruser routing (those already marked with 0x1 ➊), and packets originating from legacy VPNs (UID 1016 ➋, assigned to the built-in *vpn* user, which both *mtd* and *racoon* run as) pass without modification.

Next, packets created by processes running with UIDs between 0 and 99999 (the range of UIDs assigned to apps started by the primary user, as discussed in [Chapter 4](ch04.html "Chapter 4. User Management")) are matched and sent to the *st_mangle_tun0_ OUTPUT* chain ➌. Packets originating from UIDs 1300000–1399999, the range assigned to our restricted profile (user ID 13), are sent to the same chain ➍. Thus, traffic originating from the owner user and the restricted profile is treated the same way. Packets originating from the first secondary user (user ID 10, UID range 1000000-1099999) are, however, sent to a different chain, *st_mangle_tun1_OUTPUT* ➎. The target chains themselves are simple: *st_mangle_tun0_OUTPUT* first clears the packet mark and then marks them with *0x3c* ➏; *st_mangle_tun1_OUTPUT* does the same but uses the mark *0x3d* ➐. After packets have been marked, the marks are used to implement and match different routing rules, as shown in [Example 9-14](ch09.html#routing_rules_for_vpns_started_by_two_di "Example 9-14. Routing rules for VPNs started by two different device users").

Example 9-14. Routing rules for VPNs started by two different device users

```
# **ip rule ls**
0:      from all lookup local
100:    from all fwmark 0x3c lookup 60➊
100:    from all fwmark 0x3d lookup 61➋
--*snip*--
# **ip route list table 60**
default dev tun0 scope link➌
# **ip route list table 61**
default dev tun1 scope link➍
```

Notice that two rules that match each mark have been created, and that they’re associated with different routing tables. Packets marked with *0x3c* go to routing table 60 (0x3c in hexadecimal ➊), while those marked with *0x3d* go to table 61 (0x3d in hexadecimal ➋). Table 60 routes everything through the *tun0* tunneling interface ➌, which was created by the owner user, and table 61 routes everything through the *tun1* interface ➍, created by the secondary user.

### Note

*While the VPN traffic routing method introduced in Android 4.4 offers greater flexibility and allows user VPN traffic to be isolated, as of this writing the implementation appears to have some problems, especially related to switching between different physical networks (for example, mobile to Wi-Fi or vice versa). Those problems should be addressed in future versions, possibly by modifying how packet filtering chains are associated with interfaces, but the basic implementation strategy is likely to remain the same.*

# Wi-Fi EAP

Android supports different wireless network protocols, including Wi-Fi Protected Access (WPA) and Wi-Fi Protected Access II (WPA2), which are currently deployed on most wireless devices. Both protocols support a simple *pre-shared key (PSK)* mode, also referred to as *Personal mode*, in which all devices that access the network must be configured with the same 256-bit authentication key.

Devices can be configured either with the raw key bytes or with an ASCII passphrase that’s used to derive the authentication key using the PBKDF2 key derivation algorithm. While the PSK mode is simple, it doesn’t scale as the number of network users increases. If access for a certain user needs to be revoked, for example, the only way to cancel their network credentials is to change the shared passphrase, which would force all other users to reconfigure their devices. Additionally, as there is no practical way to distinguish users and devices, it is difficult to implement flexible access rules or accounting.

To address this problem, both WPA and WPA2 support the IEEE 802.1X network access control standard, which offers an encapsulation of the Extensible Authentication Protocol (EAP). Authentication in a wireless network that uses 802.1X and involves a supplicant, an authenticator, and an authentication server is shown in [Figure 9-12](ch09.html#eight02dot1x_authentication_participants "Figure 9-12. 802.1X authentication participants").

![802.1X authentication participants](figs/web/09fig12.png.jpg)

Figure 9-12. 802.1X authentication participants

The *supplicant* is a wireless device such as an Android phone that wants to connect to the network, and the *authenticator* is the gateway to the network that validates the supplicant’s identity and provides authorization. In a typical Wi-Fi configuration, the authenticator is the wireless access point (AP). The *authentication server*, typically a RADIUS server, verifies client credentials and decides whether they should be granted access based on a preconfigured access policy.

Authentication is implemented by exchanging EAP messages between the three nodes. These are encapsulated in a format suitable for the medium connecting each two nodes: EAP over LAN (EAPOL) between the supplicant and the authenticator, and RADIUS between the authenticator and the authentication server.

Because EAP is an authentication framework that supports different concrete authentication types and not a concrete authentication mechanism, the supplicant and authentication server (with the help of the authenticator) need to negotiate a commonly supported authentication method before authentication can be performed. There are various standard and proprietary EAP authentication methods, and current Android versions support most of the methods used in wireless networks.

The sections below offer a brief overview of the EAP authentication methods that Android supports, and show how it protects credentials for each method. We’ll also demonstrate how to configure access to a Wi-Fi network that uses EAP for authentication using Android’s wireless network management APIs.

## EAP Authentication Methods

As of version 4.4, Android supports the PEAP, EAP-TLS, EAP-TTLS, and EAP-PWD authentication methods. Before exploring how Android stores credentials for each authentication method, let’s briefly discuss how each one works.

**PEAP**

The Protected Extensible Authentication Protocol (PEAP) transmits EAP messages through an SSL connection in order to provide confidentiality and integrity. It uses PKI and a server certificate to authenticate the server and establish an SSL connection (Phase 1), but does not mandate how clients are authenticated. Clients are authenticated using a second, inner (Phase 2) authentication method, which is transmitted inside the SSL tunnel. Android supports the MSCHAPv2 (specified in PEAPv0^([[94](#ftn.ch09fn08)])) and Generic Token Card (GTC, specified in PEAPv2^([[95](#ftn.ch09fn09)])) methods for Phase 2 authentication.

**EAP-TLS**

The EAP-Transport Layer Security (EAP-TLS) method^([[96](#ftn.ch09fn10)]) uses TLS for mutual authentication and was formerly the only EAP method certified for use with WPA Enterprise. EAP-TLS uses both a server certificate to authenticate the server to supplicants, and a client certificate that the authentication server verifies in order to establish supplicant identity. Granting network access requires issuing and distributing X.509 client certificates, and thus maintaining a public key infrastructure. Existing clients can be blocked from accessing the network by revoking their supplicant certificates. Android supports EAP-TLS and manages client keys and certificates using the system credential store.

**EAP-TTLS**

Like EAP-TLS, the EAP-Tunneled Transport Layer Security (EAP-TTLS) protocol^([[97](#ftn.ch09fn11)]) is based on TLS. However, EAP-TTLS does not require client authentication using X.509 certificates. Clients can be authenticated either using a certificate during the handshake phase (Phase 1), or with another protocol during the tunnel phase (Phase 2). Android does not support authentication during Phase 1, but supports the PAP, MSCHAP, MSCHAPv2, and GTC protocols for Phase 2.

**EAP-PWD**

The EAP-PWD authentication method^([[98](#ftn.ch09fn12)]) uses a shared password for authentication. Unlike legacy schemes that rely on a simple challenge-response mechanism, EAP-PWD is designed to be resistant to passive attacks, active attacks, and dictionary attacks. The protocol also provides forward secrecy and guarantees that even if a password is compromised, earlier sessions cannot be decrypted. EAP-PWD is based on discrete logarithm cryptography and can be implemented using either finite fields or elliptic curves.

## Android Wi-Fi Architecture

Like most hardware support in Android, Android’s Wi-Fi architecture consists of a kernel layer (WLAN adapter driver modules), native daemon (*wpa_supplicant*), a Hardware Abstraction Layer (HAL), system services, and a system UI. Wi-Fi adapter kernel drivers are usually specific to the system on a chip (SoC) that an Android device is built upon, and are typically closed source and loaded as kernel modules. The *wpa_supplicant*^([[99](#ftn.ch09fn13)]) is a WPA supplicant daemon that implements key negotiation with a WPA authenticator and controls 802.1X association of the WLAN driver. However, Android devices rarely include the original *wpa_supplicant* code; the included implementation is often modified for better compatibility with the underlying SoC.

The HAL is implemented in the *libharware_legacy* native library and is responsible for relaying commands from the framework to *wpa_supplicant* via its control socket. The system service that controls Wi-Fi connectivity is `WifiService`, which offers a public interface via the `WifiManager` facade class. The `WifiService` delegates Wi-Fi state management to a rather complex `WifiStateMachine` class, which can go through more than a dozen states while connecting to a wireless network.

WLAN connectivity is controlled via the Wi-Fi screen of the system Settings app, and connectivity status is displayed in the status bar and Quick Settings, both of which are part of the SystemUI package.

Android stores Wi-Fi-related configuration files in the */data/misc/wifi/* directory because wireless connectivity daemons persist configuration changes directly to disk and thus need a writable directory. The directory is owned by the *wifi* user (UID 1010), which is also the user that the *wpa_supplicant* runs as. Configurations files, including *wpa_supplicant.conf*, have permissions set to 0660 and are owned by the *system* user, and their group is set to *wifi*. This ensures that both system applications and the supplicant daemon can read and modify configurations files, but they are not accessible to other applications. The *wpa_supplicant.conf* file contains configuration parameters formatted as key-value pairs, both global and specific to a particular network. Network-specific parameters are enclosed in network blocks, which may look like [Example 9-15](ch09.html#psk_network_configuration_block_in_wpaun "Example 9-15. PSK network configuration block in wpa_supplicant.conf") for a PSK configuration.

Example 9-15. PSK network configuration block in wpa_supplicant.conf

```
network={
    ssid="psk-ap"➊
    key_mgmt=WPA-PSK➋
    psk="password"➌
    priority=805➍
}
```

As you can see, the `network` block specifies the network SSID ➊, authentication key management protocol ➋, the pre-shared key itself ➌, and a priority value ➍. The PSK is saved in plaintext, and while the *wpa_supplicant.conf* access bits disallow non-system applications from accessing it, it can be easily extracted from devices that allow root access.

## EAP Credentials Management

In this section, we’ll examine how Android manages Wi-Fi credentials for each of the supported EAP authentication methods and discuss the Android-specific *wpa_supplicant* changes that allow the supplicant daemon to take advantage of Android’s system credential store.

[Example 9-16](ch09.html#peap_network_configuration_block_in_wpau "Example 9-16. PEAP network configuration block in wpa_supplicant.conf") shows the network block in *wpa_supplicant.conf* for a network configured to use PEAP.

Example 9-16. PEAP network configuration block in wpa_supplicant.conf

```
network={
    ssid="eap-ap"
    key_mgmt=WPA-EAP IEEE8021X➊
    eap=PEAP➋
    identity="android1"➌
    anonymous_identity="anon"
    password="password"➍
    ca_cert="keystore://CACERT_eapclient"➎
    phase2="auth=MSCHAPV2"➏
    proactive_key_caching=1
}
```

Here, the key management mode is set to *WPA-EAP IEEE8021X* ➊, the EAP method to *PEAP* ➋, and Phase 2 authentication to MSCHAPv2 ➏. Credentials, namely the identity ➌ and password ➍, are stored in plaintext in the configuration file, as they are in PSK mode.

One notable difference from a general-purpose *wpa_supplicant.conf* is the format of the CA certificate path ➎. The CA certificate path (*ca_cert*) is used when validating the server certificate, and in Android *ca_cert* is in a URI-like format with the *keystore* scheme. This Android-specific extension allows the *wpa_supplicant* daemon to retrieve certificates from the system credential store. When the daemon encounters a certificate path that starts with *keystore://*, it connects to the `IKeystoreService` remote interface of the native *keystore* service and retrieves the certificate bytes using the URI path as the key.

EAP-TLS configuration is similar to the PEAP one, as shown in [Example 9-17](ch09.html#eap-tls_network_configuration_block_in_w "Example 9-17. EAP-TLS network configuration block in wpa_supplicant.conf").

Example 9-17. EAP-TLS network configuration block in wpa_supplicant.conf

```
network={
    ssid="eap-ap"
    key_mgmt=WPA-EAP IEEE8021X
    eap=TLS
    identity="android1"
    ca_cert="keystore://CACERT_eapclient"
    client_cert="keystore://USRCERT_eapclient"➊
    engine_id="keystore"➋
    key_id="USRPKEY_eapclient"➌
    engine=1
    priority=803
    proactive_key_caching=1
}
```

New here is the addition of a client certificate URI ➊, an engine ID ➋, and a key ID ➌. The client certificate is retrieved from the system credential store, just like the CA certificate. The engine ID refers to the OpenSSL engine that should be used for cryptographic operations when connecting to the SSID configured in the `network` block. The *wpa_supplicant* has native support for configurable OpenSSL engines, and is often used with an PKCS#11 engine in order to use keys stored in a smart card or other hardware device.

As discussed in [Chapter 7](ch07.html "Chapter 7. Credential Storage"), Android’s *keystore* engine uses keys stored in the system credential store. If a device supports hardware-backed credential storage, the *keystore* engine can transparently take advantage of it by virtue of the intermediate *keymaster* HAL module. The key ID in [Example 9-17](ch09.html#eap-tls_network_configuration_block_in_w "Example 9-17. EAP-TLS network configuration block in wpa_supplicant.conf") references the alias of the private key to use for authentication.

As of version 4.3, Android allows you to select the owner of private keys and certificates when importing them. Previously, all imported keys were owned by the *system* user, but if you set the Credential use parameter to Wi-Fi in the import dialog (see [Figure 9-13](ch09.html#setting_the_credential_owner_to_wi-fi_in "Figure 9-13. Setting the credential owner to Wi-Fi in the PKCS#12 import dialog")), the key owner is set to the *wifi* user (UID 1010), and the key can only be accessed by system components that run as the *wifi* user, like *wpa_supplicant*.

![Setting the credential owner to Wi-Fi in the PKCS#12 import dialog](figs/web/09fig13.png.jpg)

Figure 9-13. Setting the credential owner to Wi-Fi in the PKCS#12 import dialog

Because Android does not support client authentication when using the EAP-TTLS authentication method, the configuration only contains a CA certificate reference ➋, as shown in [Example 9-18](ch09.html#eap-ttls_network_configuration_block_in "Example 9-18. EAP-TTLS network configuration block in wpa_supplicant.conf"). The password ➊ is stored in plaintext.

Example 9-18. EAP-TTLS network configuration block in wpa_supplicant.conf

```
network={
    ssid="eap-ap"
    key_mgmt=WPA-EAP IEEE8021X
    eap=TTLS
    identity="android1"
    anonymous_identity="anon"
    password="pasword"➊
    ca_cert="keystore://CACERT_eapclient"➋
    phase2="auth=GTC"
    proactive_key_caching=1
}
```

The EAP-PWD method does not depend on TLS to establish a secure channel and thus requires no certificate configuration, as shown in [Example 9-19](ch09.html#eap-pwd_network_configuration_block_in_w "Example 9-19. EAP-PWD network configuration block in wpa_supplicant.conf"). Credentials are stored in plaintext (➊ and ➋), as with other configurations that use passwords.

Example 9-19. EAP-PWD network configuration block in wpa_supplicant.conf

```
network={
    ssid="eap-ap"
    key_mgmt=WPA-EAP IEEE8021X
    eap=PWD
    identity="android1"➊
    password="password"➋
    proactive_key_caching=1
}
```

To sum up, configurations for all EAP methods that use a password for authentication store credential information in plaintext in the *wpa_supplicant.conf* file. When using EAP-TLS, which relies on client authentication, the client key is stored in the system keystore, and thus offers the highest level of credential protection.

## Adding an EAP Network with WifiManager

While Android supports a number of WPA Enterprise authentication methods, setting them up properly might challenge some users because of the number of parameters that need to be configured and the need to install and select authentication certificates. Because Android’s official API for managing Wi-Fi networks, called `WifiManager`, did not support EAP configurations prior to Android 4.3, the only way to set up an EAP network was to add it via the system Settings app and configure it manually. Android 4.3 (API level 18) extended the `WifiManager` API to allow for programmatic EAP configuration, thus enabling automatic network provisioning in enterprise environments. In this section, we’ll show how to use `WifiManager` to add an EAP-TLS network and discuss the underlying implementation.

`WifiManager` allows an app that holds the `CHANGE_WIFI_STATE` permission (protection level *dangerous*) to add a Wi-Fi network by initializing a `WifiConfiguration` instance with the network’s SSID, authentication algorithms, and credentials, and pass it to the `addNetwork()` method of `WifiManager`. Android 4.3 extends this API by adding an `enterpriseConfig` field of type `WifiEnterpriseConfig` to the `WifiConfiguration` class, which allows you to configure the EAP authentication method to use, client and CA certificates, the Phase 2 authentication method (if any), and additional credentials such as username and password. [Example 9-20](ch09.html#adding_an_eap-tls_network_using_wifimana "Example 9-20. Adding an EAP-TLS network using WifiManager") shows how to use this API to add a network that uses EAP-TLS for authentication.

Example 9-20. Adding an EAP-TLS network using `WifiManager`

```
X509Certificate caCert = getCaCert();
PrivateKey clientKey = getClientKey();
X509Certificate clientCert = getClientCert();

WifiEnterpriseConfig enterpriseConfig = new WifiEnterpriseConfig();
enterpriseConfig.setCaCertificate(caCert);➊
enterpriseConfig.setClientKeyEntry(clientKey, clientCert);➋
enterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.TLS);➌
enterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.NONE);➍
enterpriseConfig.setIdentity("android1");➎
WifiConfiguration config = new WifiConfiguration();
config.enterpriseConfig = enterpriseConfig;➏
config.SSID = "\"eap-ap\"";
config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);➐
config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);➑

int netId = wm.addNetwork(config);➒
if (netId != -1) {
    boolean success = wm.saveConfiguration();➓
}
```

In order to set up EAP-TLS authentication, we first need to obtain the CA certificate used to verify the server’s identity, and the client’s private key and certificate. Because these are typically distributed as a PKCS#12 file, we can use a `KeyStore` of type *PKCS12* to extract them (not shown). (Android will automatically import the specified keys and certificates into the system keystore when you add an EAP profile that uses them, so you don’t need to import the PKCS#12 file.) After we have the CA certificate and client credentials, we set them to our `WifiEnterpriseConfig` instance using the `setCaCertificate()` ➊ and `setClientKeyEntry()` ➋ methods. We then set the EAP method to `Eap.TLS` ➌ and the Phase 2 method to `NONE` ➍, as EAP-TLS authenticates users as part of establishing an SSL connection (Phase 1). Android also requires us to set the identity ➎ even though it might not be used by the authentication server. After we’ve configured the `WifiEnterpriseConfig` object, we can add it to the main `WifiConfiguration` instance ➏. The set of key management protocols also needs to be configured (➐ and ➑) because it defaults to WPA PSK. Finally, we can add the network ➒ and save the configuration ➓, which updates the *wpa_supplicant.conf* file to include the newly configured network.

Android automatically generates aliases for the configured private key and certificates, and then imports the PKI credentials into the system keystore. The aliases are based on the AP name, key management scheme, and EAP authentication method. A programmatically configured network is automatically shown in the Wi-Fi screen of the system Settings application, and might look like [Figure 9-14](ch09.html#eap-tls_network_added_using_wifimanager "Figure 9-14. An EAP-TLS network added using WifiManager") for the example shown in [Example 9-20](ch09.html#adding_an_eap-tls_network_using_wifimana "Example 9-20. Adding an EAP-TLS network using WifiManager").

![An EAP-TLS network added using WifiManager](figs/web/09fig14.png.jpg)

Figure 9-14. An EAP-TLS network added using `WifiManager`

# Summary

Android supports a Device Administration API that allows device administration apps to configure a security policy, which can include requirements for lockscreen password complexity, device encryption, and camera usage. Device administrators are often used with corporate accounts, such as those for Microsoft Exchange and Google Apps, in order to limit access to corporate data based on the policy and device settings. The Device Administration API also provides features that enable remote device locking and data wipe.

Android devices can connect to various types of VPNs, including PPTP, L2TP/IPSec, and SSL-based VPNs. Support for PPTP and L2TP/IPSec is built into the platform and can only be extended through OS updates. Android 4.0 adds support for application-based VPNs, which allows third-party applications to implement custom VPN solutions.

In addition to the widely used pre-shared key Wi-Fi authentication mode, Android supports various WPA Enterprise configurations, namely PEAP, EAP-TLS, EAP-TTLS, and EAP-PWD. Certificates and private keys for EAP authentication methods that use SSL to establish a secure channel or authenticate users are stored in the system keystore and can use hardware protection when available. Wi-Fi networks that use EAP for authentication can be automatically provisioned using the `WifiManager` API in recent Android versions, beginning with Android 4.3.

* * *

^([[87](#ch09fn01)]) Google, *Android APIs Reference*, “DeviceAdminInfo,” *[https://developer.android.com/reference/android/app/admin/DeviceAdminInfo.html](https://developer.android.com/reference/android/app/admin/DeviceAdminInfo.html)*

^([[88](#ch09fn02)]) Google, *Android APIs Reference*, “DevicePolicyManager,” *[https://developer.android.com/reference/android/app/admin/DevicePolicyManager.html](https://developer.android.com/reference/android/app/admin/DevicePolicyManager.html)*

^([[89](#ch09fn03)]) Google, *API Guides*, “Device Administration,” *[https://developer.android.com/guide/topics/admin/device-admin.html](https://developer.android.com/guide/topics/admin/device-admin.html)*

^([[90](#ch09fn04)]) OpenVPN Technologies, Inc, “OpenVPN Security Overview,” *[http://openvpn.net/index.php/open-source/documentation/security-overview.html](http://openvpn.net/index.php/open-source/documentation/security-overview.html)*

^([[91](#ch09fn05)]) IPSec-Tools, *[http://ipsec-tools.sourceforge.net/](http://ipsec-tools.sourceforge.net/)*

^([[92](#ch09fn06)]) Google, *Android APIs Reference*, “VpnService,” *[https://developer.android.com/reference/android/net/VpnService.html](https://developer.android.com/reference/android/net/VpnService.html)*

^([[93](#ch09fn07)]) Arne Schwabe, “Openvpn for Android 4.0+,” *[https://code.google.com/p/ics-openvpn/](https://code.google.com/p/ics-openvpn/)*

^([[94](#ch09fn08)]) Vivek Kamath, Ashwin Palekar, and Mark Woodrich, *Microsoft’s PEAP version 0 (Implementation in Windows XP SP1)*, *[https://tools.ietf.org/html/draft-kamath-pppext-peapv0-00/](https://tools.ietf.org/html/draft-kamath-pppext-peapv0-00/)*

^([[95](#ch09fn09)]) Ashwin Palekar et al., *Protected EAP Protocol (PEAP) Version 2*, *[https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-10/](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-10/)*

^([[96](#ch09fn10)]) D. Simon, B. Aboba, and R. Hurst, *The EAP-TLS Authentication Protocol, [http://tools.ietf.org/html/rfc5216/](http://tools.ietf.org/html/rfc5216/)*

^([[97](#ch09fn11)]) P. Funk and S. Blake-Wilson, *Extensible Authentication Protocol Tunneled Transport Layer Security Authenticated Protocol Version 0 (EAP-TTLSv0)*, *[https://tools.ietf.org/html/rfc5281/](https://tools.ietf.org/html/rfc5281/)*

^([[98](#ch09fn12)]) D. Harkins and G. Zorn, *Extensible Authentication Protocol (EAP) Authentication Using Only a Password*, *[https://tools.ietf.org/html/rfc5931/](https://tools.ietf.org/html/rfc5931/)*

^([[99](#ch09fn13)]) Jouni Malinen, *Linux WPA/WPA2/IEEE 802.1X Supplicant*, *[http://hostap.epitest.fi/wpa_supplicant/](http://hostap.epitest.fi/wpa_supplicant/)*
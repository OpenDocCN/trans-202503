# Chapter 12. Selinux

While previous chapters mentioned Security-Enhanced Linux (SELinux) and its Android integration, our discussion of Android’s security model up until now has focused on Android’s “traditional” sandbox implementation, which relies heavily on Linux’s default discretionary access control (DAC). The Linux DAC is lightweight and well understood, but it has certain disadvantages, most notably the coarse granularity of DAC permissions, the potential for misconfigured programs to leak data, and the inability to apply fine-grained privilege constraints to processes that run as the root user. (While POSIX capabilities, which are implemented as an extension to the traditional DAC in Linux, offer a way to grant only certain privileges to root processes, the granularity of POSIX capabilities is fairly coarse and the granted privileges extend to all objects accessed by the process.)

*Mandatory access control (MAC)*, as implemented by SELinux, seeks to overcome these limitations of Linux’s DAC by enforcing a systemwide, more finely grained security policy that can be changed only by the system administrator, and not by unprivileged users and programs. This chapter first gives a brief overview of the architecture and concepts used in SELinux and then describes the major modifications made to SELinux in order to support Android. Finally, we give an overview of the SELinux policy that’s deployed in the current version of Android.

# SELinux Introduction

SELinux is a mandatory access control mechanism for the Linux kernel, implemented as a Linux security module. The Linux Security Modules (LSM) framework allows third-party access control mechanisms to be linked into the kernel and to modify the default DAC implementation. LSM is implemented as a series of security function hooks (upcalls) and related data structures that are integrated into the various modules of the Linux kernel responsible for access control.

Some of the main kernel services that have LSM hooks inserted are program execution, file and inode operations, netlink messaging, and socket operations. If no security module is installed, Linux uses its built-in DAC mechanism to regulate access to kernel objects managed by these services. If a security module is installed, Linux consults it in addition to the DAC in order to reach a final security decision when access to a kernel object is requested.

Besides providing hooks into major kernel services, the LSM framework also extends the procfs virtual filesystem (*/proc*) to include per-process and per-task (thread) security attributes, and adds support for using filesystem extended attributes as persistent security attribute storage. SELinux was the first LSM module integrated into the Linux kernel and has been officially available since version 2.6 (previous SELinux implementations were distributed as a set of patches). Since the integration of SELinux, other security modules have also been accepted into the mainline kernel, which as of this writing includes AppArmor, Smack, and TOMOYO Linux as well. These modules provide alternative MAC implementations and are based on different security models than those of SELinux.

We’ll explore the SELinux security model and architecture in the next sections.

## SELinux Architecture

While the SELinux architecture is quite complex, at a high level it consists of four main components: object managers (OM), an access vector cache (AVC), a security server, and a security policy, as shown in [Figure 12-1](ch12.html#selinux_components "Figure 12-1. SELinux components").

When a subject asks to perform an action on an SELinux object (for example, when a process tries to read a file), the associated object manager queries the AVC to see if the attempted action is allowed. If the AVC contains a cached security decision for the request, the AVC returns it to the OM, which enforces the decision by allowing or denying the action (steps 1, 2, and 5 in [Figure 12-1](ch12.html#selinux_components "Figure 12-1. SELinux components")). If the cache does not contain a matching security decision, the AVC contacts the security server, which makes a security decision based on the currently loaded policy and returns it to the AVC, which caches it. The AVC in turn returns it to the OM, which ultimately enforces the decision (steps 1, 2, 3, 4, and 5 in [Figure 12-1](ch12.html#selinux_components "Figure 12-1. SELinux components")). The security server is part of the kernel, while the policy is loaded from userspace via a series of functions contained in the supporting userspace library.

![SELinux components](figs/web/12fig01.png.jpg)

Figure 12-1. SELinux components

The OM and AVC can reside either in kernel space (when the OM is managing kernel-level objects) or userspace (when the OM is part of a so-called SELinux-aware application, which has built-in MAC support).

## Mandatory Access Control

SELinux’s MAC model is based on three main concepts: subjects, objects, and actions. In this model, subjects are the active actors that perform actions on objects, and the action is carried out only if the security policy allows it.

In practice, subjects are usually running processes (a process can also be an object), and objects are OS-level resources managed by the kernel, such as files and sockets. Both subjects and objects have a set of security attributes (collectively known as the *security context*, discussed in the next section), which the OS queries in order to decide whether the requested action should be allowed or not. When SELinux is enabled, subjects cannot bypass or influence policy rules; therefore, the policy is mandatory.

### Note

*The MAC policy is only consulted if the DAC allows access to a resource. If the DAC denies access (for example, based on file permissions), the denial is taken as the final security decision.*

SELinux supports two forms of MAC: *type enforcement (TE)* and *multilevel security (MLS)*. MLS is typically used to enforce different levels of access to restricted information and is not used in Android. The type enforcement implemented in SELinux requires that all subjects and objects have an associated type and SELinux uses this type to enforce the rules of its security policy.

In SELinux, a *type* is simply a string that’s defined in the policy and associated with objects or subjects. Subject types reference processes or groups of processes and are also referred to as *domains*. Types referring to objects usually specify the role an object plays within the policy, such as system file, application data file, and so on. The type (or domain) is an integral part of the security context, as discussed in “[Security Contexts](ch12.html#security_contexts "Security Contexts")” below.

## SELinux Modes

SELinux has three modes of operation: disabled, permissive, and enforcing. When SELinux is disabled, no policy is loaded and only the default DAC security is enforced. In permissive mode, the policy is loaded and object access is checked, but access denial is only logged—not enforced. Finally, in enforcing mode, the security policy is both loaded and enforced, with violations logged.

In Android, the SELinux mode can be checked and changed with the `getenforce` and `setenforce` commands, as shown in [Example 12-1](ch12.html#using_the_getenforceandsetenforcecommand "Example 12-1. Using the getenforce and setenforce commands"). However, the mode set with `setenforce` is not persistent and will be reset to the default mode when the device reboots.

Example 12-1. Using the *getenforce and setenforce commands*

```
# **getenforce**
Enforcing
# **setenforce 0**
# **getenforce**
Permissive
```

Additionally, even when SELinux is in enforcing mode, the policy can specify permissive mode per domain (process) using the `permissive` statement. (See “[Object Class and Permission Statements](ch12.html#object_class_and_permission_statements "Object Class and Permission Statements")” for an example.)

## Security Contexts

In SELinux, a *security context* (also referred to as a *security label*, or just *label*) is a string with four fields delimited with colons: username, role, type, and an optional MLS security range. An SELinux username is typically associated with a group or class of users; for example, *user_u* for unprivileged users and *admin_u* for administrators.

Users can be associated with one or more roles in order to implement role-based access control, where each role is associated with one or more domain types. The type is used to group processes in a domain or to specify an object logical type.

The security range (or level) is used to implement MLS and specifies the security levels a subject is allowed to access. As of this writing, Android only uses the type field of the security context, and the user and security range are always set to *u* and *s0*. The role is set to either *r* for domains (processes) or to the built-in *object_r* role for objects.

The security context of processes can be displayed by specifying the `-Z` option to the `ps` command, as shown in [Example 12-2](ch12.html#process_security_contexts_in_android "Example 12-2. Process security contexts in Android") (in the `LABEL` column).

Example 12-2. Process security contexts in Android

```
# **ps -Z**
LABEL                                   USER    PID    PPID     NAME
u:r:init:s0➊                            root    1      0        /init
u:r:kernel:s0                           root    2      0        kthreadd
u:r:kernel:s0                           root    3      2        ksoftirqd/0
--*snip*--
u:r:healthd:s0➋              root    175    1        /sbin/healthd
u:r:servicemanager:s0➌       system  176    1        /system/bin/
servicemanager
u:r:vold:s0➍                 root    177    1        /system/bin/vold
u:r:init:s0                             nobody  178    1        /system/bin/rmt_storage
u:r:netd:s0                             root    179    1        /system/bin/netd
u:r:debuggerd:s0                        root    180    1        /system/bin/debuggerd
u:r:rild:s0                             radio   181    1        /system/bin/rild
--*snip*--
u:r:platform_app:s0                     u0_a12  950    183      com.android.systemui
u:r:media_app:s0                        u0_a5   1043   183      android.process.media
u:r:radio:s0                            radio   1141   183      com.android.phone
u:r:nfc:s0                              nfc     1163   183      com.android.nfc
u:r:untrusted_app:s0                    u0_a7   1360   183      com.google.android.gms
--*snip*--
```

Similarly, the context of files can be viewed by passing the `-Z` to the `ls` command, as shown in [Example 12-3](ch12.html#file_and_directory_security_contexts_in "Example 12-3. File and directory security contexts in Android").

Example 12-3. File and directory security contexts in Android

```
# **ls -Z**
drwxr-xr-x root        root              u:object_r:cgroup:s0 acct
drwxrwx--- system      cache             u:object_r:cache_file:s0 cache
-rwxr-x--- root        root              u:object_r:rootfs:s0 charger
--*snip*--
drwxrwx--x system      system            u:object_r:system_data_file:s0 data
-rw-r--r-- root        root              u:object_r:rootfs:s0 default.prop
drwxr-xr-x root        root              u:object_r:device:s0 dev
lrwxrwxrwx root        root              u:object_r:rootfs:s0 etc -> /system/etc
-rw-r--r-- root        root              u:object_r:rootfs:s0 file_contexts
dr-xr-x--- system      system            u:object_r:sdcard_external:s0 firmware
-rw-r----- root        root              u:object_r:rootfs:s0 fstab.hammerhead
-rwxr-x--- root        root              u:object_r:rootfs:s0 init
--*snip*--
```

## Security Context Assignment and Persistence

We’ve established that all subject and objects have a security context, but how is the context assigned and persisted? For objects (which are usually associated with a file on the filesystem), the security context is persistent and is usually stored as an extended attribute in the file’s metadata.

Extended attributes are not interpreted by the filesystem and can contain arbitrary data (though any such data is usually limited in size). The *ext4* filesystem, the default in most Linux distributions and current versions of Android, supports extended attributes in the form of name-value pairs, where the name is a null-terminated string. SELinux uses the *security.selinux* name to store the security context of file objects. The security context of objects can be set explicitly as part of a filesystem initialization (also called *labeling*), or be implicitly assigned when an object is created. Objects typically inherit the type label of their parent (for example, newly created files in a directory inherit the label of the directory). However, if the security policy allows, objects can receive a label that’s different from that of their parent, a process referred to as *type transition*.

Like objects, subjects (processes) inherit the security context of their parent process, or they can change their context via *domain transition*, if allowed by the security policy. The policy can specify automatic domain transition as well, which automatically sets the domain of newly started processes based on the domain of their parent and the type of the executed binary. For example, because all system daemons are started by the *init* process, which has the *u:r:init:s0* security context (➊ in [Example 12-2](ch12.html#process_security_contexts_in_android "Example 12-2. Process security contexts in Android")), they would normally inherit this context, but Android’s SELinux policy uses automatic domain transitions to set a dedicated domain to each daemon as needed (➋, ➌, and ➍ in [Example 12-2](ch12.html#process_security_contexts_in_android "Example 12-2. Process security contexts in Android")).

## Security Policy

The SELinux security policy is used by the security server in the kernel to allow or disallow access to kernel objects at runtime. For performance reasons, the policy is typically in a binary form generated by compiling a number of policy source files. The policy source files are written in a dedicated policy language, which consists of statements and rules. *Statements* define policy entities such as types, users, and roles. *Rules* allow or deny access to objects (access vector rules); specify the type of transitions allowed (type enforcement rules); and designate how default users, roles, and types are assigned (default rules). A thorough discussion of SELinux’s policy grammar is beyond the scope of this book, but the following sections will introduce some of the most widely used statements and rules.

## Policy Statements

The SELinux policy language supports various types of statements, but type, attribute, and permission statements make up the bulk of a security policy. We introduce these three types of statements in the following sections.

### Type and Attribute Statements

`type` and `attribute` statements declare types and their attributes, as shown in [Example 12-4](ch12.html#type_and_attribute_statements-id00028 "Example 12-4. type and attribute statements").

Example 12-4. `type` and `attribute statements`

```
attribute file_type;➊
attribute domain;➋

type system_data_file, file_type, data_file_type;➌
type untrusted_app, domain;➍
```

Here, the first ➊ and second ➋ statements declare the `file_type` and `domain` attributes, and the next statement ➌ declares the `system_data_file` type and associates it with the `file_type` and `data_file_type` attributes. The code at ➍ declares the `untrusted_app` type and associates it with the `domain` attribute (which marks all types used for processes).

Depending on its granularity, an SELinux policy can have dozens or even hundreds of type and attribute declarations spread across multiple source files. However, because access to all kernel objects needs to be checked against the policy at runtime, a large policy can have a negative impact on performance. The effect on performance is especially apparent when running on devices with limited computing resources, and that is why Android strives to keep its SELinux policy relatively small.

### User and Role Statements

The `user` statement declares an SELinux user identifier, associates it with its role(s), and optionally specifies its default security level and the range of security levels that the user can access. [Example 12-5](ch12.html#declarations_of_the_default_selinux_user "Example 12-5. Declarations of the default SELinux user identifier in Android") shows the declarations of the default and only user identifier in Android.

Example 12-5. Declarations of the default SELinux user identifier in Android

```
user u roles { r } level s0 range s0 - mls_systemhigh;
```

As you can see in [Example 12-5](ch12.html#declarations_of_the_default_selinux_user "Example 12-5. Declarations of the default SELinux user identifier in Android"), the *u* user is associated with the *r* role (inside the braces), which in turn is declared using the `role` statement ➊ as shown in [Example 12-6](ch12.html#declaration_of_the_default_selinux_role "Example 12-6. Declaration of the default SELinux role in Android").

Example 12-6. Declaration of the default SELinux role in Android

```
role r;➊
role r types domain;➋
```

The second statement ➋ associates the *r* role with the `domain` attribute, which marks it as a role assigned to processes (domains).

### Object Class and Permission Statements

The `permissive` statement allows a named domain to run in permissive mode (a mode that only logs MAC policy violations but doesn’t actually enforce the policy, as discussed next), even if SELinux is running in enforcing mode. As we will see in “[Enforcing Domains](ch12.html#enforcing_domains "Enforcing Domains")”, most domains in Android’s current base policy are permissive. For example, processes in the *adbd* domain (in practice *adbd* daemon processes) run in permissive mode, as shown in [Example 12-7](ch12.html#setting_a_named_domain_to_permissive_mod "Example 12-7. Setting a named domain to permissive mode") ➊.

Example 12-7. Setting a named domain to permissive mode

```
type adbd, domain;
permissive adbd;➊
--*snip*--
```

The `class` statement defines an SELinux object class, as shown in [Example 12-8](ch12.html#object_class_declarations_in_the_securit "Example 12-8. Object class declarations in the security_classes file"). Object classes and their associated permissions are determined by the respective object manager implementations in the Linux kernel, and are static within a policy. Object classes are usually defined in the *security_classes* policy source file.

Example 12-8. Object class declarations in the security_classes *file*

```
--*snip*--
# file-related classes
class filesystem
class file
class dir
class fd
class lnk_file
class chr_file
class blk_file
class sock_file
class fifo_file
--*snip*--
```

SELinux permissions (also referred to as *access vectors*) are usually defined and associated with object classes in a policy source file called *access_vectors*. Permissions can be either class-specific (defined with the `class` keyword) or inheritable by one or more object classes, in which case they’re defined with the `common` keyword. [Example 12-9](ch12.html#permission_definitions_in_the_accessunde "Example 12-9. Permission definitions in the access_vectors file") shows the definition of the set of permissions common to all file objects ➊, and the association of the `dir` class (which represents directories) with all common file permissions (using the `inherits` keyword), and a set of directory-specific permissions (*add_name*, *remove_name*, and so on) ➋.

Example 12-9. Permission definitions in the access_vectors file

```
--*snip*--
common file
{
    ioctl
    read

    write
    create
    getattr
    setattr
    lock
    --*snip*--
}➊
--*snip*--
class dir
inherits file
{

    add_name
    remove_name
    reparent
    search
    rmdir
    --*snip*--
}➋
--*snip*--
```

## Type Transition Rules

Type enforcement rules and access vector rules (discussed in “[Domain Transition Rules](ch12.html#domain_transition_rules "Domain Transition Rules")” and “[Access Vector Rules](ch12.html#access_vector_rules "Access Vector Rules")”) typically make the bulk of an SELinux policy. In turn, the most commonly used type of enforcement rule is the `type_transition` rule, which specifies when domain and type transitions are allowed. For example, the *wpa_supplicant* daemon, which manages Wi-Fi connections in Android, uses the type transition rule shown in [Example 12-10](ch12.html#type_transitions_in_the_wpa_domain_left "Example 12-10. Type transitions in the wpa domain (from wpa_supplicant.te)") at ➍ in order to associate the control sockets it creates in the */data/misc/wifi/* directory with the `wpa_socket` type. In the absence of this rule, the sockets would inherit the type of their parent directory: `wifi_data_file`.

Example 12-10. Type transitions in the wpa domain (from wpa_supplicant.te)

```
# wpa - wpa supplicant or equivalent
type wpa, domain;
permissive wpa;➊
type wpa_exec, exec_type, file_type;

init_daemon_domain(wpa)➋
unconfined_domain(wpa)➌
type_transition wpa wifi_data_file:sock_file wpa_socket;➍
```

Here, `wpa`, `wifi_data_file:sock_file`, and `wpa_socket` are the source type (in this case, the domain of the *wpa_supplicant* process), the target type and class (the type and class of the object before the transition), and the type of the object after the transition, respectively.

### Note

*In order to be able to create the socket file and change its label, the `wpa` domain needs additional permissions on the parent directory and the socket file itself—the `type_transition` rule alone is not sufficient. However, because the `wpa` domain is both permissive* ➊ *and unconfined (granted most permissions by default)* ➌*, the transition is allowed without explicitly allowing each required permission.*

## Domain Transition Rules

In Android, native system daemons like *wpa_supplicant* are started by the *init* process, and therefore inherit its security context by default. However, most daemons are associated with a dedicated domain and use domain transitions to switch their domain when started. This is typically accomplished using the `init_daemon_domain()` macro (➋ in [Example 12-10](ch12.html#type_transitions_in_the_wpa_domain_left "Example 12-10. Type transitions in the wpa domain (from wpa_supplicant.te)")), which under the hood is implemented using the `type_transition` keyword, just like type transitions.

The binary SELinux policy build process uses the `m4` macro preprocessor^([[132](#ftn.ch12fn01)]) to expand macros before merging all source files in order to create the binary policy file. The `init_daemon_domain()` macro takes one parameter (the new domain of the process) and is defined in the *te_macros* file using two other macros: `domain_trans()` and `domain_auto_trans()`, which are used to allow transition to a new domain and to execute the transition automatically, respectively. [Example 12-11](ch12.html#domain_transition_macros_definition_in_t "Example 12-11. Domain transition macros definition in the te_macros file") shows the definitions of these three macros (➊, ➋, and ➌). The lines beginning with the `allow` keyword are access vector (AV) rules, which we discuss in the next section.

Example 12-11. Domain transition macros definition in the te_macros `file`

```
# domain_trans(olddomain, type, newdomain)
define(`domain_trans', `
allow $1 $2:file { getattr open read execute };
allow $1 $3:process transition;
allow $3 $2:file { entrypoint read execute };
allow $3 $1:process sigchld;
dontaudit $1 $3:process noatsecure;
allow $1 $3:process { siginh rlimitinh };
')➊
# domain_auto_trans(olddomain, type, newdomain)
define(`domain_auto_trans', `
domain_trans($1,$2,$3)
type_transition $1 $2:process $3;
')➋
# init_daemon_domain(domain)
 define(`init_daemon_domain', `
domain_auto_trans(init, $1_exec, $1)
tmpfs_domain($1)
')➌
--*snip*--
```

## Access Vector Rules

AV rules define what privileges processes have at runtime by specifying the set of permissions they have over their target objects. [Example 12-12](ch12.html#format_of_av_rules "Example 12-12. Format of AV rules") shows the general format of an AV rule.

Example 12-12. Format of AV rules

```
rule_name source_type target_type : class perm_set;
```

The `rule_name` can be `allow`, `dontaudit`, `auditallow`, or `neverallow`. To form a rule, the `source_type` and `target_type` elements are replaced with one or more previously defined `type` or `attribute` identifiers, where `source_type` is the identifier of a subject (process), and `target_type` is the identifier of an object the process is trying to access. The `class` element is replaced with the object class of the target, and `perm_set` specifies the set of permissions that the source process has over the target object. You can specify multiple types, classes, and permissions by enclosing them in braces (`{}`). In addition, some rules support use of the wildcard (`*`) and complement (`~`) operators, which allow you to specify that all types should be included or that all types except those explicitly listed should be included, respectively.

### allow Rules

The most commonly used rule is `allow`, which specifies the operations that a subject (process) of the specified source type is allowed to perform on an object of the target type and class specified in the rule. Let’s take the SELinux policy for the *vold* daemon (see [Example 12-13](ch12.html#allow_rules_for_the_vold_domain_left_par "Example 12-13. allow rules for the vold domain (from vold.te)")) as an example to illustrate how to use the `allow` rule.

Example 12-13. `allow` rules for the `vold` domain (from vold.te)

```
type vold, domain;
type vold_exec, exec_type, file_type;
init_daemon_domain(vold)
--*snip*--
allow vold sdcard_type:filesystem { mount remount unmount };➊
--*snip*--
allow vold self:capability { sys_ptrace kill };➋
--*snip*--
```

In this listing, rule ➊ allows the *vold* daemon (which runs in the `vold` domain) to mount, unmount, and remount filesystems of type `sdcard_type`. Rule ➋ allows the daemon to use the `CAP_SYS_PTRACE` (which allows `ptrace()` to be called on any process) and `CAP_KILL` (which allows signals to be sent to any process) Linux capabilities, which correspond to the permission set specified in the rule (inside the `{}`). In rule ➋, the `self` keyword means that the target domain is the same as the source, which in this case is `vold`.

### auditallow Rules

The `auditallow` rule is used with `allow` to record audit events when an operation is allowed. This is useful because by default, SELinux logs only access denied events. However, `auditallow` itself doesn’t grant access, and therefore a matching `allow` rule must be used in order to grant the necessary permissions.

### dontaudit Rules

The `dontaudit` rule is used to suppress the auditing of denial messages when a specified event is known to be safe. For example, the rule at ➊ in [Example 12-14](ch12.html#dontaudit_rule_for_the_installd_domain_l "Example 12-14. dontaudit rule for the installd domain (from installd.te)") specifies that no audit log be created if the *installd* daemon is denied the `CAP_SYS_ADMIN` capability. However, `dontaudit` rules can mask program errors and the use of `dontaudit` is discouraged.

Example 12-14. `dontaudit` rule for the installd domain (from installd.te)

```
type installd, domain;
--*snip*--
dontaudit installd self:capability sys_admin;➊
--*snip*--
```

### neverallow Rules

The `neverallow` rule says that the declared operation should never be allowed, even if an explicit `allow` rule that allows it exists. For example, the rule shown in [Example 12-15](ch12.html#neverallow_rule_that_forbids_domains_oth "Example 12-15. neverallow rule that forbids domains other than init from loading the SELinux policy (from domain.te)") forbids all domains but the `init` domain to load the SELinux policy.

Example 12-15. `neverallow` rule that forbids domains other than init from loading the SELinux policy (from domain.te)

```
--*snip*--
neverallow { domain -init } kernel:security load_policy;
```

### Note

*This section provides only a brief overview of SELinux, focusing on the features used in Android. For a more detailed discussion of the architecture and implementation of SELinux, as well its policy language, see the* SELinux Notebook.^([[133](#ftn.ch12fn02)])

# Android Implementation

As discussed in [Chapter 1](ch01.html "Chapter 1. Android’s Security Model") and [Chapter 2](ch02.html "Chapter 2. Permissions"), Android’s sandboxing security model relies heavily on the use of separate Linux UIDs for system daemons and applications. Process isolation and access control is ultimately enforced by the Linux kernel based on process UID and GIDs. Because SELinux is also part of the Linux kernel, SELinux is a natural candidate for hardening the Android sandboxing model using a MAC policy.

As SELinux is integrated into the mainline Linux kernel, it would seem that enabling it in Android should be a simple matter of configuring the kernel and designing an appropriate MAC policy. However, because Android introduces some unique extensions to the Linux kernel and its userspace structure is quite different from that of desktop and server Linux distributions, several changes in both kernel and userspace were needed in order to integrate and enable SELinux into Android. While the initial work required to integrate SELinux was started by Google, most of the required changes were implemented in the Security Enhancements for Android project (formally Security-Enhanced Android, or SEAndroid),^([[134](#ftn.ch12fn03)]) and were later integrated into the mainline Android source tree. The following sections survey these major changes. For a comprehensive list of changes and the rationale behind them, see the *Security Enhanced (SE) Android: Bringing Flexible MAC to Android* paper by the original authors of the SEAndroid project.^([[135](#ftn.ch12fn04)])

## Kernel Changes

Recall from earlier that SELinux is a security module that implements the various LSM hooks inserted in kernel services related to object access control. Android’s Binder IPC mechanism is also implemented as a kernel driver, but because its implementation originally did not contain any LSM hooks, its runtime behavior could not be controlled by an SELinux policy. In order to add SELinux support to Binder, LSM hooks were inserted into the Binder driver, and support for the `binder` object class and related permissions was added to SELinux code.

SELinux security hooks are declared in *include/linux/security.h*, and [Example 12-16](ch12.html#binder_security_hooks_declarations_in_in "Example 12-16. Binder security hooks declarations in include/linux/security.h") shows the Binder-related declarations added to support Android.

Example 12-16. Binder security hooks declarations in include/linux/security.h

```
--*snip*--
int security_binder_set_context_mgr(struct task_struct *mgr);➊
int security_binder_transaction(struct task_struct *from,
                                struct task_struct * to);➋
int security_binder_transfer_binder(struct task_struct *from,
                                    struct task_struct *to);➌
int security_binder_transfer_file(struct task_struct *from,
                                  struct task_struct *to, struct file *file);➍
--*snip*--
```

The first hook ➊ controls what process can become the binder context manager, and the second one ➋ controls the ability of a process to invoke a binder transaction. The next two functions are used to regulate who can transfer a Binder reference to another process ➌, and transfer an open file to another process ➍ using Binder.

In order to allow the SELinux policy to set restrictions for Binder, support for the `binder` object class and its permissions (`impersonate`, `call`, `set_context_mgr`, and `transfer`) was also added to the kernel, as shown in [Example 12-17](ch12.html#binder_object_class_and_permission_decla "Example 12-17. Binder object class and permission declaration in selinux/include/classmap.h").

Example 12-17. Binder object class and permission declaration in selinux/include/classmap.h

```
--*snip*--
struct security_class_mapping secclass_map[] = {
    --*snip*--
    {"binder", {"impersonate", "call", "set_context_mgr", "transfer", NULL} },
    { NULL }
  };
```

## Userspace Changes

In addition to kernel changes, a number of userspace modifications and extensions were also required in order to integrate SELinux into Android. Among these, the most important ones are support for filesystem labeling in the core C library (bionic); extensions to *init* and the core native daemons and executables; framework-level SELinux APIs; and modifications to core framework services to make them SELinux-aware. This section describes each change and how it’s integrated into the Android runtime.

### Libraries and Tools

Because SELinux uses extended attributes to store the security contexts of filesystem objects, wrapper functions for the system calls used to manage extended attributes (`listxattr()`, `getxattr()`, `setxattr()`, and so on) were first added to Android’s C library in order to be able to get and set the security labels of files and directories.

In order to be able to take advantage of SELinux features from user-space, SEAndroid added an Android-compatible port of the *libselinux* library, as well as a set of utility commands to manage labeling, the security policy, and to switch the SELinux mode between enforcing and permissive. Like most Android command-line utilities, SELinux tools are implemented in the `toolbox` binary and are installed as symbolic links to it. [Table 12-1](ch12.html#selinux_command-line_utilities "Table 12-1. SELinux Command-Line Utilities") summarizes the added or modified command-line tools.

Table 12-1. SELinux Command-Line Utilities

| Command | Description |
| --- | --- |
| `chcon` | Changes a file’s security context |
| `getenforce` | Gets the current SELinux mode |
| `getsebool` | Gets policy Boolean values |
| `id` | Displays a process’s security context |
| `load_policy` | Loads a policy file |
| `ls -Z` | Displays the security context of a file |
| `ps -Z` | Displays the security context of running processes |
| `restorecon` | Restores the security context of a file(s) |
| `runcon` | Runs a program in the specified security context |
| `setenforce` | Sets the enforcing mode |
| `setsebool` | Sets the value of a policy Boolean |

### System Initialization

As in traditional Linux systems, in Android all userspace daemons and programs are started by the *init* process, the first process the kernel starts (PID=1). However, unlike other Linux-based systems, Android’s initialization scripts (*init.rc* and its variants) are not interpreted by a general-purpose shell, but by *init* itself. Each initialization script contains built-in commands that are executed by *init* as it reads the script. SEAndroid extends Android’s *init* language with a number of new commands required to initialize SELinux and set the security contexts of services and files, as summarized in [Table 12-2](ch12.html#init_built-in_commands_for_selinux_suppo "Table 12-2. init Built-in Commands for SELinux Support").

Table 12-2. init Built-in Commands for SELinux Support

| init Built-In Command | Description |
| --- | --- |
| `seclabel` | Sets the security context of a service |
| `restorecon` | Restores the security context of a file or directory |
| `setcon` | Set the security context of the *init* process |
| `setenforce` | Sets the enforcing mode |
| `setsebool` | Sets the value of a policy Boolean |

When *init* starts, it loads the SELinux policy from the */sepolicy* binary policy file, and then sets the enforcing mode based on the value of the *ro.boot.selinux* system property (which *init* sets based on the value of the *androidboot.selinux* kernel command-line parameter). When the property value is *permissive*, SELinux goes into permissive mode; when set to any other value or not set at all, the mode is set to enforcing.

Next, *init* loads and parses the *init.rc* file and executes the commands specified there. [Example 12-18](ch12.html#selinux_initialization_in_initdotrc "Example 12-18. SELinux initialization in init.rc") shows an excerpt of *init.rc*, focusing on the parts responsible for SELinux initialization.

Example 12-18. SELinux initialization in init.rc

```
--*snip*--
on early-init
    --*snip*--
    setcon u:r:init:s0➊
    start ueventd
--*snip*--
on post-fs-data
    chown system system /data
    chmod 0771 /data
    restorecon /data➋
--*snip*--
service ueventd /sbin/ueventd
    class core
    critical
    seclabel u:r:ueventd:s0➌
--*snip*--
on property:selinux.reload_policy=1➍
    restart ueventd
    restart installd
--*snip*--
```

In this example, *init* sets its own security context using the `setcon` command ➊ before starting the core system daemons. Because a child process inherits the security context of its parent, *init* explicitly sets the security context of the *ueventd* daemon (the first daemon to be started) to *u:r:ueventd:s0* ➌ using the `seclabel` command. Most other native services have their domain set automatically by type transition rules defined in the policy (as in [Example 12-10](ch12.html#type_transitions_in_the_wpa_domain_left "Example 12-10. Type transitions in the wpa domain (from wpa_supplicant.te)")). (The `seclabel` command is only used to set the security contexts of processes that start very early in the system initialization process.)

When writable filesystems are mounted, *init* uses the `restorecon` command to restore the default labels of their mount points, because a factory reset could have cleared their labels. [Example 12-18](ch12.html#selinux_initialization_in_initdotrc "Example 12-18. SELinux initialization in init.rc") shows the command ➋ that labels the *userdata* partition’s mount point—*/data*.

Finally, because a policy reload can be triggered by setting the *selinux.reload_policy* system property to 1 ➍, *init* restarts the *ueventd* and *installd* daemons when this property is set so that the new policy can take effect.

### Labeling Files

Recall that persistent SELinux objects, such as files, have a persistent security context that is typically saved in a file’s extended attribute. In Android, the initial security context of all files is defined in a text file called *file_contexts*, which might look like [Example 12-19](ch12.html#contents_of_the_fileunderscorecontexts_f "Example 12-19. Contents of the file_contexts file").

Example 12-19. Contents of the file_contexts file

```
/                            u:object_r:rootfs:s0➊
/adb_keys                    u:object_r:rootfs:s0
/default.prop                u:object_r:rootfs:s0
/fstab\..*                   u:object_r:rootfs:s0
--*snip*--
/dev(/.*)?                   u:object_r:device:s0➋
/dev/akm8973.*               u:object_r:akm_device:s0
/dev/accelerometer           u:object_r:accelerometer_device:s0
--*snip*--
/system(/.*)?                u:object_r:system_file:s0➌
/system/bin/ash              u:object_r:shell_exec:s0
/system/bin/mksh             u:object_r:shell_exec:s0
--*snip*--
/data(/.*)?                  u:object_r:system_data_file:s0➍
/data/backup(/.*)?           u:object_r:backup_data_file:s0
/data/secure/backup(/.*)?    u:object_r:backup_data_file:s0
--*snip*--
```

As you can see, the file contains a list of paths (sometimes using wildcard characters) and their associated security contexts, each on a new line. The *file_contexts* file is consulted at various times during Android’s build and bootup process. For example, because on-memory filesystems such as Android’s root filesystem (mounted at */*) and the device filesystem (mounted at */dev*) are not persistent, all files are usually associated with the same security context as specified in the *genfs_contexts* file, or assigned using the `context=` mount option. In order to assign individual security contexts to specific files in such filesystems, *init* uses the `restorecon` command to look up the security context of each file in *file_contexts* (➊ for the root file-system, and ➋ as the default for the device filesystem) and sets it accordingly. When building Android from source, the `make_ext4fs` command also consults *file_contexts* in order to set the initial contexts of files on the *system* (mounted at */system* ➌) and *userdata* partition (mounted at */data* ➍) images. The security contexts of data partitions’ mount points are also restored on each boot (as shown in [Example 12-18](ch12.html#selinux_initialization_in_initdotrc "Example 12-18. SELinux initialization in init.rc")) in order to make sure they’re in a consistent state. Finally, Android’s recovery OS also includes a copy of *file_contexts*, which is used to set the correct labels of files created by the recovery during system updates. This guarantees that the system remains in a securely labeled stated across updates and avoids the need for full relabeling after each update.

### Labeling System Properties

Android uses global system properties that are visible to all processes for various purposes such as communicating hardware state, starting or stopping system services, triggering disk encryption, and even reloading the SELinux policy. Access to read-only system properties isn’t restricted, but because changing the values of key read-write properties alters the behavior of the system, write access to these properties is restricted and allowed only to system processes running under privileged UIDs, such as *system* and *radio*. SEAndroid augments this UID-based access control by adding MAC rules that regulate write access to system properties based on the domain of the process attempting property modification. In order for this to work, system properties (which are not native SELinux objects) must be associated with security contexts. This is accomplished by listing the security contexts of properties in a *property_contexts* file, much the same way that *file_contexts* specifies the security labels of files. The file is loaded into memory by the *property_service* (part of *init*), and the resulting security context lookup table is used to determine whether a process should be allowed access to a specific property based on the security contexts of both the process (subject) and the property (object). The SELinux policy defines a new `property_service` object class, with a single permission, `set`, which is used to specify access rules, as shown in [Example 12-20](ch12.html#system_property_access_rules_in_volddott "Example 12-20. System property access rules in vold.te").

Example 12-20. System property access rules in vold.te

```
type vold, domain;
--*snip*--
allow vold vold_prop:property_service set;➊
allow vold powerctl_prop:property_service set;➋
allow vold ctl_default_prop:property_service set;➌
--*snip*--
```

In this listing, the `vold` domain is allowed to set system properties of type `vold_prop` ➊, `powerctl_prop` ➋, and `ctl_default_prop` ➌.

These types are associated with actual properties based on the property name in *property_contexts*, as shown in [Example 12-21](ch12.html#association_of_property_names_with_their "Example 12-21. Association of property names with their security contexts in property_contexts").

Example 12-21. Association of property names with their security contexts in property_contexts

```
--*snip*--
vold.                     u:object_r:vold_prop:s0➊
sys.powerctl              u:object_r:powerctl_prop:s0➋
ctl.                      u:object_r:ctl_default_prop:s0➌
--*snip*--
```

The effect of this policy is that *vold* can set the values of all properties whose name starts with `vold.` ➊, `sys.powerctl` ➋, or `ctl.` ➌.

### Labeling Application Processes

Recall from [Chapter 2](ch02.html "Chapter 2. Permissions") that all app processes in Android are forked from the *zygote* process in order to reduce memory usage and improve application startup time. The *system_server* process, which runs as the *system* user and hosts most system services, is also forked from *zygote*, albeit via a slightly different interface.

The *zygote* process, which runs as root, is responsible for setting each app process’s DAC credentials (UID, GID, and supplementary GIDs), as well as its capabilities and resource limits. In order to support SELinux, *zygote* has been extended to check the security context of its clients (implemented in the `ZygoteConnection` class) and set the security context of each app process that it forks. The security context is determined according to the assignment rules specified in the *seapp_contexts* configuration file, according to the app’s UID, its package name, a flag that marks the system server process, and an SELinux-specific string attribute called `seinfo`. The *seapp_contexts* configuration file contains security context assignment rules (one per line) that consist of input selector attributes and output attributes. In order for a rule to be matched, all input selectors should match (logical AND). [Example 12-22](ch12.html#contents_of_the_seappunderscorecontexts "Example 12-22. Contents of the seapp_contexts file") shows the contents of the *seapp_contexts* file in the reference Android SELinux policy as of version 4.4.3.

### Note

*The* seapp_contexts*, like all files in the reference policy, can be found in the* external/sepolicy/ *directory of Android’s source tree. See the file’s comments for the full list of input selectors, the selector matching precedence rules, and outputs.*

Example 12-22. Contents of the seapp_contexts file

```
isSystemServer=true domain=system➊
user=system domain=system_app type=system_data_file➋
user=bluetooth domain=bluetooth type=bluetooth_data_file
user=nfc domain=nfc type=nfc_data_file
user=radio domain=radio type=radio_data_file
user=_app domain=untrusted_app type=app_data_file levelFrom=none➌
user=_app seinfo=platform domain=platform_app type=platform_app_data_file➍
user=_app seinfo=shared domain=shared_app type=platform_app_data_file➎
user=_app seinfo=media domain=media_app type=platform_app_data_file
user=_app seinfo=release domain=release_app type=platform_app_data_file
user=_isolated domain=isolated_app➏
user=shell domain=shell type=shell_data_file
```

The first line ➊ in this listing specifies the domain of the system server (`system`), because the `isSystemServer` selector (which can be used only once) is set to `true`. Because Android uses a fixed SELinux user identifier, role and security level, the resulting security context becomes *u:r:system:s0*.

The second assignment rule ➋ matches the `user` selector against the target process’s username, which is derived from its UID. If a process runs as one of the built-in Android Linux users (*system*, *radio*, *nfc*, and so on, as defined in *android_filesystem_config.h*), the associated name is used when matching the `user` selector. Isolated services are given the *_isolated* user-name string, and any other process is given the *_app* username string. Thus, system apps that match this selector are assigned the `system_app` domain.

The `type` attribute specifies the object type that’s assigned to files owned by the target process. Because in this case the type is `system_data_file`, the security context of system files becomes *u:object_r:system_data_file:s0*.

Rule ➌ matches all apps that execute under a non-system UID and assigns their processes to the `untrusted_app` domain. The private app data directory of each untrusted app is recursively assigned the `app_data_file` object type, which results in the *u:object_r:app_data_file:s0* security context. The security context of the data directory is set by the *installd* daemon when it creates it as part of the app install process (see [Chapter 3](ch03.html "Chapter 3. Package Management")).

Rules ➍ and ➎ use the `seinfo` selector to differentiate between non-system apps and assign them to different domains: apps processes that match `seinfo=platform` are assigned the `platform_app` domain, and those matching `seinfo=shared` are assigned the `shared_app` domain. (As we’ll see in the next section, an app’s `seinfo` attribute is determined by its signing certificate, so in effect, rules ➍ and ➎ use each app’s signing certificate as a process domain selector.)

Finally, rule ➏ assigns the `isolated_app` domain to all isolated services. (Isolated services run under a UID separate from their hosting app’s UID and cannot access any system services.)

### Middleware MAC

The `seinfo` attribute introduced in the previous section is part of an SEAndroid feature called *middleware MAC (MMAC)*, which is a higher-level access control scheme, separate from the kernel-level MAC (implemented in the SELinux LSM module).

The MMAC was designed to provide MAC restrictions over Android’s permission model, which works at the framework level and cannot be easily mapped to the default kernel-level MAC. The original implementation includes an install-time MAC feature, which restricts the permissions that can be granted to each package based on its package name and signing certificate, regardless of a user’s permission grant decision. That is, even if a user decides to grant an app all the permissions it requests, the install can still be blocked by the MMAC if the policy doesn’t allow certain permissions to be granted.

SEAndroid’s MMAC implementation also includes an intent MMAC feature that uses a policy to control which intents can be exchanged between applications. Another SEAndroid feature is the content provider MMAC, which defines a policy for content provider data access. However, the original SEAndroid MMAC implementation has been merged in mainline Android only partially, and the only supported feature is `seinfo` assignment based on the app signing certificate.

### Note

*As of version 4.3, Android has an experimental* intent firewall *feature that restricts what intents can be sent and received using “firewall”-style rules. This feature is similar to SEAndroid’s intent MMAC but is not integrated with the SELinux implementation.*

The MMAC configuration file is called *mac_permission.xml* and resides in the */system/etc/security/* directory on the device. [Example 12-23](ch12.html#template_for_the_macunderscorepermission "Example 12-23. Template for the mac_permission.xml file") shows the template used to generate this file, typically stored as *external/sepolicy/ mac_permission.xml* in Android’s source tree.

Example 12-23. Template for the mac_permission.xml file

```
<?xml version="1.0" encoding="utf-8"?>
<policy>

    <!-- Platform dev key in AOSP -->
    <signer signature="@PLATFORM" >➊
      <seinfo value="platform" />
    </signer>

    <!-- Media dev key in AOSP -->
    <signer signature="@MEDIA" >➋
      <seinfo value="media" />
    </signer>

    <!-- shared dev key in AOSP -->
    <signer signature="@SHARED" >➌
      <seinfo value="shared" />
    </signer>

    <!-- release dev key in AOSP -->
    <signer signature="@RELEASE" >➍
      <seinfo value="release" />
    </signer>

    <!-- All other keys -->
    <default>➎
      <seinfo value="default" />
    </default>

</policy>
```

Here, the *@PLATFORM* ➊, *@MEDIA* ➋, *@SHARED* ➌, and *@RELEASE* ➍ macros represent the four platform signing certificates used in Android (*platform*, *media*, *shared*, and *release*) and are replaced with their respective certificates, encoded as hexadecimal strings, when building the SELinux policy.

When scanning each installed package, the system `PackageManagerService` matches its signing certificate against the contents of the *mac_permission.xml* file and assigns the specified `seinfo` value to the package if it finds a match. If no match is found, it assigns the *default* `seinfo` value as specified by the `<default>` tag ➎.

## Device Policy Files

Android’s SELinux policy consists of a binary policy file and four supporting configuration files, which are used for process, app, system property, and file labeling, as well as for MMAC initialization. [Table 12-3](ch12.html#android_selinux_policy_files "Table 12-3. Android SELinux Policy Files") shows where each of these files is located on a device and provides a brief description of the file’s purpose and contents.

Table 12-3. Android SELinux Policy Files

| Policy File | Description |
| --- | --- |
| */sepolicy* | Binary kernel policy |
| */file_contexts* | File security contexts, used for labeling filesystems |
| */property_contexts* | System property security contexts |
| */seapp_contexts* | Used to derive security contexts of app processes and files |
| */system/etc/security/mac_permissions.xml* | Maps app signing certificates to `seinfo` values |

### Note

*SELinux-enabled Android releases before version 4.4.3 supported overriding the default policy files shown in [Table 12-3](ch12.html#android_selinux_policy_files "Table 12-3. Android SELinux Policy Files") with their counterparts stored in the* /data/ security/current/ *and* /data/system/ *(for the MMAC configuration file) directories in order to enable online policy updates without a full OTA update. However, Android 4.4.3 removed this feature because it could create discrepancies between the security labels set on the filesystem and the labels referenced from the new policy. Policy files are now loaded only from the default, read-only locations shown in [Table 12-3](ch12.html#android_selinux_policy_files "Table 12-3. Android SELinux Policy Files").*

## Policy Event Logging

Access denial and access grants that have matching `auditallow` rules are logged to the kernel log buffer and can be viewed using `dmesg`, as shown in [Example 12-24](ch12.html#selinux_access_denials_logged_in_the_ker "Example 12-24. SELinux access denials logged in the kernel log buffer").

Example 12-24. SELinux access denials logged in the kernel log buffer

```
# **dmesg |grep 'avc:'**
--*snip*--
<5>[18743.725707] type=1400 audit(1402061801.158:256): avc: denied { getattr
} for pid=9574 comm="zygote" path="socket:[8692]" dev="sockfs" ino=8692
scontext=u:r:untrusted_app:s0 tcontext=u:r:zygote:s0 tclass=unix_stream_socket
--*snip*--
```

Here, the audit log shows that a third-party application (source security context *u:r:untrusted_app:s0*) was denied access to the *getattr* permission on the *zygote* Unix domain socket (target context *u:r:zygote:s0*, object class `unix_stream_socket`).

# Android 4.4 SELinux Policy

Android 4.2 was the first release to contain SELinux code, but SELinux was disabled at compile time in release builds. Android 4.3 enabled SELinux in all builds, but its default mode was set to permissive. Additionally, all domains were also individually set to permissive and were based on the `unconfined` domain, essentially allowing them full access (within the confines of DAC), even if the global SELinux mode was set to enforcing.

Android 4.4 was the first version to ship with SELinux in enforcing mode, and it included enforcing domains for core system daemons. This section gives an overview of Android’s SELinux policy, as deployed in version 4.4, and introduces some of the major domains that make up the policy.

## Policy Overview

The source code of Android’s base SELinux policy is hosted in the *external/ sepolicy/* directory of the Android source tree. Besides the files introduced in this chapter so far (*access_vectors*, *file_contexts*, *mac_permissions.xml*, and so on), the policy source consists mostly of type enforcement (TE) statements and rules split into multiple *.te* files, typically one for each defined domain. These files are combined to produce the binary policy file *sepolicy*, which is included in the root of the boot image as */sepolicy*.

You can examine the binary policy file using standard SELinux tools such as `seinfo`, `sesearch`, `sedispol`, and so on. For example, we can use the `seinfo` command to get a summary of the number of policy objects and rules, as shown in [Example 12-25](ch12.html#querying_a_binary_policy_file_using_the "Example 12-25. Querying a binary policy file using the seinfo command").

Example 12-25. Querying a binary policy file using the `seinfo` command

```
$**seinfo sepolicy**

Statistics for policy file: sepolicy
Policy Version & Type: v.26 (binary, mls)

   Classes:                84    Permissions:     249
   Sensitivities:           1    Categories:     1024
   Types:                 267    Attributes:       21
   Users:                   1    Roles:             2
   Booleans:                1    Cond. Expr.:       1
   Allow:                1140    Neverallow:        0
   Auditallow:              0    Dontaudit:        36
   Type_trans:            132    Type_change:       0
   Type_member:             0    Role allow:        0
   Role_trans:              0    Range_trans:       0
   Constraints:            63    Validatetrans:     0
   Initial SIDs:           27    Fs_use:           14
   Genfscon:               10    Portcon:           0
   Netifcon:                0    Nodecon:           0
   Permissives:            42    Polcap:            2
```

As you can see, the policy is fairly complex: it defines 84 classes, 267 types, and 1,140 allow rules.

You can get additional information about policy objects by specifying filtering options to the `seinfo` command. For example, because all domains are associated with the `domain` attribute, the command shown in [Example 12-26](ch12.html#getting_a_list_of_all_defined_domains_us "Example 12-26. Getting a list of all defined domains using the seinfo command") lists all domains defined in the policy.

Example 12-26. Getting a list of all defined domains using the `seinfo` command

```
$ **seinfo -adomain -x sepolicy**
   domain
      nfc
      platform_app
      media_app
      clatd
      netd
      sdcardd
      zygote
--*snip*--
```

You can search for policy rules using the `sesearch` command. For example, all `allow` rules that have the `zygote` domain as their source can be displayed using the command shown in [Example 12-27](ch12.html#searching_for_policy_rules_using_the_ses "Example 12-27. Searching for policy rules using the sesearch commands").

Example 12-27. Searching for policy rules using the `sesearch` commands

```
$**sesearch --allow -s zygote -d sepolicy**
Found 40 semantic av rules:
   allow zygote zygote_exec : file { read execute execute_no_trans entrypoint open } ;
   allow zygote init : process sigchld ;
   allow zygote rootfs : file { ioctl read getattr lock open } ;
   allow zygote rootfs : dir { ioctl read getattr mounton search open } ;
   allow zygote tmpfs : filesystem mount ;
   allow zygote tmpfs : dir { write create setattr mounton add_name search } ;
--*snip*--
```

### Note

*For details about building and customizing the SELinux policy, see the* Validating Security-Enhanced Linux in Android *document.*^([[136](#ftn.ch12fn05)])

## Enforcing Domains

Even though SELinux is deployed in enforcing mode in Android 4.4, only the domains assigned to a few core daemons are currently enforcing, namely: *installd* (responsible for creating application data directories), *netd* (responsible for managing network connections and routes), *vold* (responsible for mounting external storage and secure containers), and *zygote*. All of these daemons run as root or are granted special capabilities because they need to perform administrative operations such as changing directory ownership (*installd*), manipulating packet filtering and routing rules (*netd*), mounting filesystems (*vold*), and changing process credentials (*zygote*) on behalf of other processes.

Because they have elevated privileges, these daemons have been the target of various privilege escalation exploits, which have allowed non-privileged processes to obtain root access on a device. Therefore, specifying a restrictive MAC policy for the domains associated with these system daemons is an important step towards strengthening Android’s sandboxing security model and preventing similar exploits in the future.

Let’s look at the type enforcement rules defined for the `installd` domain (in *instald.te*) to see how SELinux restricts what system daemons can access (see [Example 12-28](ch12.html#installd_type_enforcement_policy_left_pa "Example 12-28. installd type enforcement policy (from installd.te)")).

Example 12-28. installd type enforcement policy (from installd.te)

```
type installd, domain;
type installd_exec, exec_type, file_type;

init_daemon_domain(installd)➊
relabelto_domain(installd)➋
typeattribute installd mlstrustedsubject;➌
allow installd self:capability { chown dac_override fowner fsetid setgid setuid };➍
--*snip*--
allow installd dalvikcache_data_file:file create_file_perms;➎
allow installd data_file_type:dir create_dir_perms;➏
allow installd data_file_type:dir { relabelfrom relabelto };➐
allow installd data_file_type:{ file_class_set } { getattr unlink };➑
allow installd apk_data_file:file r_file_perms;➒
--*snip*--
allow installd system_file:file x_file_perms;➓
--*snip*--
```

In this listing, the *installd* daemon is first automatically transitioned to a dedicated domain (also named `installd`) when started ➊ using the `init_daemon_domain()` macro. It is then granted the `relabelto` permission so that it can set the security labels of the files and directories it creates ➋. Next, the domain is associated with the `mlstrustedsubject` attribute ➌, which allows it to bypass MLS access rules. Because *installd* needs to set the owner of the files and directories it creates to that of their owner application, it’s granted the `chown`, `dac_override`, and other capabilities pertaining to file ownership ➍.

As part of the app install process, *installd* also triggers the DEX optimization process, which creates ODEX files in the */data/dalvik-cache/* directory (security context *u:object_r:dalvikcache_data_file:s0*), which is why the installer daemon is granted permission to create files in that directory ➎. Next, because *installd* creates private data directories for applications in the */data/* directory, it is given permission to create and relabel directories (➏ and ➐), as well as get the attributes and delete files ➑ under */data/* (which is associated with the `data_file_type` attribute). Because *installd* also needs to read downloaded APK files in order to perform DEX optimization, it’s granted access to APK files stored under */data/app/* ➒, a directory associated with the `apk_data_file` type (security context *u:object_r:apk_data_file:s0*).

Finally, *installd* is allowed to execute system commands (security context *u:object_r:system_file:s0*) ➓ in order to start the DEX optimization process. [Example 12-28](ch12.html#installd_type_enforcement_policy_left_pa "Example 12-28. installd type enforcement policy (from installd.te)") omits a few of them, but the remaining policy rules follow the same principle: allow *installd* the least amount of privileges it needs to complete package installation. As a result, even if the daemon is compromised and a malicious program is executed under *installd*’s privileges, it would only have access to a limited number of files and directories, and would be denied any permissions not explicitly allowed by the MAC policy.

### Note

*While Android 4.4 has only four enforcing domains, as the platform evolves and the base SELinux policy is refined, eventually all domains are likely to be deployed in enforcing mode. For example, as of this writing, in the base policy in the master branch of the Android Open Source Project (AOSP), all domains are set to enforcing mode in release builds and the permissive domains are only used in development builds.*

Even if a domain is in enforcing mode, it can be allowed effectively unrestricted access if it’s derived from a base domain that is granted all or most access permissions. In Android’s SELinux policy, such a domain is the `unconfineddomain` domain, which we discuss next.

## Unconfined Domains

Android’s SELinux policy contains a base (also referred to as template) domain called `unconfineddomain`, which is allowed almost all system privileges and is used as a parent for other policy domains. As of Android 4.4, the `unconfineddomain` is defined as shown in [Example 12-29](ch12.html#unconfineddomain_domain_definition_in_an "Example 12-29. unconfineddomain domain definition in Android 4.4").

Example 12-29. `unconfineddomain` domain definition in Android 4.4

```
allow unconfineddomain self:capability_class_set *;➊
allow unconfineddomain kernel:security ~load_policy;➋
allow unconfineddomain kernel:system *;
allow unconfineddomain self:memprotect *;
allow unconfineddomain domain:process *;➌
allow unconfineddomain domain:fd *;
allow unconfineddomain domain:dir r_dir_perms;
allow unconfineddomain domain:lnk_file r_file_perms;
allow unconfineddomain domain:{ fifo_file file } rw_file_perms;
allow unconfineddomain domain:socket_class_set *;
allow unconfineddomain domain:ipc_class_set *;
allow unconfineddomain domain:key *;
allow unconfineddomain fs_type:filesystem *;
allow unconfineddomain {fs_type dev_type file_type}:{ dir blk_file lnk_file sock_file fifo_file
} ~relabelto;
allow unconfineddomain {fs_type dev_type file_type}:{ chr_file file } ~{entrypoint relabelto};
allow unconfineddomain node_type:node *;
allow unconfineddomain node_type:{ tcp_socket udp_socket rawip_socket } node_bind;
allow unconfineddomain netif_type:netif *;
allow unconfineddomain port_type:socket_class_set name_bind;
allow unconfineddomain port_type:{ tcp_socket dccp_socket } name_connect;
allow unconfineddomain domain:peer recv;
allow unconfineddomain domain:binder { call transfer set_context_mgr };
allow unconfineddomain property_type:property_service set;
```

As you can see, the `unconfineddomain` domain is allowed all kernel capabilities ➊, full access to the SELinux security server ➋ (except for loading the MAC policy), all process-related permissions ➌, and so on. Other domains “inherit” the permissions of this domain via the `unconfined_domain()` macro, which assigns the `unconfineddomain` attribute to the domain passed as an argument. In Android 4.4’s SELinux policy, all permissive domains are also unconfined, and thus are granted practically unrestricted access (within the limits of the DAC).

### Note

*While the `unconfineddomain` still exists in AOSP’s master branch, it has been considerably restricted and is no longer used as an unrestricted domain, but as the base policy for system daemons and other privileged Android components. As more domains are switched to enforcing mode and their policies are fine-tuned, `unconfineddomain` is expected to be removed.*

## App Domains

Recall that SEAndroid assigns several different domains to application processes based on their process UID or signing certificate. These application domains are assigned common permissions by inheriting the base `appdomain` using the `app_domain()` macro which, as defined in *app.te*, includes rules that allow the common operations all Android apps require. [Example 12-30](ch12.html#appdomain_policy_excerpt_left_parenthesi "Example 12-30. appdomain policy excerpt (from app.te)") shows an excerpt from the *app.te* file.

Example 12-30. `appdomain` policy excerpt (from app.te)

```
--*snip*--
allow appdomain zygote:fd use;➊
allow appdomain zygote_tmpfs:file read;➋
--*snip*--
allow appdomain system:fifo_file rw_file_perms;
allow appdomain system:unix_stream_socket { read write setopt };
binder_call(appdomain, system)➌

allow appdomain surfaceflinger:unix_stream_socket { read write setopt };
binder_call(appdomain, surfaceflinger)➍

allow appdomain app_data_file:dir create_dir_perms;
allow appdomain app_data_file:notdevfile_class_set create_file_perms;➎
--*snip*--
```

This policy allows the `appdomain` to receive and use file descriptors from *zygote* ➊; read system properties managed by *zygote* ➋; communicate with the *system_server* via pipes, local sockets, or Binder ➌; communicate with the *surfaceflinger* daemon (responsible for drawing on screen) ➍; and create files and directories in its sandbox data directory ➎. The rest of the policy defines rules that allow other required permissions, such as network access, access to downloaded files, and Binder access to core system services. Operations that apps do not typically require, such as raw block device access, kernel memory access, and SELinux domain transitions, are explicitly prohibited using `neverallow` rules.

Concrete app domains such as `untrusted_app` (which is assigned to all non-system applications according to the assignment rules in *seapp_contexts* shown in [Example 12-22](ch12.html#contents_of_the_seappunderscorecontexts "Example 12-22. Contents of the seapp_contexts file")) extend `appdomain` and add additional access rules, as required by the target application(s). [Example 12-31](ch12.html#untrustedunderscoreapp_domain_policy_exc "Example 12-31. untrusted_app domain policy excerpt (from untrusted_app.te)") shows an excerpt from *untrusted_app.te*.

Example 12-31. `untrusted_app` domain policy excerpt (from untrusted_app.te)

```
type untrusted_app, domain;
permissive untrusted_app;➊
app_domain(untrusted_app)➋
net_domain(untrusted_app)➌
bluetooth_domain(untrusted_app)➍

allow untrusted_app tun_device:chr_file rw_file_perms;➎

allow untrusted_app sdcard_internal:dir create_dir_perms;
allow untrusted_app sdcard_internal:file create_file_perms;➏

allow untrusted_app sdcard_external:dir create_dir_perms;
allow untrusted_app sdcard_external:file create_file_perms;➐

allow untrusted_app asec_apk_file:dir { getattr };
allow untrusted_app asec_apk_file:file r_file_perms;➑
--*snip*--
```

In this policy file, the `untrusted_app` domain is set to permissive mode ➊, after which it inherits the policies of `appdomain` ➋, `netdomain` ➌, and `bluetoothdomain` ➍ via the respective macros. The domain is then allowed access to tunnel devices (used for VPNs) ➎, external storage (SD cards, ➏ and ➐), and encrypted application containers ➑. The rest of the rules (not shown) grant access to sockets, pseudoterminals, and a few other needed OS resources.

All other app domains (`isolated_app`, `media_app`, `platform_app`, `release_app`, and `shared_app` in version 4.4) also inherit from `appdomain` and add additional `allow` rules, either directly or by extending additional domains. In Android 4.4, all app domains are set to permissive mode.

### Note

*The SELinux policy in AOSP’s mater branch simplifies the app domain hierarchy by removing the dedicated `media_app`, `shared_app`, and `release_app` domains and merging them into the `untrusted_app` domain. Additionally, only the `system_app` domain is unconfined.*

# Summary

As of version 4.3, Android has integrated SELinux in order to reinforce the default sandbox model using the mandatory access control (MAC) available in the Linux kernel. Unlike the default discretionary access control (DAC), MAC offers a fine-grained object and permission model and a flexible security policy that cannot be overridden or changed by malicious processes (as long as the kernel itself isn’t compromised).

Android 4.4 is the first version to switch SELinux to enforcing mode in release builds, but all domains other than a few highly privileged core daemons are set to permissive mode in order to maintain compatibility with existing applications. Android’s base SELinux policy continues to be refined with each release, and future releases will likely switch most domains to enforcing mode and remove the supporting unconfined domain, which is currently inherited by the majority of domains associated with privileged services.

* * *

^([[132](#ch12fn01)]) Free Software Foundation, Inc., “GNU M4 - GNU Project - Free Software Foundation (FSF),” *[https://www.gnu.org/software/m4/](https://www.gnu.org/software/m4/)*

^([[133](#ch12fn02)]) Richard Haines, *The SELinux Notebook: The Foundations*, 3rd edition, 2012, *[http://www.freetechbooks.com/efiles/selinuxnotebook/The_SELinux_Notebook_The_Foundations_3rd_Edition.pdf](http://www.freetechbooks.com/efiles/selinuxnotebook/The_SELinux_Notebook_The_Foundations_3rd_Edition.pdf)*

^([[134](#ch12fn03)]) Security Enhancements for Android, *[https://bitbucket.org/seandroid/manifests/](https://bitbucket.org/seandroid/manifests/)*

^([[135](#ch12fn04)]) Craig Smalley, *Security Enhanced (SE) Android: Bringing Flexible MAC to Android*, *[http://www.internetsociety.org/sites/default/files/02_4.pdf](http://www.internetsociety.org/sites/default/files/02_4.pdf)*

^([[136](#ch12fn05)]) Google, “Validating Security-Enhanced Linux in Android,” *[http://source.android.com/devices/tech/security/se-linux.html](http://source.android.com/devices/tech/security/se-linux.html)*
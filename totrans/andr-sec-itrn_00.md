# Introduction

In a relatively short period of time, Android has become the world’s most popular mobile platform. Although originally designed for smartphones, it now powers tablets, TVs, and wearable devices, and will soon even be found in cars. Android is being developed at a breathtaking pace, with an average of two major releases per year. Each new release brings a better UI, performance improvements, and a host of new user-facing features which are typically blogged about and dissected in excruciating detail by Android enthusiasts.

One aspect of the Android platform that has seen major improvements over the last few years, but which has received little public attention, is security. Over the years, Android has become more resistant to common exploit techniques (such as buffer overflows), its application isolation (sandboxing) has been reinforced, and its attack surface has been considerably reduced by aggressively decreasing the number of system processes that run as root. In addition to these exploit mitigations, recent versions of Android have introduced major new security features such as restricted user support, full-disk encryption, hardware-backed credential storage, and support for centralized device management and provisioning. Even more enterprise-oriented features and security improvements such as managed profile support, improved full-disk encryption, and support for biometric authentication have been announced for the next Android release (referred to as *Android L* as I write this).

As with any new platform feature, discussing cutting-edge security improvements is exciting, but it’s arguably more important to understand Android’s security architecture from the bottom up because each new security feature builds upon and integrates with the platform’s core security model. Android’s sandboxing model (in which each application runs as a separate Linux user and has a dedicated data directory) and permission system (which requires each application to explicitly declare the platform features it requires) are fairly well understood and documented. However, the internals of other fundamental platform features that have an impact on device security, such as package management and code signing, are largely treated as a black box beyond the security research community.

One of the reasons for Android’s popularity is the relative ease with which a device can be “flashed” with a custom build of Android, “rooted” by applying a third-party update package, or otherwise customized. Android enthusiast forums and blogs feature many practical “How to” guides that take users through the steps necessary to unlock a device and apply various customization packages, but they offer very little structured information about how such system updates operate under the hood and what risks they carry.

This books aims to fill these gaps by providing an exploration of how Android works by describing its security architecture from the bottom up and delving deep into the implementation of major Android subsystems and components that relate to device and data security. The coverage includes broad topics that affect all applications, such as package and user management, permissions and device policy, as well as more specific ones such as cryptographic providers, credential storage, and support for secure elements.

It’s not uncommon for entire Android subsystems to be replaced or rewritten between releases, but security-related development is conservative by nature, and while the described behavior might be changed or augmented across releases, Android’s core security architecture should remain fairly stable in future releases.

# Who This Book Is For

This book should be useful to anyone interested in learning more about Android’s security architecture. Both security researchers looking to evaluate the security level of Android as a whole or of a specific subsystem and platform developers working on customizing and extending Android will find the high-level description of each security feature and the provided implementation details to be a useful starting point for understanding the underlying platform source code. Application developers can gain a deeper understanding of how the platform works, which will enable them to write more secure applications and take better advantage of the security-related APIs that the platform provides. While some parts of the book are accessible to a non-technical audience, the bulk of the discussion is closely tied to Android source code or system files, so familiarity with the core concepts of software development in a Unix environment is useful.

# Prerequisites

The book assumes basic familiarity with Unix-style operating systems, preferably Linux, and does not explain common concepts such as processes, user groups, file permissions, and so on. Linux-specific or recently added OS features (such as capability and mount namespaces) are generally introduced briefly before discussing Android subsystems that use them. Most of the presented platform code comes from core Android daemons (usually implemented in C or C++) and system services (usually implemented in Java), so basic familiarity with at least one of these languages is also required. Some code examples feature sequences of Linux system calls, so familiarity with Linux system programming can be helpful in understanding the code, but is not absolutely required. Finally, while the basic structure and core components (such as activities and services) of Android apps are briefly described in the initial chapters, basic understanding of Android development is assumed.

# Android Versions

The description of Android’s architecture and implementation in this book (except for several proprietary Google features) is based on source code publicly released as part of the Android Open Source Project (AOSP). Most of the discussion and code excerpts reference Android 4.4, which is the latest publicly available version released with source code at the time of this writing. The master branch of AOSP is also referenced a few times, because commits to master are generally a good indicator of the direction future Android releases will take. However, not all changes to the master branch are incorporated in public releases as is, so it’s quite possible that future releases will change and even remove some of the presented functionality.

A developer preview version of the next Android release (Android L, mentioned earlier) was announced shortly after the draft of this book was completed. However, as of this writing, the full source code of Android L is not available and its exact public release date is unknown. While the preview release does include some new security features, such as improvements to device encryption, managed profiles, and device management, none of these features are final and so are subject to change. That is why this book does not discuss any of these new features. Although we could introduce some of Android L’s security improvements based on their observed behavior, without the underlying source code, any discussion about their implementation would be incomplete and speculative.

# How Is This Book Organized?

This book consists of 13 chapters that are designed to be read in sequence. Each chapter discusses a different aspect or feature of Android security, and subsequent chapters build on the concepts introduced by their predecessors. Even if you’re already familiar with Android’s architecture and security model and are looking for details about a specific topic, you should at least skim [Chapter 1](ch01.html "Chapter 1. Android’s Security Model") through [Chapter 3](ch03.html "Chapter 3. Package Management") because the topics they cover form the foundation for the rest of the book.

*   **[Chapter 1](ch01.html "Chapter 1. Android’s Security Model")** gives a high-level overview of Android’s architecture and security model.

*   **[Chapter 2](ch02.html "Chapter 2. Permissions")** describes how Android permissions are declared, used, and enforced by the system.

*   **[Chapter 3](ch03.html "Chapter 3. Package Management")** discusses code signing and details how Android’s application installation and management process works.

*   **[Chapter 4](ch04.html "Chapter 4. User Management")** explores Android’s multi-user support and describes how data isolation is implemented on multi-user devices.

*   **[Chapter 5](ch05.html "Chapter 5. Cryptographic Providers")** gives an overview of the Java Cryptography Architecture (JCA) framework and describes Android’s JCA cryptographic providers.

*   **[Chapter 6](ch06.html "Chapter 6. Network Security and PKI")** introduces the architecture of the Java Secure Socket Extension (JSSE) framework and delves into its Android implementation.

*   **[Chapter 7](ch07.html "Chapter 7. Credential Storage")** explores Android’s credential store and introduces the APIs it provides to applications that need to store cryptographic keys securely.

*   **[Chapter 8](ch08.html "Chapter 8. Online Account Management")** discusses Android’s online account management framework and shows how support for Google accounts is integrated into Android.

*   **[Chapter 9](ch09.html "Chapter 9. Enterprise Security")** presents Android’s device management framework, details how VPN support is implemented, and delves into Android’s support for the Extensible Authentication Protocol (EAP).

*   **[Chapter 10](ch10.html "Chapter 10. Device Security")** introduces verified boot, disk encryption, and Android’s lockscreen implementation, and shows how secure USB debugging and encrypted device backups are implemented.

*   **[Chapter 11](ch11.html "Chapter 11. NFC and Secure Elements")** gives an overview of Android’s NFC stack, delves into secure element (SE) integration and APIs, and introduces host-based card emulation (HCE).

*   **[Chapter 12](ch12.html "Chapter 12. Selinux")** starts with a brief introduction to SELinux’s architecture and policy language, details the changes made to SELinux in order to integrate it in Android, and gives an overview of Android’s base SELinux policy.

*   **[Chapter 13](ch13.html "Chapter 13. System Updates and Root Access")** discusses how Android’s bootloader and recovery OS are used to perform full system updates, and details how root access can be obtained on both engineering and production Android builds.

# Conventions

Because the main topic of this book is Android’s architecture and implementation, it contains multiple code excerpts and file listings, which are extensively referenced in the sections that follow each listing or code example. A few format conventions are used to set those references (which typically include multiple OS or programming language constructs) apart from the rest of the text.

Commands; function and variable names; XML attributes; and SQL object names are set in `monospace` (for example: “the `id` command,” “the `getCallingUid()` method,” “the `name` attribute,” and so on). The names of files and directories, Linux users and groups, processes, and other OS objects are set in *italic* (for example: “the *packages.xml* file,” “the *system* user,” “the *vold* daemon,” and so on). String literals are also set in *italic* (for example: “the *AndroidOpenSSL* provider”). If you use such string literals in a program, you typically need to enclose them in double or single quotes (for example: `Signature.getInstance("SHA1withRSA", "AndroidOpenSSL")`).

Java class names are typically in their unqualified format without the package name (for example: “the `Binder` class”); fully qualified names are only used when multiple classes with the same name exist in the discussed API or package, or when specifying the containing package is otherwise important (for example: “the `javax.net.ssl.SSLSocketFactory` class”). When referenced in the text, function and method names are shown with parentheses, but their parameters are typically omitted for brevity (for example: “the `getInstance()` factory method”). See the relevant reference documentation for the full function or method signature.

Most chapters include diagrams that illustrate the architecture or structure of the discussed security subsystem or component. All diagrams follow an informal “boxes and arrows” style and do not conform strictly to a particular format. That said, most diagrams borrow ideas from UML class and deployment diagrams, and boxes typically represent classes or objects, while arrows represent dependency or communication paths.
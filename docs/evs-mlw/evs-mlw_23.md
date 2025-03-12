<hgroup>

# <samp class="SANS_Futura_Std_Bold_Condensed_B_11">B</samp> <samp class="SANS_Dogma_OT_Bold_B_11">用于规避的 WINDOWS 函数</samp>

</hgroup>

![](img/opener.jpg)

本附录描述了在本书中讨论的某些规避技术中常用的 Windows 函数。虽然这不是威胁行为者可能滥用的函数的全面列表，但这些是我认为在恶意软件分析中最有趣或最重要的函数，值得熟悉。

请注意，这些函数是去掉了它们的 *A* 和 *W* 后缀。例如，<samp class="SANS_TheSansMonoCd_W5Regular_11">CreateFileW</samp> 只列为 <samp class="SANS_TheSansMonoCd_W5Regular_11">CreateFile</samp>。此外，一些函数有 *Nt* 和 *Zw* 两个变体，如 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtLoadDriver</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">ZwLoadDriver</samp>，但这里只列出了 *Nt* 变体。有关这些变体的更多信息，请参见 第一章。

您可以在 [*https://<wbr>malapi<wbr>.io*](https://malapi.io) 找到常见滥用函数的更完整列表。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">AddAtom</samp>

将字符串添加到本地原子表中。可用作某些进程注入技术的一部分，如原子轰炸。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">AddVectoredExceptionHandler</samp>

注册一个新的向量化异常处理程序。可用于滥用异常进行反分析和反调试。替代函数是 <samp class="SANS_TheSansMonoCd_W5Regular_11">RtlAddVectoredExceptionHandler</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">AdjustTokenPrivileges</samp>

启用或禁用访问令牌的权限。可以被滥用来提升权限。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">BCrypt*</samp>

请参见 <samp class="SANS_TheSansMonoCd_W5Regular_11">Crypt*</samp> 函数。所有以 <samp class="SANS_TheSansMonoCd_W5Regular_11">BCrypt*</samp> 开头的函数（如 <samp class="SANS_TheSansMonoCd_W5Regular_11">BCryptEncrypt</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">BCryptDestroyKey</samp>）与它们对应的 <samp class="SANS_TheSansMonoCd_W5Regular_11">Crypt*</samp> 函数（如 <samp class="SANS_TheSansMonoCd_W5Regular_11">CryptEncrypt</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">CryptDestroyKey</samp>）对齐。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">BlockInput</samp>

阻止输入到达应用程序。可以作为反调试技术来阻止与调试器的交互。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CallNtPowerInformation</samp>

返回诸如电池状态和上次睡眠时间等信息，这些信息可用于推断系统是否为虚拟机。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CheckRemoteDebuggerPresent</samp>

如果当前进程正在被调试，则返回非零值；否则返回零。可用于检测正在使用的调试器。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CloseHandle</samp>

关闭一个打开的句柄。可以作为反调试技术，在特定情况下使某些调试器崩溃。替代方法是现已弃用的 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtClose</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateFile</samp>

获取文件句柄或创建新文件。可用于多种用途，包括虚拟机和沙盒检测（例如，查找与虚拟机监控器相关的文件和管道）。替代方法是 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtCreateFile</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateFileTransacted</samp>

创建或打开一个文件，作为 NTFS 事务操作。可用于进程操控，例如进程双重化。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateMutex(Ex)</samp>

打开一个互斥对象或创建一个新的互斥。可用于枚举与虚拟机监控器相关的互斥对象，作为虚拟机和沙盒检测技术的一部分。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateProcess</samp>

创建一个新进程，通常作为进程注入的一部分或解包过程中调用。替代方法包括 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtCreateProcess(Ex)</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">CreateProcessInternal</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtCreateUserProcess</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateProcessWithToken</samp>

创建一个新进程，并将现有令牌的权限分配给该进程。可以被滥用用于提升权限和绕过防御。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateRemoteThread</samp>

在另一个进程的地址空间中执行新线程，通常作为各种进程注入技术的一部分。替代方法包括 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtCreateThreadEx</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">RtlCreateUserThread</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateService</samp>

创建一个服务。可以用于持久化或加载恶意内核模块。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateToolhelp32Snapshot</samp>

创建当前系统上正在运行的进程的快照。可以用于定位系统中的进程进行注入或虚拟机检测。通常在调用 <samp class="SANS_TheSansMonoCd_W5Regular_11">GetProcess32First</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">GetProcess32Next</samp> 之前调用。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">CreateTransaction</samp>

创建一个新的 NTFS 事务对象。另一个可选的函数是<samp class="SANS_TheSansMonoCd_W5Regular_11">NtCreateTransaction</samp>函数。*另请参见* <samp class="SANS_TheSansMonoCd_W5Regular_11">CreateFileTransacted</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">Crypt*</samp>

以<samp class="SANS_TheSansMonoCd_W5Regular_11">Crypt</samp>开头的函数（例如<samp class="SANS_TheSansMonoCd_W5Regular_11">CryptEncrypt</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">CryptDecrypt</samp>、和<samp class="SANS_TheSansMonoCd_W5Regular_11">CryptCreateHash</samp>）用于各种加密操作，如加密和数据哈希，通常用于混淆和规避防御。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">DebugActiveProcess</samp>

使调试器能够附加到一个活动进程。可用于检测调试器。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">DeleteFile</samp>

删除文件或目录。可通过删除它们来隐藏磁盘上的痕迹。另一个可选函数是<samp class="SANS_TheSansMonoCd_W5Regular_11">NtDeleteFile</samp>函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">DeviceIOControl</samp>

允许用户空间的进程向内核空间的驱动程序发送控制码。通常被 Rootkit 用来向恶意内核驱动发送控制码。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">DsGetDcName</samp>

检索系统域控制器的名称，常用于检测系统是否属于某个域，以便进行上下文感知、定向攻击或沙箱检测。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">DuplicateToken(Ex)</samp>

创建一个“副本”令牌并分配给另一个进程。通常会跟随一个类似于<samp class="SANS_TheSansMonoCd_W5Regular_11">ImpersonateLoggedOnUser</samp>的函数调用，作为提升权限和规避防御的一部分。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">EnumDisplayMonitors</samp>

识别系统中配置的监视器数量，以推断系统是虚拟机还是沙箱。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">EnumServiceStatus(Ex)</samp>

枚举系统上的服务。可用于识别与虚拟机相关的服务，以进行虚拟机检测。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">EnumSystemFirmwareTables</samp>

枚举系统固件表。可用于识别系统硬件并检测虚拟机。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">EnumWindows</samp>

枚举打开的窗口。可用于检测恶意软件分析工具和调试器。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">ExitProcess</samp>

结束一个进程，并可作为反分析技术使用。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">ExitWindows(Ex)</samp>

注销当前用户账户或关闭系统。可作为反分析和反沙箱技术使用。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">FindFirstFile(Ex)</samp>

枚举文件系统中的文件。可用于定位与虚拟机和沙箱检测相关的虚拟化程序文件。在调用 <samp class="SANS_TheSansMonoCd_W5Regular_11">FindNextFile</samp> 之前执行，该函数遍历系统中的每个文件。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">FindFirstUrlCacheEntry(Ex)</samp>

枚举浏览器缓存。缺少浏览器缓存数据可能表示虚拟机或沙箱环境。在调用 <samp class="SANS_TheSansMonoCd_W5Regular_11">FindNextUrlCacheEntry(Ex)</samp> 之前执行。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">FindWindow(Ex)</samp>

定位某个特定的窗口，例如特定的分析工具或调试器。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">FltEnumerateFilters</samp>

可供 rootkit 用于枚举系统中的迷你过滤器驱动程序，有时在安装钩子之前使用。替代方案是 <samp class="SANS_TheSansMonoCd_W5Regular_11">FltEnumerateInstances</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">FltGetFilterFromName</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">FltRegisterFilter</samp>

注册一个新的迷你过滤器驱动程序。可能在尝试安装迷你过滤器驱动程序的 rootkit 中看到。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetAdaptersAddresses</samp>

检索主机网络接口的 IP 地址和 MAC 地址。可能被滥用来进行虚拟机和沙箱检测。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetAsyncKeyState</samp>

检索某个键盘按键的状态。可用于沙箱规避（例如，等待某个键的按下）。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetComputerName(Ex)</samp>

检索系统的计算机名称，有时用于识别与沙箱相关的计算机名称。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetCursorPos</samp>

获取当前鼠标光标的位置。可用于人机交互检测，以规避沙箱。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetDiskFreeSpace(Ex)</samp>

返回系统上的空闲磁盘空间，可用于检测分析环境，特别是当虚拟机配置有较小的磁盘空间时。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetForegroundWindow</samp>

获取活动前景窗口的信息，有时用于分析工具检测或规避沙箱。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetKeyboardLayout</samp>

返回主机的活动键盘语言，有时用于目标分析。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetKeyboardLayoutList</samp>

返回主机上安装的所有键盘语言的完整列表。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetLastError</samp>

检索调用线程的最后错误值。可以与 <samp class="SANS_TheSansMonoCd_W5Regular_11">SetLastError</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">OutputDebugString</samp> 结合使用，用于检测调试器以及其他反分析目的。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetLocalTime</samp>

获取系统的当前日期和时间。可以用于检测调试或其他反分析技术，如定时炸弹。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetLogicalProcessorInformation(Ex)</samp>

返回关于系统处理器的信息。可以用来识别虚拟机（VM）或沙箱环境。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetModuleFileName(Ex)</samp>

检索包含特定模块的文件路径，或者检索当前进程的可执行文件路径。可以用来枚举已加载的模块，如分析工具注入的异常模块，或检索自身可执行文件的路径。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetModuleHandle(Ex)</samp>

返回已加载模块的句柄。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetPhysicallyInstalledSystemMemory</samp>

返回系统的物理内存大小。可以被滥用来识别虚拟机（VM）或沙箱环境。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetProcAddress</samp>

获取函数的过程地址。可以与 <samp class="SANS_TheSansMonoCd_W5Regular_11">LoadLibrary</samp> 结合使用，动态加载库和函数，用于端点防御规避和反分析。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetSystemFirmwareTable</samp>

检索系统中的各种固件表。可以用作虚拟机（VM）和沙箱检测技术，通过搜索与虚拟机监控程序（hypervisor）相关的固件。另一种选择是 <samp class="SANS_TheSansMonoCd_W5Regular_11">EnumSystemFirmwareTables</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetSystemInfo</samp>

返回关于系统的信息。可以用来检测虚拟机（VM）环境。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetSystemMetrics</samp>

返回关于系统指标和配置的信息。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetSystemTime</samp>

*见* <samp class="SANS_TheSansMonoCd_W5Regular_11">GetLocalTime</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetTcpTable</samp>

返回系统的 IPv4 TCP 连接表。可用于检测没有连接网络或互联网的虚拟机（VM）或沙箱。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetThreadContext</samp>

检索当前线程的上下文。可以用来检测硬件断点。另一种选择是 <samp class="SANS_TheSansMonoCd_W5Regular_11">Wow64GetThreadContext</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetThreadLocale</samp>

返回正在运行的线程的区域信息，例如当前使用的语言。可以用于目标分析。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetTickCount</samp>

检索自系统启动以来已过去的毫秒数。可用于多种反分析技术，如调试器检测。替代方法是 <samp class="SANS_TheSansMonoCd_W5Regular_11">GetTickCount64</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetUserDefaultUILanguage</samp>

返回当前登录用户的界面语言。可用于与 <samp class="SANS_TheSansMonoCd_W5Regular_11">GetThreadLocale</samp> 相同的目的。替代方法包括 <samp class="SANS_TheSansMonoCd_W5Regular_11">GetSystemDefaultUILanguage</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">GetSystemDefaultLCID</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">GetUserDefaultLCID</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">GetProcessPreferredUILanguages</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetVersion(Ex)</samp>

检索操作系统的版本信息。可用于目标配置文件分析。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GetWindowText</samp>

获取窗口的标题文本。可用于检测恶意软件分析工具。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GlobalAddAtom(Ex)</samp>

将字符串添加到全局原子表中。*另见* <samp class="SANS_TheSansMonoCd_W5Regular_11">AddAtom</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">GlobalGetAtomName</samp>

检索指定全局原子的字符串。*另见* <samp class="SANS_TheSansMonoCd_W5Regular_11">AddAtom</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">ImpersonateLoggedOnUser</samp>

允许调用线程模拟登录用户的安全上下文。*另见* <samp class="SANS_TheSansMonoCd_W5Regular_11">DuplicateToken(Ex)</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">InitiateShutdown</samp>

关闭并重启系统。可用作反分析和反沙箱技术。替代方法是 <samp class="SANS_TheSansMonoCd_W5Regular_11">InitiateSystemShutdown(Ex)</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">InternetConnect</samp>

打开 FTP 或 HTTP 网络连接。可用于多种规避技术，如判断系统是否连接到互联网，以检测沙箱或虚拟机。常与 <samp class="SANS_TheSansMonoCd_W5Regular_11">InternetOpen</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">InternetReadFile</samp> 结合使用。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">IsDebuggerPresent</samp>

检查调用进程是否正在被调试。*另见* <samp class="SANS_TheSansMonoCd_W5Regular_11">CheckRemoteDebuggerPresent</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">IsProcessorFeaturePresent</samp>

返回各种处理器功能的状态，这些功能可以指示虚拟机（VM）。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">LoadLibrary</samp>

将模块加载到调用进程的地址空间中。*参见* <samp class="SANS_TheSansMonoCd_W5Regular_11">GetProcAddress</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">Module32First</samp>

获取关于进程中加载的第一个模块的信息。可以与 <samp class="SANS_TheSansMonoCd_W5Regular_11">Module32Next</samp> 一起使用，枚举和识别与分析工具相关的模块。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtCreateTransaction</samp>

创建一个新的 NTFS 事务对象。可用于进程操作技术，如进程伪装（process doppelganging）。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtLoadDriver</samp>

将驱动程序加载到系统中。可以调用该功能来加载恶意的内核模块。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtMapViewOfSection</samp>

将一个视图映射到目标进程的地址空间中。可用于手动将库或代码映射到内存中，作为进程注入的一部分。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtOpenDirectoryObject</samp>

可用于查询系统上的设备和驱动程序对象。有时用来定位虚拟机相关的文物，作为虚拟机检测的一部分。另一个替代方案是 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtQueryDirectoryObject</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtQueryInformationProcess</samp>

返回大量有关目标进程的信息。可以用来识别附加的调试器。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtQueryObject</samp>

返回有关不同操作系统对象的信息。可用于识别调试器对象，指示恶意软件正在被调试。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtQuerySystemInformation</samp>

返回许多不同的系统信息。可以用于枚举固件表以识别虚拟机或沙箱。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtQuerySystemTime</samp>

*参见* <samp class="SANS_TheSansMonoCd_W5Regular_11">GetLocalTime</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtSetInformationThread</samp>

设置线程的优先级。可用于隐藏代码执行，避免调试器检测，或者在某些情况下导致调试器崩溃。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">NtUnmapViewOfSection</samp>

从内存中卸载一个视图。有时用作进程注入技术的一部分。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">OpenMutex</samp>

打开一个互斥体对象。*参见* <samp class="SANS_TheSansMonoCd_W5Regular_11">CreateMutex</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">OpenProcess</samp>

打开进程对象，通常是进程注入的前兆。另一个替代方案是 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtOpenProcess</samp> 函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">OpenProcessToken</samp>

打开进程的访问令牌，通常是特权提升技术的前兆。*另见* <samp class="SANS_TheSansMonoCd_W5Regular_11">AdjustTokenPrivileges</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">OpenService</samp>

打开一个服务。可以用来识别与沙箱和虚拟机监控器相关的服务。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">OpenThread</samp>

打开一个线程对象。可以用于进程注入技术，例如线程劫持。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">OutputDebugString</samp>

将字符串发送到调试器。可以用于反调试目的。*另见* <samp class="SANS_TheSansMonoCd_W5Regular_11">GetLastError</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">PostMessage</samp>

当传递 <samp class="SANS_TheSansMonoCd_W5Regular_11">WS_CLOSE</samp> 参数到窗口句柄时，关闭应用程序窗口。可以作为反分析技术使用。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">Process32First</samp>

收集进程快照中的第一个进程的信息。*另见* <samp class="SANS_TheSansMonoCd_W5Regular_11">CreateToolhelp32Snapshot</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">Process32Next</samp>

收集进程快照中的下一个进程的信息。*另见* <samp class="SANS_TheSansMonoCd_W5Regular_11">CreateToolhelp32Snapshot</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">PsLookupProcessByProcessID</samp>

获取指向进程 <samp class="SANS_TheSansMonoCd_W5Regular_11">EPROCESS</samp> 结构的指针。有时被 rootkit 用来为规避技术（如 DKOM）做准备。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">PsSetCreateProcessNotifyRoutine(Ex)</samp>

注册一个驱动程序回调函数，当任何新进程被创建或终止时触发。有时被 rootkit 用来监视进程创建。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">PsSetCreateThreadNotifyRoutine(Ex)</samp>

与 <samp class="SANS_TheSansMonoCd_W5Regular_11">PsSetCreateProcessNotifyRoutine(Ex)</samp> 类似，但用于线程创建。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">PsSetLoadImageNotifyRoutine(Ex)</samp>

注册一个回调函数，当进程将图像加载到内存中时触发，例如加载 DLL 模块，或者当加载新驱动程序时触发。有时被 rootkit 用来监视模块加载。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">QueryPerformanceCounter</samp>

查询处理器的性能计数器并返回当前值。可以作为反调试和虚拟机检测技术的一部分使用。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">QueueUserAPC</samp>

排队一个新的异步过程调用，有时用于进程注入技术，例如 APC 注入。一个替代函数是 <samp class="SANS_TheSansMonoCd_W5Regular_11">NtQueueApcThread</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">ReadProcessMemory</samp>

从目标进程的内存区域读取数据。可用于多种目的，例如检查进程内存中的钩子，作为反钩子技术的一部分。另一种选择是<samp class="SANS_TheSansMonoCd_W5Regular_11">NtReadVirtualMemory</samp>函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">RegEnumKey(Ex)</samp>

枚举一个注册表键。可用于虚拟机检测或识别感兴趣的注册表键。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">RegEnumValue</samp>

枚举一个注册表键值。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">RegOpenKey(Ex)</samp>

打开一个注册表键用于读写操作。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">ResumeThread</samp>

恢复线程执行，常用于进程注入，例如进程空洞技术。另一种选择是<samp class="SANS_TheSansMonoCd_W5Regular_11">NtResumeThread</samp>函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">RollbackTransaction</samp>

回滚一个 NTFS 事务，并用于进程操作，例如在进程双重技术中。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">RtlCopyMemory</samp>

将源缓冲区的内容从内存复制到另一个内存区域。可被调用将恶意代码写入内存，如注入钩子。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">RtlQueryProcessHeapInformation</samp>

返回有关当前进程堆的信息。可用于检测调试器。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">RtlZeroMemory</samp>

将一块内存区域填充为零。可作为反取证和防御规避技术的一部分使用。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">SetFileAttributes</samp>

为文件或目录设置各种属性。可通过<samp class="SANS_TheSansMonoCd_W5Regular_11">hidden</samp>属性来隐藏文件和目录。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">SetFileTime</samp>

为文件或目录设置各种时间戳。可用于伪造文件时间戳（时间戳篡改）。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">SetPriorityClass</samp>

设置进程的优先级。可被滥用，通过降低终端防御进程的优先级来尝试规避它们。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">SetThreadContext</samp>

设置线程的上下文，有时用于进程注入技术，特别是进程空洞技术。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">SetUnhandledExceptionFilter</samp>

允许调用程序覆盖顶级异常处理程序。可作为反调试和隐蔽代码执行技术的一部分使用。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">SetWindowsHookEx</samp>

安装一个应用程序定义的钩子。可用于多种目的，如钩住键盘和鼠标事件及注入恶意代码。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">Sleep(Ex)</samp>

挂起线程的执行一段指定的时间。可以用于许多恶意目的，如沙箱规避和各种反调试技术。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">StartService</samp>

启动系统上的服务。可以用来建立持久性或加载恶意模块。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">SuspendThread</samp>

挂起一个线程，并在某些进程注入技术中使用，如线程劫持。另一种选择是<samp class="SANS_TheSansMonoCd_W5Regular_11">Wow64SuspendThread</samp>函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">TerminateProcess</samp>

终止指定的进程。可用作一种反分析技术。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">VirtualAlloc(Ex)</samp>

分配（保留或提交）一个虚拟内存区域，并且是各种进程注入技术的一部分。另一种选择是<samp class="SANS_TheSansMonoCd_W5Regular_11">NtAllocateVirtualMemory</samp>函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">VirtualQuery(Ex)</samp>

返回关于内存区域的信息。可以用来检测硬件和内存断点。另一种选择是<samp class="SANS_TheSansMonoCd_W5Regular_11">NtQueryVirtualMemory</samp>函数。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">WriteProcessMemory</samp>

向进程中的内存区域写入数据，并作为各种进程注入技术的一部分使用。另一种选择是<samp class="SANS_TheSansMonoCd_W5Regular_11">NtWriteVirtualMemory</samp>函数。

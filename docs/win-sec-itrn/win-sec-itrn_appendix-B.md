<hgroup>

# <samp class="SANS_Futura_Std_Bold_Condensed_B_11">B</samp> <samp class="SANS_Dogma_OT_Bold_B_11">SDDL SID 别名映射</samp>

</hgroup>

![](img/chapter.jpg)

第五章介绍了安全描述符定义语言（SDDL）格式，用于将安全描述符表示为字符串，并提供了一些 Windows 支持的、用于表示知名 SDDL SID 的两字符别名示例。尽管微软文档中有关于 SID 的 SDDL 格式，但并未提供单一资源列出所有短 SID 别名字符串。唯一可用的资源是 Windows SDK 中的 *sddl.h* 头文件。该头文件定义了程序员可以用来操作 SDDL 格式字符串的 Windows API，并提供了短 SID 别名字符串的列表。

表 B-1 包含了简短的别名以及它们所代表的名称和完整的 SID。该表格摘自 Windows 11 SDK 提供的头文件（操作系统版本为 22621），应当是撰写时的权威列表。请注意，某些 SID 别名仅在您连接到域网络时有效。您可以通过 SID 名称中的 *<DOMAIN>* 占位符来识别这些别名，您需要将其替换为系统连接的域名。同时，将 SDDL SID 字符串中的 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp> 占位符替换为唯一的域 SID。

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-1：</samp> <samp class="SANS_Futura_Std_Book_11">支持的 SDDL SID 别名到 SID 的映射</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">SID 别名</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">名称</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">SDDL SID</samp> |
| --- | --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">内建\访问控制协助操作员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-579</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AC</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">应用程序包权限\所有应用程序包</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-15-2-1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AN</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT 权限\匿名登录</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-7</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AO</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">内建\帐户操作员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-548</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AP</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\受保护用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-525</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AS</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">认证机构声明身份</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-18-1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\已认证用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-11</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">BA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">内置\管理员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-544</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">BG</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">内置\访客</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-546</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">BO</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">内置\备份操作员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-551</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">BU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">内置\用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-545</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\证书发布者</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-517</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CD</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">内置\证书服务 DCOM 访问</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-574</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CG</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">创建者组</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-3-1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CN</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\可克隆域控制器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-522</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CO</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">创建者所有者</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-3-0</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CY</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">内置\加密操作符</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-569</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\域管理员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-512</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DC</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\域计算机</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-515</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DD</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\域控制器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-516</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DG</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\域访客</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-514</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\域用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-513</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">EA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\企业管理员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-519</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ED</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\企业域控制器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-9</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">EK</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\企业密钥管理员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-527</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ER</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\事件日志读取器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-573</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ES</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\RDS 端点服务器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-576</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">HA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\Hyper-V 管理员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-578</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">HI</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">强制标签\高级强制级别</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-16-12288</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">IS</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\IIS_IUSRS</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-568</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">IU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\交互式</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">KA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\关键管理员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-526</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\管理员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-500</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LG</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\访客</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-501</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LS</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\本地服务</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-19</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\性能日志用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-559</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LW</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">强制标签\低强制级别</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-16-4096</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ME</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">强制标签\中等强制级别</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-16-8192</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">MP</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">强制标签\中级强制级别</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-16-8448</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">MS</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\RDS 管理服务器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-577</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">MU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\性能监视器用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-558</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">NO</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\网络配置操作员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-556</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">NS</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\NETWORK SERVICE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-20</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">NU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\NETWORK</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-2</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">OW</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">所有者权限</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-3-4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">PA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\组策略创建者所有者</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-520</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">PO</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\打印操作员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-550</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">PS</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\SELF</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-10</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">PU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\高级用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-547</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">RA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\RDS 远程访问服务器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-575</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">RC</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\RESTRICTED</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-12</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">RD</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\远程桌面用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-555</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">RE</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\复制器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-552</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">RM</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\远程管理用户</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-580</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">RO</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\只读域控制器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-498</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">RS</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\RAS 和 IAS 服务器</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-553</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">RU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\预 Windows 2000 兼容访问</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-554</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">SA</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11"><DOMAIN>\架构管理员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-21-</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><DOMAIN></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">-518</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">SI</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">强制标签\系统强制级别</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-16-16384</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">SO</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">BUILTIN\服务器操作员</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-32-549</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">SS</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">服务声明身份</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-18-2</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">SU</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\服务</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-6</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">SY</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\系统</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-18</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UD</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\用户模式驱动程序</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-84-0-0-0-0-0</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">WD</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">每个人</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-1-0</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">WR</samp> | <samp class="SANS_Futura_Std_Book_Oblique_I_11">NT AUTHORITY\写入限制</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">S-1-5-33</samp> |

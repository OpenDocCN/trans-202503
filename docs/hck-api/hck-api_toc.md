# 详细内容

1.  《黑客攻防：API 篇》好评

1.  封面

1.  版权

1.  致谢

1.  关于作者

1.  前言

1.  鸣谢

1.  简介

    1.  破解 Web API 的魅力

    1.  本书的研究方法

    1.  破解 API 餐厅

1.  第一部分：Web API 安全如何运作

    1.  第零章：准备进行安全测试

        1.  接收授权

        1.  API 测试中的威胁建模

        1.  你应该测试的 API 功能

            1.  API 身份验证测试

            1.  Web 应用防火墙

            1.  移动应用测试

            1.  API 文档审计

            1.  速率限制测试

        1.  限制与排除条款

            1.  云 API 的安全测试

            1.  拒绝服务测试

        1.  报告与修复测试

        1.  关于漏洞悬赏范围的说明

        1.  总结

    1.  第一章：Web 应用程序的工作原理

        1.  Web 应用程序基础

            1.  URL

            1.  HTTP 请求

            1.  HTTP 响应

            1.  HTTP 状态码

            1.  HTTP 方法

            1.  有状态与无状态 HTTP

        1.  Web 服务器数据库

            1.  SQL

            1.  NoSQL

        1.  API 在整体架构中的角色

        1.  总结

    1.  第二章：Web API 的结构

        1.  Web API 的工作原理

        1.  标准 Web API 类型

            1.  RESTful API

            1.  GraphQL

        1.  REST API 规范

        1.  API 数据交换格式

            1.  JSON

            1.  XML

            1.  YAML

        1.  API 身份验证

            1.  基本身份验证

            1.  API 密钥

            1.  JSON Web 令牌

            1.  HMAC

            1.  OAuth 2.0

            1.  无身份验证

        1.  API 实践：探索 Twitter 的 API

        1.  总结

    1.  第三章：常见 API 漏洞

        1.  信息披露

        1.  破损的对象级授权

        1.  破损的用户认证

        1.  过度的数据暴露

        1.  资源不足和速率限制

        1.  破损的功能级别授权

        1.  大规模赋值

        1.  安全配置错误

        1.  注入

        1.  不当资产管理

        1.  业务逻辑漏洞

        1.  总结

1.  第二部分：构建 API 测试实验室

    1.  第四章：你的 API 黑客系统

        1.  Kali Linux

        1.  使用 DevTools 分析 Web 应用

        1.  使用 Burp Suite 捕获和修改请求

            1.  设置 FoxyProxy

            1.  添加 Burp Suite 证书

            1.  浏览 Burp Suite

            1.  拦截流量

            1.  使用 Intruder 修改请求

        1.  在 Postman 中构建 API 请求，一个 API 浏览器

            1.  请求构建器

            1.  环境

            1.  集合

            1.  集合运行器

            1.  代码片段

            1.  测试面板

        1.  配置 Postman 与 Burp Suite 配合使用

        1.  补充工具

            1.  使用 OWASP Amass 进行侦察

            1.  使用 Kiterunner 发现 API 端点

            1.  使用 Nikto 扫描漏洞

            1.  使用 OWASP ZAP 扫描漏洞

            1.  使用 Wfuzz 进行模糊测试

            1.  使用 Arjun 发现 HTTP 参数

        1.  总结

        1.  **实验 #1：列举 REST API 中的用户帐户**

    1.  第五章：设置易受攻击的 API 目标

        1.  创建 Linux 主机

        1.  安装 Docker 和 Docker Compose

        1.  安装易受攻击的应用

            1.  完全荒谬的 API（crAPI）

            1.  OWASP DevSlop 的 Pixi

            1.  OWASP Juice Shop

            1.  Damn Vulnerable GraphQL 应用

        1.  添加其他易受攻击的应用

        1.  在 TryHackMe 和 HackTheBox 上黑客攻击 API

        1.  总结

        1.  **实验 #2：发现你的易受攻击的 API**

1.  第三部分：攻击 API

    1.  第六章：发现

        1.  被动侦察

            1.  被动侦察过程

            1.  Google 黑客技术

            1.  ProgrammableWeb 的 API 搜索目录

            1.  Shodan

            1.  OWASP Amass

            1.  GitHub 上暴露的信息

        1.  主动侦察

            1.  主动侦察过程

            1.  使用 Nmap 进行基线扫描

            1.  在 Robots.txt 中寻找隐藏路径

            1.  使用 Chrome DevTools 寻找敏感信息

            1.  使用 Burp Suite 验证 API

            1.  使用 OWASP ZAP 爬取 URI

            1.  使用 Gobuster 暴力破解 URI

            1.  使用 Kiterunner 发现 API 内容

        1.  总结

        1.  **实验 #3：执行黑盒测试的主动侦察**

    1.  第七章：端点分析

        1.  寻找请求信息

            1.  在文档中寻找信息

            1.  导入 API 规范

            1.  逆向工程 API

        1.  在 Postman 中添加 API 认证要求

        1.  分析功能性

            1.  测试预期使用

            1.  执行特权操作

            1.  分析 API 响应

        1.  发现信息泄露

        1.  寻找安全配置错误

            1.  冗长的错误信息

            1.  不安全的传输加密

            1.  有问题的配置

        1.  发现过度的数据暴露

        1.  发现业务逻辑漏洞

        1.  总结

        1.  **实验 #4：构建 crAPI 集合并发现过度的数据暴露**

    1.  第八章：攻击认证

        1.  经典认证攻击

            1.  密码暴力破解攻击

            1.  密码重置与多因素认证暴力破解攻击

            1.  密码喷射攻击

            1.  在暴力破解攻击中包含 Base64 认证

        1.  伪造令牌

            1.  手动负载分析

            1.  实时令牌捕获分析

            1.  暴力破解可预测令牌

        1.  JSON Web Token 滥用

            1.  识别与分析 JWT

            1.  None 攻击

            1.  算法切换攻击

            1.  JWT 破解攻击

        1.  总结

        1.  **实验 #5：破解 crAPI JWT 签名**

    1.  第九章：模糊测试

        1.  高效的模糊测试

            1.  选择模糊测试有效载荷

            1.  检测异常

        1.  广泛和深入的模糊测试

            1.  使用 Postman 进行广泛模糊测试

            1.  使用 Burp Suite 进行深度模糊测试

            1.  使用 Wfuzz 进行深度模糊测试

            1.  针对不当资源管理的广泛模糊测试

        1.  使用 Wfuzz 测试请求方法

        1.  深入模糊测试以绕过输入数据清理

        1.  进行目录遍历模糊测试

        1.  总结

        1.  **实验 #6：模糊测试不当资源管理漏洞**

    1.  第十章：利用授权漏洞

        1.  查找 BOLA

            1.  定位资源 ID

            1.  BOLA 的 A-B 测试

            1.  旁道 BOLA

        1.  查找 BFLA

            1.  BFLA 的 A-B-A 测试

            1.  在 Postman 中测试 BFLA

        1.  授权破解技巧

            1.  Postman 的集合变量

            1.  Burp Suite 的匹配和替换功能

        1.  总结

        1.  **实验 #7：查找另一个用户的车辆位置**

    1.  第十一章：大规模赋值

        1.  查找大规模赋值目标

            1.  账户注册

            1.  未授权访问组织

        1.  查找大规模赋值变量

            1.  在文档中查找变量

            1.  模糊测试未知变量

            1.  盲目大规模赋值攻击

        1.  使用 Arjun 和 Burp Suite Intruder 自动化大规模赋值攻击

        1.  结合 BFLA 和大规模赋值

        1.  总结

        1.  **实验 #8：修改在线商店中商品的价格**

    1.  第十二章：注入漏洞

        1.  发现注入漏洞

        1.  跨站脚本攻击 (XSS)

        1.  跨 API 脚本攻击 (XAS)

        1.  SQL 注入

            1.  手动提交元字符

            1.  SQLmap

        1.  NoSQL 注入

        1.  操作系统命令注入

        1.  总结

        1.  **实验室#9：使用 NoSQL 注入伪造优惠券**

1.  第四部分：现实世界中的 API 黑客攻击

    1.  第十三章：应用规避技术和速率限制测试

        1.  规避 API 安全控制

            1.  安全控制的工作原理

            1.  API 安全控制检测

            1.  使用临时账户

            1.  规避技术

            1.  在 Burp Suite 中自动化规避

            1.  使用 Wfuzz 自动化规避

        1.  测试速率限制

            1.  关于宽松速率限制的说明

            1.  路径绕过

            1.  伪造 Origin 头

            1.  在 Burp Suite 中轮换 IP 地址

        1.  总结

    1.  第十四章：攻击 GraphQL

        1.  GraphQL 请求与 IDE

        1.  主动侦察

            1.  扫描

            1.  在浏览器中查看 DVGA

            1.  使用开发者工具

        1.  逆向工程 GraphQL API

            1.  为 GraphQL 端点进行目录暴力破解

            1.  通过篡改 Cookie 启用 GraphiQL IDE

            1.  逆向工程 GraphQL 请求

            1.  通过内省逆向工程 GraphQL 集合

        1.  GraphQL API 分析

            1.  使用 GraphiQL 文档浏览器构造请求

            1.  使用 InQL Burp 扩展

        1.  模糊测试命令注入

        1.  总结

    1.  第十五章：数据泄露与漏洞奖励

        1.  漏洞事件

            1.  Peloton

            1.  USPS 知情可视化 API

            1.  T-Mobile API 泄露事件

        1.  漏洞奖励

            1.  良好 API 密钥的代价

            1.  私人 API 授权问题

            1.  星巴克：从未发生的泄露事件

            1.  Instagram 的 GraphQL BOLA 漏洞

        1.  总结

1.  结论

1.  附录 A：API 黑客检查清单

1.  附录 B：额外资源

    1.  第零章：为你的安全测试做准备

    1.  第一章：Web 应用程序的工作原理

    1.  第二章：Web API 的结构

    1.  第三章：常见的 API 漏洞

    1.  第四章：你的 API 黑客系统

    1.  第五章：设置易受攻击的 API 目标

    1.  第六章：发现

    1.  第七章：端点分析

    1.  第八章：攻击身份验证

    1.  第九章：模糊测试

    1.  第十章：利用授权漏洞

    1.  第十一章：批量赋值

    1.  第十二章：注入

    1.  第十三章：应用规避技术和速率限制测试

    1.  第十四章：攻击 GraphQL

    1.  第十五章：数据泄露和漏洞奖励计划

1.  索引

## **表格列表**

1.  表 0-1：漏洞奖励测试注意事项

1.  表 1-1：HTTP 响应码范围

1.  表 1-2：HTTP 方法

1.  表 1-3：关系型用户表

1.  表 1-4：关系型电子邮件表

1.  表 1-5：关系型权限表

1.  表 2-1：JSON 类型

1.  表 2-2：JWT 组件

1.  表 2-3：HMAC 算法

1.  表 4-1：开发者工具面板

1.  表 4-2：请求构建器面板

1.  表 5-1：具有漏洞 API 的其他系统

1.  表 5-2：已退役的具有 API 黑客组件的机器

1.  表 6-1：Google 查询参数

1.  表 6-2：GHDB 查询

1.  表 6-3：Shodan 查询参数

1.  表 7-1：API 文档约定

1.  表 8-1：潜在的 crAPI JWT 密钥

1.  表 10-1：资源的有效请求和等效的 BOLA 测试

1.  表 10-2：旁道 BOLA 泄露示例

1.  表 12-1：注入攻击中常用的操作系统命令

1.  表 13-1：Wfuzz 编码器示例

1.  表 13-2：Wfuzz `-s`选项用于限制请求速率

1.  表 13-3：Burp Suite Intruder 的资源池延迟选项，用于限制请求速率

## **插图列表**

1.  图 0-1：来自 https://developer.twitter.com/en/docs 的 Twitter HTTP 状态码

1.  图 0-2：Files.com 在 BugCrowd 上的漏洞奖励计划，旨在激励与 API 相关的发现

1.  图 2-1：一个示例的微服务架构和 API 网关

1.  图 2-2：GitHub 的 GraphiQL 界面

1.  图 2-3：NASA 用于生成 API 密钥的表单

1.  图 2-4：LinkedIn–Twitter OAuth 授权请求

1.  图 2-5：OAuth 过程的示意图

1.  图 2-6：Twitter API 搜索请求的渲染结果

1.  图 3-1：Cisco Webex Admin API 文档

1.  图 4-1：Chrome DevTools 网络面板

1.  图 4-2：DevTool 的性能标签页，显示 Twitter 应用与 Twitter API 交互的确切时刻

1.  图 4-3：下载 Burp Suite 的 CA 证书时应看到的登录页面

1.  图 4-4：Chrome 证书管理器，选择了 Authorities 标签

1.  图 4-5：Burp Suite 模块

1.  图 4-6：Burp Suite 中的拦截功能已开启。

1.  图 4-7：请求发送到 Twitter，并通过 Hackz 代理传送至 Burp Suite。

1.  图 4-8：通过 Burp Suite 拦截的 HTTP 请求到 Twitter

1.  图 4-9：Burp Suite Repeater

1.  图 4-10：对 api.twitter.com 的 Intruder 攻击

1.  图 4-11：Intruder Payloads，列出了密码列表

1.  图 4-12：Intruder 攻击类型

1.  图 4-13：配置了 Hackz 和 Postman 代理的 FoxyProxy

1.  图 4-14：Postman 的主登录页面，显示来自 API 集合的响应

1.  图 4-15：Postman 请求构建器

1.  图 4-16：Postman 的键值头部

1.  图 4-17：Postman 请求和响应面板

1.  图 4-18：Postman 中的创建新面板

1.  图 4-19：Postman 中的管理环境窗口，显示变量 `admin_creds` 当前值为 `This_``i``s_hidd3n`

1.  图 4-20：使用导入面板中的 Link 标签在 Postman 中导入 API 规范

1.  图 4-21：Collections 侧边栏，显示导入的《帝国时代 II》API GET 请求

1.  图 4-22：在 Postman 中编辑一个集合

1.  图 4-23：《帝国时代 II》API 集合变量

1.  图 4-24：更新后的 `baseURL` 变量

1.  图 4-25：在 Postman 中成功使用《帝国时代 II》API 集合

1.  图 4-26：Postman 集合运行器

1.  图 4-27：AOE2 公共 API 测试

1.  图 4-28：Postman 的代理设置，配置为与 Burp Suite 交互

1.  图 4-29：在 https://reqres.in 找到的 API 文档，包含请求 `user id:2` 的说明

1.  图 4-30：使用 Postman 发出的标准 API 请求，从 https://reqres.in 数据库中检索用户 1

1.  图 4-31：使用 Postman 拦截的请求，用于检索用户 1

1.  图 4-32：Burp Suite 的 Intruder 配置，攻击位置设置在路径中的 *UserID* 部分

1.  图 4-33：Intruder 的 Payloads 选项卡，负载类型设置为数字

1.  图 5-1：crAPI 商店

1.  图 5-2：Pixi 登录页面

1.  图 5-3：OWASP Juice Shop

1.  图 5-4：GraphiQL IDE 网页，托管在 5000 端口

1.  图 5-5：OWASP Juice Shop

1.  图 5-6：拦截的 Juice Shop HTTP 请求

1.  图 6-1：Google API 黑客搜索的结果，包括多个包含暴露 API 密钥的网页

1.  图 6-2：ProgrammableWeb API 目录

1.  图 6-3：ProgrammableWeb 的 Medici Bank API 目录列表

1.  图 6-4：Medici Bank API 规范部分提供了 API 端点位置、API 门户位置和 API 认证模型。

1.  图 6-5：Shodan 搜索结果

1.  图 6-6：OWASP Amass 可视化，使用 `-d3` 导出 Amass 结果的 HTML 文件，用于 *twitter.com*

1.  图 6-7：GitHub 代码选项卡的示例，你可以在其中查看不同文件的源代码

1.  图 6-8：分割按钮允许你将之前的代码（左侧）与更新后的代码（右侧）分开。

1.  图 6-9：一个公开的 GitHub 问题，提供了应用程序代码中暴露的 API 密钥的确切位置

1.  图 6-10：开发者在拉取请求中的评论可能暴露私密的 API 密钥。

1.  图 6-11：Files Changed 选项卡演示了对代码的提议更改。

1.  图 6-12：DevTools 网络选项卡中的“在源中打开”选项

1.  图 6-13：在此页面源的第 4,197 行，正在使用一个 API。

1.  图 6-14：DevTools 中的内存面板

1.  图 6-15：内存快照的搜索结果

1.  图 6-16：DevTools 中的性能记录

1.  图 6-17：Web 服务器返回 HTTP 401 未授权错误。

1.  图 6-18：设置为使用 OWASP ZAP 扫描目标的自动化扫描

1.  图 6-19：在 ZAP 自动扫描结果中搜索 API 的强大功能

1.  图 6-20：启动 Burp Suite 的手动探索选项

1.  图 6-21：这是你启动 ZAP HUD 时看到的第一个屏幕。

1.  图 6-22：crAPI 登录页面

1.  图 6-23：crAPI 主要 JavaScript 源文件

1.  图 6-24：使用 Burp Suite 拦截的 crAPI 注册请求

1.  图 7-1：完整构造的请求到 Pixi 端点 */api/{picture_id}/likes*

1.  图 7-2：Pixi Swagger 定义页面

1.  图 7-3：Postman 中的导入链接功能

1.  图 7-4：导入的 Pixi 应用集合

1.  图 7-5：Postman 集合变量编辑器

1.  图 7-6：Postman 的工作区部分

1.  图 7-7：在新 Postman 集合中的添加请求选项

1.  图 7-8：Postman 捕获请求和 cookie 窗口

1.  图 7-9：有序的 crAPI 集合

1.  图 7-10：成功的 Pixi API 注册请求

1.  图 7-11：使用 Burp Suite 拦截的 Kiterunner 请求

1.  图 7-12：设置 `x-access-token` 作为 JWT 的变量

1.  图 7-13：Pixi 管理端点的要求

1.  图 7-14：Wireshark 捕获的用户令牌在 HTTP 请求中的信息

1.  图 7-15：Tiredful API 的调试页面

1.  图 7-16：crAPI 账户注册页面

1.  图 7-17：拦截的 crAPI 身份验证请求

1.  图 7-18：Postman 中的 crAPI 注册请求

1.  图 7-19：成功登录 crAPI 后拦截的请求

1.  图 7-20：Postman 集合编辑器

1.  图 8-1：配置 Burp Suite Intruder，并设置强力破解负载类型

1.  图 8-2：使用 Intruder 进行的凭证喷洒攻击

1.  图 8-3：Burp Suite Intruder 示例负载，用于集群炸弹攻击

1.  图 8-4：使用 Intruder 进行成功的密码喷洒攻击

1.  图 8-5：使用 Burp Suite Intruder 解码 base64

1.  图 8-6：向 Burp Suite Intruder 添加负载处理规则

1.  图 8-7：Burp Suite Sequencer 中手动加载的令牌

1.  图 8-8：Sequencer 提供的令牌分析报告的总结选项卡

1.  图 8-9：Sequencer 字符级分析中的字符位置图

1.  图 8-10：为分析选择的 API 提供者的令牌响应

1.  图 8-11：Burp Suite Intruder 中的集群炸弹攻击

1.  图 8-12：Burp Suite Intruder 中的负载选项卡

1.  图 8-13：使用 Burp Suite Decoder 解码 JWT

1.  图 8-14：在 JWT.io 调试器中分析捕获的 JWT

1.  图 8-15：使用 JWT.io 生成令牌  

1.  图 9-1：Burp Suite 的比较器  

1.  图 9-2：用 Comparer 比较两个 API 响应  

1.  图 9-3：在 Postman 环境编辑器中创建模糊测试变量  

1.  图 9-4：对集合令牌头进行模糊测试  

1.  图 9-5：Postman 集合运行器结果  

1.  图 9-6：Postman 中的 PUT 请求  

1.  图 9-7：Burp Suite 攻击结果

1.  图 9-8：在 Postman 中编辑集合变量  

1.  图 9-9：Postman 集合运行器  

1.  图 9-10：用 Postman 变量替换路径中的版本信息  

1.  图 9-11：不正确的资产管理变量  

1.  图 9-12：基准 Postman 集合运行器测试  

1.  图 10-1：使用 Postman 成功的 BFLA 攻击  

1.  图 10-2：Burp Suite 的匹配与替换功能  

1.  图 10-3：在 crAPI 中注册 UserB  

1.  图 10-4：crAPI 新用户仪表板  

1.  图 10-5：crAPI MailHog 邮件服务  

1.  图 10-6：crAPI 车辆验证界面  

1.  图 11-1：使用 Burp Suite Repeater 分析 */workshop/api/shop/products* 端点  

1.  图 11-2：Burp Suite Intruder 请求方法与有效载荷  

1.  图 11-3：Burp Suite Intruder 结果  

1.  图 11-4：crAPI 中的 MassAssignment SPECIAL  

1.  图 11-5：crAPI 上的可用余额  

1.  图 12-1：Pixi API Swagger 文档  

1.  图 12-2：使用 Postman 成功的 NoSQL 注入攻击  

1.  图 12-3：crAPI 优惠券代码验证功能  

1.  图 12-4：Intruder 模糊测试结果  

1.  图 12-5：Burp Suite Intruder 的有效载荷编码选项  

1.  图 12-6：Burp Suite Intruder 结果  

1.  图 13-1：Burp Suite 解码器  

1.  图 13-2：添加有效载荷处理规则界面  

1.  图 13-3：Intruder 的有效载荷处理选项  

1.  图 13-4：Burp Suite Intruder 的资源池  

1.  图 13-5：Burp Suite 扩展选项  

1.  图 13-6：BApp Store 中的 IP 旋转  

1.  图 13-7：查找 AWS IAM 服务  

1.  图 13-8：AWS 设置用户详细信息页面  

1.  图 13-9：AWS 设置权限页面  

1.  图 13-10：Burp Suite IP 旋转模块  

1.  图 13-11：IPChicken  

1.  图 14-1：DVGA 登录页面

1.  图 14-2：DVGA 首页的网络源文件

1.  图 14-3：DVGA *public_pastes* 来源

1.  图 14-4：DVGA */graphql* 路径

1.  图 14-5：DVGA GraphiQL Web IDE

1.  图 14-6：Burp Suite 的解码器

1.  图 14-7：DevTools 中的 Cookies

1.  图 14-8：Postman 的捕获请求和 Cookies 屏幕

1.  图 14-9：一个不清晰的 GraphQL Postman 集合

1.  图 14-10：清理过的 DVGA 集合

1.  图 14-11：GraphiQL 文档资源管理器

1.  图 14-12：Burp Suite 中的 InQL 扫描器模块

1.  图 14-13：一个拦截的 GraphQL 变更请求

1.  图 14-14：对主机变量攻击的 Intruder 结果

1.  图 14-15：对 `"path"` 变量攻击的 Intruder 结果

1.  图 15-1：Omkar Bhagwat 为他的漏洞奖励报告提供的示例，展示了 API 对他的 */ping* 请求响应了 “pong”

1.  图 15-2：Omkar 成功的 API 请求，用于编辑用户账户密码

## **列表清单**

1.  列表 1-1：用于认证 *twitter.com* 的 HTTP 请求

1.  列表 1-2：在认证 *twitter.com* 时的 HTTP 响应示例

1.  列表 1-3：一个 200 响应的示例

1.  列表 2-1：一个示例 RESTful API 请求

1.  列表 2-2：一个示例 RESTful API 响应

1.  列表 2-3：一个示例 GraphQL 请求

1.  列表 2-4：一个示例 GraphQL 响应

1.  列表 7-1：来自 */community/api/v2/community/posts/recent* 端点的 JSON 响应示例

1.  列表 10-1：BFLA 测试的示例请求

1.  列表 10-2：BFLA 测试的示例响应

1.  列表 10-3：用户信息请求

1.  列表 10-4：带有用户信息的响应

1.  列表 10-5：BOLA 尝试

1.  列表 10-6：对 BOLA 尝试的响应

1.  列表 10-7：请求另一个用户的 GUID

1.  列表 10-8：响应

1.  列表 12-1：优惠券验证请求

1.  列表 12-2：优惠券验证响应

1.  列表 12-3：禁用 URL 编码的请求

1.  列表 12-4：对应的响应

1.  列表 14-1：一个 GraphQL 请求

1.  列表 14-2：一个 GraphQL 响应

1.  Listing 14-3: The request

1.  Listing 14-4: The response

## Guide

1.  Cover

1.  Front Matter

1.  Dedication

1.  Foreword

1.  Introduction

1.  Start Reading

1.  Index

## Pages

1.  i

1.  iii

1.  iv

1.  v

1.  vi

1.  xvii

1.  xviii

1.  xix

1.  xxi

1.  xxii

1.  xxiii

1.  xxiv

1.  xxv

1.  xxvi

1.  1

1.  3

1.  4

1.  5

1.  6

1.  7

1.  8

1.  9

1.  10

1.  11

1.  12

1.  13

1.  15

1.  16

1.  17

1.  18

1.  19

1.  20

1.  21

1.  22

1.  23

1.  24

1.  25

1.  26

1.  27

1.  28

1.  29

1.  30

1.  31

1.  32

1.  33

1.  34

1.  35

1.  36

1.  37

1.  38

1.  39

1.  40

1.  41

1.  42

1.  43

1.  44

1.  45

1.  46

1.  47

1.  48

1.  49

1.  50

1.  51

1.  53

1.  54

1.  55

1.  56

1.  57

1.  58

1.  59

1.  60

1.  61

1.  62

1.  63

1.  64

1.  65

1.  66

1.  67

1.  68

1.  69

1.  71

1.  72

1.  73

1.  74

1.  75

1.  76

1.  77

1.  78

1.  79

1.  80

1.  81

1.  82

1.  83

1.  84

1.  85

1.  86

1.  87

1.  88

1.  89

1.  90

1.  91

1.  92

1.  93

1.  94

1.  95

1.  96

1.  97

1.  98

1.  99

1.  100

1.  101

1.  102

1.  103

1.  104

1.  105

1.  106

1.  107

1.  109

1.  110

1.  111

1.  112

1.  113

1.  114

1.  115

1.  116

1.  117

1.  118

1.  119

1.  121

1.  123

1.  124

1.  125

1.  126

1.  127

1.  128

1.  129

1.  130

1.  131

1.  132

1.  133

1.  134

1.  135

1.  136

1.  137

1.  138

1.  139

1.  140

1.  141

1.  142

1.  143

1.  144

1.  145

1.  146

1.  147

1.  148

1.  149

1.  150

1.  151

1.  152

1.  153

1.  155

1.  156

1.  157

1.  158

1.  159

1.  160

1.  161

1.  162

1.  163

1.  164

1.  165

1.  166

1.  167

1.  168

1.  169

1.  170

1.  171

1.  172

1.  173

1.  174

1.  175

1.  176

1.  177

1.  178

1.  179

1.  180

1.  181

1.  182

1.  183

1.  184

1.  185

1.  186

1.  187

1.  188

1.  189

1.  190

1.  191

1.  192

1.  193

1.  194

1.  195

1.  196

1.  197

1.  198

1.  199

1.  200

1.  201

1.  202

1.  203

1.  204

1.  205

1.  206

1.  207

1.  208

1.  209

1.  210

1.  211

1.  212

1.  213

1.  214

1.  215

1.  216

1.  217

1.  218

1.  219

1.  220

1.  221

1.  223

1.  224

1.  225

1.  226

1.  227

1.  228

1.  229

1.  230

1.  231

1.  232

1.  233

1.  234

1.  235

1.  237

1.  238

1.  239

1.  240

1.  241

1.  242

1.  243

1.  244

1.  245

1.  246

1.  247

1.  249

1.  250

1.  251

1.  252

1.  253

1.  254

1.  255

1.  256

1.  257

1.  258

1.  259

1.  260

1.  261

1.  262

1.  263

1.  264

1.  265

1.  267

1.  268

1.  269

1.  270

1.  271

1.  272

1.  273

1.  274

1.  275

1.  276

1.  277

1.  278

1.  279

1.  280

1.  281

1.  282

1.  283

1.  284

1.  285

1.  286

1.  287

1.  288

1.  289

1.  290

1.  291

1.  292

1.  293

1.  294

1.  295

1.  296

1.  297

1.  298

1.  299

1.  300

1.  301

1.  302

1.  303

1.  304

1.  305

1.  307

1.  308

1.  309

1.  310

1.  311

1.  312

1.  313

1.  314

1.  315

1.  316

1.  317

1.  318

1.  319

1.  320

1.  321

1.  322

1.  323

1.  324

1.  325

1.  326

1.  327

1.  328

1.  329

1.  330

1.  331

1.  332

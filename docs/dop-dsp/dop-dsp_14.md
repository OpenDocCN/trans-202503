# 索引

请注意，索引链接至每个术语的大致位置。

**符号与数字**

2FA（双因素认证）, 28–33

3164 syslog 协议, 143

5424 syslog 协议, 143

*/etc/group*, 22

*/etc/pam.d/common-password*, 15

*/etc/pam.d/sshd*, 30

*/etc/passwd*, 146

*/etc/resolv.conf*, 134

*/etc/shadow*, 22

*/etc/ssh/sshd_config*, 32

*/etc/ufw/user.rules*, 52

*/home/bender/.google_authenticator*, 35

*/home/bender/.ssh/authorized_keys*, 27

*/opt/engineering*, 19, 22, 42

*/opt/engineering/greeting.py*, 42, 46

*/opt/engineering/private.txt*, 19, 23

*/var/log*, 139

*/var/log/ufw.log*, 56

**A**

Alertmanager, 111, 113, 120–123

应用配置更改, 122–123

*configmap.yaml*, 121, 123

电子邮件通知, 121–122

接收者, 121, 122, 123

路由和通知, 121–123

警报, 119–123

黄金信号, 120

审查, 119–120

路由, 121–123

状态, 120

Ansible

`apt` 模块, 29, 39

`authorized_key` 模块, 27

`blockinfile` 模块, 32

命令, 9

`ansible`, 9, 30

`ansible-playbook`, 9, 11, 30

`copy` 模块, 30, 40

`file` 模块, 19

`group` 模块, 18

`handler`, 33

`hostvars`, 43

安装, 7

`lineinfile` 模块, 15, 31, 32, 52

`lookup` 函数, 27

`notify`, 32

`package` 模块, 14

playbook, 8

`import_tasks`, 8

`service` 模块, 33

`set_fact` 模块, 42

`systemd` 模块, 41

`template` 模块, 42

`ufw` 模块, 51

`allow`规则，51

`deny`规则，51

`drop`规则，53

`limit`规则，51

`logging`参数，51

`reject`规则，51

`user`模块，16–17

群组分配，19

选项，17，19

*authorized_keys.yml*，27

`awk`命令，147–148

**B**

*banner.go*，102

bbs-warrior，114–115

**C**

cgroups，64–65

CI/CD，96–97，105–106

ArgoCD，106

代码更改，102，103

交付策略

蓝绿部署，96–97

金丝雀发布，96–97

滚动，96–97

GitLab CI/CD，106

Jenkins，106

流水线，97–105

CM（配置管理），4

*command-and-metadata-test.yaml*，99

命令，Docker

`exec`，71

`history`，73

`inspect`，72，142

`ps`，142

`rm`，72

`stats`，74

`du`，139

复杂密码，14–18

容器，61

`container-structure-test`，97

`commandTests`，99

`metadataTest`，99

持续集成与持续部署。*参见* CI/CD

**D**

调试，125。*参见* 故障排除

声明式配置风格，6，88

*deployment.yaml*，83，89，91–92，98

*developers*组，18，22，38，42

*developers.j2*，43

开发流水线，100–102

`df`，138

*dftd.pub*，27

DHCP（动态主机配置协议），5，55

`dig`，136–137

`dmesg`，133，144

DNS（域名系统），133–134

A 记录，*136*

Docker，62，72

客户端连接性，66

客户端安装，66

命令

`exec`，71

`history`，73

`inspect`，72，142

`ps`，142

`rm`，72

`stats`，74

`du`，139

容器镜像和层，62，64

Dockerfile，62

指令，63

多阶段构建，67

框架，63

入门，62

安装，65–66

命名空间和控制组，64–65

注册表，62

联合文件系统（UFS），64

动态主机配置协议（DHCP），5，55

**E**

错误

连接被拒绝，140–142

连接超时，140

高负载平均，127–129

高内存使用，129–131

高 I/O 等待，131–133

主机名解析失败，133–138

磁盘空间不足，138–139

**F**

`find`，138–139

防火墙，49–58

主机基础，49–58

网络防火墙，49

*firewall.yml*，51

警报触发状态，120

`free`，129–130

**G**

`getent`，22

Go 编程语言，98

`go test`，98

黄金信号，115

错误，115

延迟，115

在 Prometheus 中查看警报，119

饱和，115

流量，115

Google Authenticator，28–30，34

Grafana，111，113

`grafana-service`，113

telnet-server 仪表板，116

*greeting_application_file*，42

*greeting.service*，40

问候 Web 应用，45

*greeting.py*，40，46

安装，39

*wsgi.py*，40

`grep`，146

`gunicorn3`，39

**H**

`head`，138

`HighConnectionRatePerSecond` 警报，120

`HighCPUThrottleRate` 警报，120

`HighErrorRatePerSecond` 警报，120

高 I/O 等待，131

**我**

IaC（基础设施即代码），3，4

幂等，15

命令式，87

闲置警报状态，120

`iostat`，132

`iotop`，133

`ip` 命令，54

iptables，50

**J**

日志，143

`journalctl`，144

常用命令，144–145

优先级级别，145

反向顺序，144

`journald`，144

**K**

K8s。*参见* Kubernetes

`kubectl` 客户端，78，112，144

`apply`，88，93，104，112，122

`cluster-info`，82

`create`，87

删除 pod，`telnet-server`，92

`explain`，84

`get`，88

`get cronjobs.batch`，114

`get deployment`，93

`get endpoints`，91

`get pods`，88，103，92，105

`get services`，带有 `label` 标志，89

`logs`，93

`logs`，Alertmanager，123

`rollout`，104，105，122

`scale`，92

Kubernetes，77

集群连通性，82

集群概览，78

配置映射，81

控制平面节点，78

部署，79

总体概述，78

`kubectl`，82

清单，79

容器，86

标签，83

元数据名称字段，84

副本，85

选择器字段，85

服务字段，87

`spec`，85

模板，85

顶级字段，83

命名空间，81，112

节点，78

节点亲和性，78

Pods，79

副本，79

ReplicaSet，79

审查清单，82

部署历史，104

路由警报，121

规模，89

Secrets，81

`Service` 资源，87

服务，80

ClusterIP，83，89

EXTERNAL-IP，90，103

LoadBalancer，83，89

NodePort，113

StatefulSets, 80

`strategy` 字段, 85

故障排除, 91

`ImagePullBackOff`, 91

卷, 80

工作节点, 78

工作负载资源, 79

**L**

`libpam-google-authenticator`, 29

`libpam-pwquality`, 14

Linux 组, 18

Linux 用户类型

正常, 16

root, 16

系统, 16

负载平均值, 127

`logrotate`, 139

日志, 109, 143–144

*/var/log/auth.log*, 35, 47, 143, 146

*/var/log/dmesg*, 144

*/var/log/kern.log*, 143

*/var/log/syslog*, 35, 47, 143, 146

搜索, 142–148

lo（回环接口）, 55

`lsof`, 133, 139

`ltrace`, 151

**M**

平均恢复时间（MTTR）, 105

内存管理（OOM），143

指标, 109, 115–119

波动, 119

模式, 116

`RED`, 116

`USE`, 116

微服务, 115

`minikube`

命令

`ip`, 74

`kubectl`, 82, 84, 87

`service`, 90, 113

`tunnel`, 89, 103

安装, 65

`mkpasswd`, 17

模块, Ansible

`apt`, 29, 39

`authorized_key`, 27

`blockinfile`, 32

`copy`, 30, 40

`file`, 19

`group`, 18

`lineinfile`, 15, 31, 32, 52

`package`, 14

`service`, 33

`set_fact`, 42

`systemd`, 41

`template`, 42

`ufw`, 51

`user`, 16–17

监控示例应用, 111–115

*监控* 目录, 112

监控堆栈, 110

安装, 112

telnet-server, 111

验证安装, 113

MTTR（平均恢复时间）, 105

**N**

名称服务器, 134

名称空间，64–65, 81, 112

`netstat`，141

`nginx`，39

`nmap`（网络映射器），55, 57

快速扫描，56

已过滤，56

扫描端口，55

服务名称和版本，56

**O**

`oathtool`，28, 35

安装，35

可观测性，109

OOM（内存不足管理器），143

编排，77

操作系统级虚拟化，62

**P**

*pam_google_authenticator.so*，30

PAM（可插拔认证模块），14

`pam_pwquality`，14–15, 17 21

解析日志，146

密码短语，26

待处理警报状态，120

持久卷（PV），80

探测进程，148

Prometheus，111, 114

警报规则，配置，119

警报页面，120

*configmap.yaml*，114, 119

`prometheus.rules`，配置，119

`prometheus-service`，114

运行查询 Web 界面，118

严重性临界，规则标签，120

PromQL，118

配置，3

防火墙，53

SSH，33

sudoers，44

用户和组，20

`ps`，129, 131

CMD 列，131

公钥对，26

RSS 列，131

公钥

认证，26–28

复制，27

`rsa`，27

PV（持久卷），80

`pwgen`，17

`python3-flask`，39

**R**

常驻集大小（RSS），131

`resolv.conf`, 134

`edns0`，135

`trust-ad`，135

`resolvectl`, 135

`resolver`，135

*restart_ssh.yml*，33

`RollingUpdate`，85

RSS（常驻集大小），131

运行手册，120

**S**

安全外壳（SSH）。*另见* SSH（安全外壳协议）

*service.yaml*，83, 87, 91

shadow 文件，17。*另见* */etc/shadow*

*site.yml*，8, 20, 33, 44, 53

`skaffold`， 97， 100

`build` 部分， 98

`deploy`， 100–101

`deploy` 部分， 99

`dev`， 100， 102

审查， 98–99

*skaffold.yaml*， 98， 100

`structureTests`， 99

`test` 部分， 98

套接字统计 (ss)， 140–141

正在监听， 140

套接字所有者，进程， 140

`ssh-keygen`， 26

SSH（安全外壳协议）， 7， 25

会话， 145

SSH 服务器

`AuthenticationMethods`， 31

`ChallengeResponseAuthentication`， 32

配置， 31

`keyboard-interactive`， 31

`Match`， 32

`publickey`， 31

使用 Ansible 处理程序重启， 32

`strace`， 133， 148

跟踪子进程， 149

输出到文件， 150

PID， 149

字符串大小， 149

摘要， 149

跟踪特定系统调用， 150

`sudo`， 37， 38， 47

sudoers， 38， 42， 45， 146

`Aliases`， 41

`Cmnd_Alias`， 43

创建文件， 42

`Defaults`， 41

文件结构， 41

`Host_Alias`， 43

Jinja2 模板， 43

`LOCAL_VM`， 43

策略规划， 38

测试 sudoers 策略， 45

访问 Greeting， 45

编辑 *greeting.py*， 46

`sudoedit`， 46

`systemctl` 启动和停止， 46

`User Specifications`， 41

`validate`， 43

*sudoers.yml*， 42

`sudo su`，作为 bender 用户， 22

*syslog*， 149

3164 协议， 143

5424 协议， 143

格式， 143

系统调用

`accept4`， 149

`close`， 149

`recvfrom`， 149

`sendto`， 149

*systemd*， 39， 43， 46

重载， 41

`resolved`， 134

`resolver`, 135

`systemctl`， 46

**T**

`tail`， 76， 144

`tcpdump`，141

TCP 三次握手，142

telnet，89，94，103，105

telnet-server，86，88，89，92，98，101，104

通过 Kubernetes 访问，89

创建部署和服务，87

部署清单，84

`get` 部署，88

Grafana 仪表盘，117

Metric 服务，87

Pod

终止，92

日志，93–94

扩展部署，92

服务清单，87

回滚，Kubernetes，104

telnet-server-metrics，服务名称，89

通过 Kubernetes 使用 telnet，91

测试 Kubernetes 部署，89

telnet-server（应用），66

构建容器镜像，68

连接，74

容器化，66

Dockerfile，67

获取日志，75

Grafana 仪表盘，117

运行中的容器，70

使用 telnet 测试，74，103，105

验证容器镜像，69

三次握手，142

`ACK`，142

`SYN`，142

`SYN-ACK`，142

基于时间的一次性密码 (TOTP)，28

`top`，128

`COMMAND` 列，128

`CPU percent` 列，128

`MEM percent` 列，128

`PID` 列，128

`RES` 列，128

输出，128

跟踪，109

故障排除，125–142

连接拒绝错误，140–142

高 I/O 等待，131–133

高负载平均错误，127–129

高内存使用错误，129–131

主机名解析失败，133–137

磁盘空间不足错误，138–139

双因素认证 (2FA)，28–33

*two_factor.yml*，28，29，30，33

**U**

Ubuntu 虚拟机设置，9–11

UFW（简易防火墙），50

`BLOCK`，57

链，50

`LIMIT BLOCK`, 58

日志记录, 56–57

速率限制, 57–58

规则, 50

测试, 54

正常运行时间, 127

*user_and_group.yml*, 16, 18–20

**V**

Vagrant, 4

命令, 6

`vagrant plugin install`, 5

`vagrant provision`, 21, 34, 45, 54

`vagrant ssh`, 21

`vagrant status`, 11

`vagrant up`, 9, 11

客户机附加功能, 4

安装, 4

*vagrant* 用户, 21, 22, 31

Vagrantfile, 4, 54

box, 5

网络, 5–6

提供者, 6

Vagrantfile, 4, 54

`visudo`, 43

`vmstat`, 129, 130, 132

**W**

*web_application.yml*, 39

**Y**

YAML（另一种标记语言）, 6, 83, 98

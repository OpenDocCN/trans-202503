# <samp class="SANS_Dogma_OT_Bold_B_11">术语表</samp>

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">特定应用集成电路 (ASIC)</samp>

为特定用途定制的集成电路，而非通用用途的集成电路。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">双向</samp>

描述一个可以同时发送和接收数据的 FPGA 引脚，通常用于半双工通信。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">阻塞赋值</samp>

一种赋值方式，在当前赋值执行之前，阻止执行下一个语句。阻塞赋值运算符在 Verilog 中是 <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp>，在 VHDL 中是 <samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp>，但在 VHDL 中你只能在变量上创建阻塞赋值，而不能在信号上创建。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">块 RAM</samp>

一种常见的 FPGA 基元，用于更大范围的存储和检索内存。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">布尔代数</samp>

仅使用真/假、高/低或 1/0 表示输入和输出的方程式。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">缓冲器</samp>

一种将输入与输出隔离的电子电路元件。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">时钟</samp>

一种在固定频率下稳定交替高低电平的数字信号，协调并驱动 FPGA 的活动。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">时钟数据恢复 (CDR)</samp>

从通过 SerDes 发送的时钟/数据合成信号中提取时钟和数据信号的过程。提取的时钟信号可用于在 SerDes 接收器中对数据进行采样。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">时钟使能 (到触发器)</samp>

标记为 En 的输入，允许在激活时更新触发器输出。当时钟使能无效时，触发器将保持其输出状态。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">时钟输入 (到触发器)</samp>

标记为 >，接收时钟信号的输入，使触发器能够工作。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">组合逻辑</samp>

其输出由当前输入决定的逻辑，没有记忆过去状态（也称为 *组合逻辑*）。组合逻辑在 FPGA 中生成 LUT。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">约束</samp>

你提供给综合和布图布线工具的 FPGA 规则，例如信号的引脚位置和设计中使用的时钟频率。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">核心电压</samp>

FPGA 执行所有内部数字处理的电压。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">数据输入 (到触发器)</samp>

标记为 D，触发器的输入信号，通常在时钟的上升沿传播到输出。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">数据输出（来自触发器）</samp>

标记为 Q，触发器的输出信号，通常在时钟的上升沿更新。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">数据手册</samp>

关于电子组件的信息集合。FPGA 通常有多个数据手册，更复杂的 FPGA 可能有几十个。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">直流平衡</samp>

发送相同数量的高位和低位，以改善高速通信中的数字信号完整性。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">去抖动</samp>

一种去除弹跳或毛刺以获得稳定信号的技术。通常用于机械开关，开关切换时可能会引入毛刺。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">解复用器（demux）</samp>

一种设计元素，可以从多个输出中选择一个输入。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">被测设备（DUT）</samp>

由测试平台测试的代码块。也称为*单元测试（UUT）*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">差分信号传输</samp>

一种通过评估两根电线之间的差异来传输电信号的方法。无需参考地面。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">数字滤波器</samp>

对数字信号执行数学运算的系统，用于减少或增强该信号的某些特征。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">双数据速率（DDR）</samp>

在每个时钟周期的上升沿和下降沿都发送数据。相比单数据速率（SDR），这允许两倍的数据吞吐量。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">驱动强度</samp>

控制引脚源或吸收电流（以毫安计）级别的设置。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">DSP 块</samp>

用于加速数字信号处理（DSP）中的数学运算（特别是乘法和加法）的原语，通常在 FPGA 中使用。也称为*DSP 模块*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">占空比</samp>

信号为高与低的时间百分比。时钟信号通常具有 50%的占空比。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">边缘</samp>

信号（例如时钟）从一个状态过渡到另一个状态的点。由低到高的过渡称为上升沿或正边缘，由高到低的过渡称为下降沿或负边缘。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">边缘检测</samp>

查找上升沿或下降沿并根据该边缘触发某些操作的过程。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">电磁干扰（EMI）</samp>

由电磁场变化引起的现象（例如来自附近的微波炉、手机或电力线），可能会对其他系统造成干扰。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">事件</samp>

状态机响应的一个动作，例如计时器到期、按钮按下或某个输入触发器。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">先进先出（FIFO）</samp>

一种常见的缓冲区类型，写入的第一个字是读取的第一个字。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">触发器</samp>

FPGA 内部的关键组件，负责存储状态。使用时钟作为输入，并通常在时钟的上升沿将其数据输入信号传递到数据输出。也叫做*寄存器*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">FPGA</samp>

*现场可编程门阵列*（FPGA）的缩写，是一种数字电路，可以使用 Verilog 或 VHDL 进行编程，以解决各种数字逻辑问题。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">FPGA 开发板</samp>

一块印刷电路板（PCB），上面有一个 FPGA，可以用来编程 FPGA 并测试代码。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">频率</samp>

信号（如时钟信号）每秒的周期数（高/低交替），以赫兹（Hz）为单位测量。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">全双工</samp>

两个系统之间的一种通信模式，其中数据可以同时发送和接收。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">通用</samp>

在 VHDL 中用于通过在更高层级覆盖低级代码的行为，使代码更加灵活和可重用。相当于 Verilog 中的参数。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">GPIO</samp>

一种通用输入/输出引脚，用于将 FPGA 与电路板上的其他组件连接。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">保护条件</samp>

一种布尔表达式，用于确定状态机中操作的流程。可以在状态机图中使用菱形表示。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">GUI 创建</samp>

使用 FPGA 开发工具中的 GUI 来创建原语的过程。这通常是初学者创建原语的最佳方法，因为它最不容易出错。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">半双工</samp>

两个系统之间的一种通信模式，其中只有一个系统可以同时发送数据。也称为*双向数据传输*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">硬 IP</samp>

一个专门用于特定任务的 FPGA 组件，例如块 RAM、PLL 或 DSP 块。也叫做*原语*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">高阻抗</samp>

缓冲区的状态，其中输出接受极少的输入电流，这有效地关闭输出并将其从电路中断开。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">保持时间</samp>

为避免亚稳态条件，翻转触发器的输入应在时钟沿后保持稳定的时间。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">推理</samp>

使用 Verilog 或 VHDL 创建原语的过程，并依赖综合工具理解你的意图。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">集成电路（IC）</samp>

通常被称为*芯片*，它是一种集成在单一封装中的电子电路。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">线性反馈移位寄存器（LFSR）</samp>

一种特殊类型的移位寄存器，通过将某些触发器通过逻辑门并将结果返回输入，产生伪随机模式。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">逻辑分析仪</samp>

一种用于调试的工具，能够同时分析多个数字信号。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">逻辑门</samp>

执行常见布尔运算（如 AND、OR 和 XOR）的设备。每种类型的逻辑门都有独特的符号。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">查找表（LUT）</samp>

FPGA 内部的专用组件，执行所有布尔逻辑运算。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">亚稳态</samp>

一种条件，其中翻转触发器的输出在一段时间内不稳定且不可预测。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">微控制器</samp>

一种集成电路上的小型计算机，具有 CPU 和外部外设，可以使用像 C 这样的语言进行编程。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">多路复用器（mux）</samp>

一种设计元素，可以选择多个输入并将其输出到单一输出。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">非阻塞赋值</samp>

在 Verilog 或 VHDL 中使用 <samp class="SANS_TheSansMonoCd_W5Regular_11"><=</samp> 进行的赋值操作，其中这些语句会在同一时刻执行。通常用于在 FPGA 上创建时序逻辑（触发器）。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">工作电压</samp>

GPIO 引脚上 1 或 0 出现的电压。常见的 1 值有 3.3 V、2.5 V 和 1.8 V。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">并行通信</samp>

一种数据传输方法，其中多个比特同时发送。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">参数</samp>

在 Verilog 中使用，允许通过在更高级别重写低级代码的行为，使代码更具灵活性和可重用性。与 VHDL 中的泛型类似。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">周期</samp>

时钟周期的上升沿之间的时间，通常以纳秒为单位。时钟的周期计算公式为 1 ÷ *频率*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">相位</samp>

信号的特性，描述其波形的当前位置或它与另一个信号之间的时间关系。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">锁相环（PLL）</samp>

一个常用于 FPGA 作为主时钟生成器的原语。它可以生成多个不同频率的时钟信号，并管理它们之间的关系。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">物理约束文件</samp>

一个文件，将设计中的信号映射到 FPGA 上的物理引脚。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">放置与布线</samp>

设计工具将你的综合设计映射到特定 FPGA 上的物理位置。还进行时序分析，报告设计是否能够在所请求的时钟频率下成功运行。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">原语</samp>

FPGA 内部专用于特定任务的组件，如块 RAM、PLL 或 DSP 块。也叫做*硬 IP*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">原语实例化</samp>

通过使用其模板直接创建一个原始 FPGA 组件。这种方法允许你精确获得所需的原语，而无需依赖工具做出假设。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">传播延迟</samp>

信号从源到目的地传播所需的时间。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">协议</samp>

一套定义两台或多台设备如何通信的规则。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">随机存取存储器（RAM）</samp>

可以按任意顺序访问的存储器，通常通过一个端口（单端口）或两个端口（双端口）访问。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">寄存器</samp>

翻转触发器的另一种说法。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">布线</samp>

FPGA 内部的布线使其具有灵活性，但成本较高。也叫做*互连*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">采样</samp>

通过对模拟信号进行离散的时间测量，将其转换为数字信号的过程。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">自检测试平台</samp>

一个测试平台，能够自动报告设计是否按预期工作，而不需要你检查结果波形。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">自时钟信号</samp>

一种将时钟和数据信号组合在一起的编码方案，利用这种信号，独立的时钟和数据路径可以合并为一个接口。此技术对于 SerDes（串行解串行化）至关重要。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">顺序逻辑</samp>

逻辑，其输出由当前输入和先前输出共同决定（也称为*同步逻辑*）。顺序逻辑在 FPGA 中生成触发器。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">SerDes（序列化/反序列化器）</samp>

一种 FPGA 原语，用于在发送设备和接收设备之间以高速传输数据。并行数据被转换为串行数据，并与时钟信号一起嵌入传输。在接收端，提取时钟和数据信号，串行数据被转换回并行数据。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">串行通信</samp>

一种数据传输方法，其中每次发送一个比特。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">设定/复位</samp>

一种输入，当其处于激活状态时，会将触发器重置为默认值。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">设定时间</samp>

输入到触发器在时钟边缘之前应保持稳定的时间，以避免产生亚稳定状态。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">移位寄存器</samp>

一种触发器链，其中一个触发器的输出连接到下一个触发器的输入。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">符号位</samp>

有符号数中最重要的比特，用于指示该数是负数（符号位为 1）还是正数（符号位为 0）。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">有符号</samp>

指可以承载正负数据的信号。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">符号扩展</samp>

增加二进制数位数的操作，同时保持该数的符号和值。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">仿真</samp>

使用计算机向 FPGA 代码注入测试用例，以查看代码的响应过程。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">单数据速率（SDR）</samp>

仅在每个时钟周期的一个边缘（通常是上升沿）发送数据。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">单端信号传输</samp>

一种电信号传输方法，其中一根电线承载信号，且该信号参考地面。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">变化率</samp>

允许输出信号变化的速率，通常以定性术语表示，如快、中或慢。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">状态</samp>

在状态机中，系统等待执行过渡的状态。状态可以在事件触发过渡时改变，或者如果状态本身引发过渡到另一个状态。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">状态机</samp>

有时称为*有限状态机（FSM）*，一种控制 FPGA 中操作序列流动的方法。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">综合</samp>

将 VHDL 或 Verilog 代码转换为 FPGA 内部低级组件的设计工具，如 LUT、触发器和块 RAM。类似于 C 语言的编译器。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">系统芯片（SoC）</samp>

将电子系统的多个组件集成到一个封装中的集成电路。例如，具有专用 CPU 的 FPGA 可以被认为是 SoC。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">SystemVerilog</samp>

一种 Verilog 的超集编程语言，新增的特性使其在验证中非常有用。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">测试平台</samp>

在仿真环境中测试您的 FPGA 设计代码，以便您可以分析设计，看它是否按预期行为运行的测试代码。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">时序错误</samp>

放置和布线过程的输出，显示可能会受到亚稳态问题影响的信号，这可能导致您的 FPGA 设计表现不稳定。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">权衡研究</samp>

在工程中通过考察多种可能性，并根据每种可能的优缺点进行权衡，选择技术解决方案的行为。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">收发器</samp>

一种既可以发送又可以接收通信的设备。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">过渡</samp>

在状态机中从一个状态转移到另一个状态的动作。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">真值表</samp>

布尔方程的表格表示，列出了所有可能的输入组合及其对应的输出。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">二进制补码</samp>

一种数学操作，用于在正负二进制数之间进行转换。获取二进制的补码时，您需要将位取反并加 1。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">被测单元（UUT）</samp>

被测试的代码块，也叫做 *被测设备（DUT）*。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">通用异步收发器（UART）</samp>

一种数据异步传输或接收的接口，即不使用时钟进行传输。通常用于交换低数据速率的信息，例如 FPGA 与计算机之间的数据交换。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">无符号</samp>

指一个只能保持正数据而不能保持负数据的信号。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">资源使用报告</samp>

合成工具的输出，告知您 FPGA 资源使用的百分比。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">验证</samp>

彻底测试 FPGA 或 ASIC 设计的过程，以确保其按预期工作。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">波形</samp>

FPGA 仿真工具的一个特性，它展示了在测试环境中信号随时间变化的可视化表示。

<hgroup>

# <samp class="SANS_Futura_Std_Bold_Condensed_B_11">9</samp> <samp class="SANS_Dogma_OT_Bold_B_11">预处理器</samp>

</hgroup>

*与 Aaron Ballman 合作*

![](img/opener.jpg)

预处理器是 C 编译器的一部分，它在编译的早期阶段运行，并在代码被翻译之前进行处理，例如将一个文件（通常是头文件）中的代码插入到另一个文件（通常是源文件）中。预处理器还允许你指定一个标识符，在宏扩展过程中自动用源代码片段替代它。在本章中，你将学习如何使用预处理器来包含文件、定义类似对象和函数的宏、根据特定实现功能有条件地包含代码，并将二进制资源嵌入到程序中。

## <samp class="SANS_Futura_Std_Bold_B_11">编译过程</samp>

从概念上讲，编译过程由八个阶段组成，如图 9-1 所示。我们称这些为*翻译阶段*，因为每个阶段都将代码转换为下一阶段处理所需的格式。

![](img/f09001.jpg)

<samp class="SANS_Futura_Std_Book_Oblique_I_11">图 9-1：翻译阶段</samp>

预处理器在翻译器将源代码转换为目标代码之前运行，这允许预处理器在翻译器处理之前*修改*用户编写的源代码。因此，预处理器对正在编译的程序的语义信息了解有限。它不了解函数、变量或类型。只有基本元素，如头文件名、标识符、字面值和标点符号（例如 <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">-</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">!</samp>）对预处理器是有意义的。这些基本元素称为*标记*，是编译器能够理解的计算机程序中最小的有意义元素。

预处理器作用于你在源代码中包含的*预处理指令*，以编程预处理器的行为。你通过在前面加上 <samp class="SANS_TheSansMonoCd_W5Regular_11">#</samp> 标记，然后跟随指令名称来拼写预处理指令，例如 <samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">#define</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">#embed</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">#if</samp>。每个预处理指令以换行符结尾。你可以通过在行的开头和 <samp class="SANS_TheSansMonoCd_W5Regular_11">#</samp> 之间添加空白字符来缩进指令。

```
 #define THIS_IS_FINE 1
```

或者位于 <samp class="SANS_TheSansMonoCd_W5Regular_11">#</samp> 和指令之间：

```
#  define SO_IS_THIS 1
```

预处理指令指示预处理器修改结果翻译单元。如果你的程序包含预处理指令，翻译器所处理的代码与你编写的代码并不完全相同。编译器通常提供查看预处理器输出的方法，这些输出被称为*翻译单元*，传递给翻译器。查看预处理器的输出虽然不必要，但你可能会觉得看到实际传给翻译器的代码是很有帮助的。表 9-1 列出了常见编译器用来输出翻译单元的标志。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-1：</samp> <samp class="SANS_Futura_Std_Book_11">输出翻译单元</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">编译器</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">示例命令行</samp> |
| --- | --- |
| <samp class="SANS_Futura_Std_Book_11">Clang</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">clang</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">其他选项</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">-E -o</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">tu.i tu.c</samp> |
| <samp class="SANS_Futura_Std_Book_11">GCC</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">gcc</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">其他选项</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">-E -o</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">tu.i tu.c</samp> |
| <samp class="SANS_Futura_Std_Book_11">Visual C++</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">cl</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">其他选项</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">/P /Fi</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">tu.i tu.c</samp> |

预处理输出文件通常使用*.i* 文件扩展名。## <samp class="SANS_Futura_Std_Bold_B_11">文件包含</samp>

预处理器的一个强大功能是能够通过使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp> 预处理指令，将一个源文件的内容插入到另一个源文件的内容中。被包含的文件称为*头文件*，以便与其他源文件区分开来。头文件通常包含供其他程序使用的声明。这是与程序其他部分共享函数、对象和数据类型外部声明的最常见方式。

你已经在本书的示例中看到许多包含 C 标准库函数头文件的例子。例如，表 9-2 中的程序被拆分为一个名为*bar.h*的头文件和一个名为*foo.c*的源文件。源文件*foo.c*中并未直接包含对 <samp class="SANS_TheSansMonoCd_W5Regular_11">func</samp> 的声明，但该函数仍然能在 <samp class="SANS_TheSansMonoCd_W5Regular_11">main</samp> 中通过名字成功引用。在预处理阶段，<samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp> 指令会将 *bar.h* 的内容插入到 *foo.c* 中，替代掉 <samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp> 指令本身。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-2：</samp> <samp class="SANS_Futura_Std_Book_11">头文件包含</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源代码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">结果翻译单元</samp> |
| --- | --- |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">bar.h</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int func(void);</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">int func(void);</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int main(void) {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">return func();</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">foo.c</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#include "bar.h"</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int main(void) {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  return func();</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |

预处理器在遇到 <samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp> 指令时会立即执行它。因此，包含操作具有传递性：如果一个源文件包含了一个头文件，而该头文件又包含了另一个头文件，那么预处理后的输出将包含两个头文件的内容。例如，给定 *baz.h* 和 *bar.h* 头文件，以及 *foo.c* 源文件，在对 *foo.c* 源代码运行预处理器后的输出，如 表 9-3 所示。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-3：</samp> <samp class="SANS_Futura_Std_Book_11">传递性头文件包含</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源代码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">结果翻译单元</samp> |
| --- | --- |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">baz.h</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int other_func(void);</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">int other_func(void);</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int func(void);</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int main(void) {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  return func();</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">bar.h</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#include "baz.h"</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int func(void);</samp> |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">foo.c</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#include "bar.h"</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int main(void) {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">   return func();</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |

编译 *foo.c* 源文件时，预处理器会包含 <samp class="SANS_TheSansMonoCd_W5Regular_11">"bar.h"</samp> 头文件。然后，预处理器会找到 <samp class="SANS_TheSansMonoCd_W5Regular_11">"baz.h"</samp> 头文件的包含指令，并将其也包含进来，从而把 <samp class="SANS_TheSansMonoCd_W5Regular_11">other_func</samp> 的声明引入到生成的翻译单元中。

最佳实践是避免依赖传递式包含，因为它们会让你的代码变得脆弱。可以考虑使用像 include-what-you-use (*[`<wbr>include<wbr>-what<wbr>-you<wbr>-use<wbr>.org`](https://include-what-you-use.org)*) 这样的工具来自动移除对传递式包含的依赖。

从 C23 开始，你可以在 <samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp> 指令执行之前，使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">__has_include</samp> 预处理器操作符来检测一个包含文件是否存在。它只接受一个头文件名作为操作数。如果指定的文件能够找到，操作符返回 true，否则返回 false。你可以与条件包含一起使用它，以便在文件无法包含时提供替代的实现。例如，你可以使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">__has_include</samp> 预处理器操作符来检测 C 标准库线程或 POSIX 线程支持，如下所示：

```
#if __has_include(<threads.h>)
#  include <threads.h>
   typedef thrd_t thread_handle;
#elif __has_include(<pthread.h>)
   typedef pthread_t thread_handle;
#endif
```

你可以使用带引号的包含字符串（例如，<samp class="SANS_TheSansMonoCd_W5Regular_11">#include "foo.h"</samp>）或尖括号的包含字符串（例如，<samp class="SANS_TheSansMonoCd_W5Regular_11">#include <foo.h></samp>）来指定要包含的文件。这两种语法的区别由实现定义，但它们通常会影响用于查找包含文件的搜索路径。例如，Clang 和 GCC 都会尝试找到使用以下语法包含的文件：

+   使用<samp class="SANS_TheSansMonoCd_W5Regular_11">-isystem</samp>标志指定的*系统包含路径*上的尖括号

+   使用<samp class="SANS_TheSansMonoCd_W5Regular_11">-iquote</samp>和<samp class="SANS_TheSansMonoCd_W5Regular_11">-isystem</samp>标志指定的*引用包含路径*上的引用字符串

请参阅您的编译器文档，了解这两种语法之间的具体差异。通常，标准或系统库的头文件位于默认系统包含路径中，而您自己的项目头文件位于引用包含路径中。

传递给<samp class="SANS_TheSansMonoCd_W5Regular_11">__has_include</samp>预处理器操作符的头文件操作数可以使用引号或尖括号指定。该操作符使用与<samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp>指令相同的搜索路径启发式方法。因此，您应确保对于<samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp>指令和相应的<samp class="SANS_TheSansMonoCd_W5Regular_11">__has_include</samp>操作符使用相同的形式，以确保结果的一致性。

## <samp class="SANS_Futura_Std_Bold_B_11">条件包含</samp>

通常，您需要编写不同的代码来支持不同的实现。例如，您可能希望为不同的目标架构提供函数的替代实现。解决此问题的一种方法是维护两个文件，它们之间有细微的差异，并为特定实现编译相应的文件。更好的解决方案是根据预处理器定义来翻译或避免翻译目标特定的代码。

您可以使用如<samp class="SANS_TheSansMonoCd_W5Regular_11">#if</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">#elif</samp>或<samp class="SANS_TheSansMonoCd_W5Regular_11">#else</samp>等预处理指令在带有谓词条件的情况下有条件地包含源代码。*谓词条件*是控制常量表达式，用于确定预处理器应该选择程序的哪个分支。它们通常与预处理器的<samp class="SANS_TheSansMonoCd_W5Regular_11">defined</samp>操作符一起使用，后者用于判断给定标识符是否是已定义宏的名称。

条件包含指令类似于 <samp class="SANS_TheSansMonoCd_W5Regular_11">if</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">else</samp> 语句。当谓词条件计算为非零预处理器值时，<samp class="SANS_TheSansMonoCd_W5Regular_11">#if</samp> 分支会被处理，其他所有分支不会被处理。当谓词条件计算为零时，下一条 <samp class="SANS_TheSansMonoCd_W5Regular_11">#elif</samp> 分支（如果有）会对其谓词进行测试以决定是否包含。如果没有谓词条件计算为非零，则处理 <samp class="SANS_TheSansMonoCd_W5Regular_11">#else</samp> 分支（如果存在）。<samp class="SANS_TheSansMonoCd_W5Regular_11">#endif</samp> 预处理指令表示条件包含代码的结束。

<samp class="SANS_TheSansMonoCd_W5Regular_11">defined</samp> 运算符如果给定的标识符被定义为宏，则计算为 <samp class="SANS_TheSansMonoCd_W5Regular_11">1</samp>，否则计算为 <samp class="SANS_TheSansMonoCd_W5Regular_11">0</samp>。例如，清单 9-1 中显示的预处理指令根据条件决定包含哪些头文件内容。预处理输出取决于 <samp class="SANS_TheSansMonoCd_W5Regular_11">_WIN32</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">__ANDROID__</samp> 是否为已定义宏。如果两者都不是已定义宏，预处理器输出将为空。

```
#if defined(_WIN32)
#  include <Windows.h>
#elif defined(__ANDROID__)
#  include <android/log.h>
#endif
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 9-1：条件包含示例</samp>

与 <samp class="SANS_TheSansMonoCd_W5Regular_11">if</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">else</samp> 关键字不同，预处理器条件包含无法使用大括号来表示由谓词控制的语句块。相反，预处理器条件包含会将从 <samp class="SANS_TheSansMonoCd_W5Regular_11">#if</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">#elif</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">#else</samp> 指令（紧随谓词后）到下一个平衡的 <samp class="SANS_TheSansMonoCd_W5Regular_11">#elif</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">#else</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">#endif</samp> 令牌的所有标记，同时跳过在未选择的条件分支中的任何标记。条件包含指令可以嵌套。你可以写

```
#ifdef `identifier`
```

作为简写形式：

```
#if defined `identifier`
```

同样，你可以写

```
#ifndef `identifier`
```

作为简写形式：

```
#if !defined `identifier`
```

从 C23 开始，你可以写

```
#elifdef `identifier`
```

作为简写形式

```
#elif defined `identifier`
```

你可以写

```
#elifndef `identifier`
```

作为简写形式

```
#elif !defined `identifier`
```

或者等效地：

```
#elif !defined(`identifier`)
```

标识符周围的圆括号是可选的。

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">生成诊断信息</samp>

如果预处理器无法执行任何条件分支，因为没有合理的回退行为，那么可能需要生成一个错误信息。考虑示例 9-2 中的例子，它使用条件包含来选择是否包含 C 标准库头文件 <samp class="SANS_TheSansMonoCd_W5Regular_11"><threads.h></samp> 或 POSIX 线程库头文件 <samp class="SANS_TheSansMonoCd_W5Regular_11"><pthread.h></samp>。如果两者都不可用，应该提醒移植系统的程序员，代码必须修复。

```
#if __STDC__ && __STDC_NO_THREADS__ != 1
#  include <threads.h>
#elif POSIX_THREADS == 200809L
#  include <pthread.h>
#else
  int compile_error[-1]; // induce a compilation error
#endif
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">示例 9-2：引发编译错误</samp>

这里，代码生成了诊断信息，但没有描述实际的问题。为此，C 提供了 <samp class="SANS_TheSansMonoCd_W5Regular_11">#error</samp> 预处理指令，导致实现生成编译时的诊断消息。你可以选择在该指令后跟一个或多个预处理器标记，以包含在生成的诊断消息中。通过这些，我们可以将示例 9-2 中的错误数组声明替换为如示例 9-3 所示的 <samp class="SANS_TheSansMonoCd_W5Regular_11">#error</samp> 指令。

```
#if __STDC__ && __STDC_NO_THREADS__ != 1
#  include <threads.h>
#elif POSIX_THREADS == 200809L
#  include <pthread.h>
#else
#  error "Neither <threads.h> nor <pthread.h> is available"
#endif
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">示例 9-3：一个</samp> <samp class="I">#error</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">指令</samp>

如果没有线程库头文件可用，以下代码将生成错误消息：

```
Neither <threads.h> nor <pthread.h> is available
```

除了 <samp class="SANS_TheSansMonoCd_W5Regular_11">#error</samp> 指令，C23 还增加了 <samp class="SANS_TheSansMonoCd_W5Regular_11">#warning</samp> 指令。这个指令和 <samp class="SANS_TheSansMonoCd_W5Regular_11">#error</samp> 指令类似，它们都会导致实现生成诊断信息。然而，不同的是，生成诊断消息后，编译继续进行（除非其他命令行选项禁用警告或将其升级为错误）。<samp class="SANS_TheSansMonoCd_W5Regular_11">#error</samp> 指令应当用于*致命*问题，例如没有回退实现的缺失库，而 <samp class="SANS_TheSansMonoCd_W5Regular_11">#warning</samp> 指令应当用于*非致命*问题，例如缺失库但有低质量回退实现。

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">使用头文件保护</samp>

编写头文件时，你会遇到的一个问题是防止程序员在一个翻译单元中多次包含同一文件。由于可以传递性地包含头文件，你可能会不小心多次包含同一头文件（甚至可能导致头文件之间的无限递归）。

*头文件保护*确保每个翻译单元中仅包含一次头文件。头文件保护是一种设计模式，根据是否已定义特定的宏来有条件地包含头文件的内容。如果该宏尚未定义，则会定义它，以确保后续的头文件保护测试不会有条件地重复包含代码。在表 9-4 中所示的程序中，*bar.h*使用了头文件保护（加粗显示）来防止它在*foo.c*中被（意外）重复包含。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-4:</samp> <samp class="SANS_Futura_Std_Book_11">头文件保护</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源代码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">生成的翻译单元</samp> |
| --- | --- |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">bar.h</samp><samp class="SANS_TheSansMonoCd_W7Bold_B_11">#ifndef BAR_H</samp><samp class="SANS_TheSansMonoCd_W7Bold_B_11">#define BAR_H</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">inline</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int func() { return 1; }</samp><samp class="SANS_TheSansMonoCd_W7Bold_B_11">#endif /* BAR_H */</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">inline</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int func() { return 1; }</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">extern inline int func();</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int main() {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  return func();</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">foo.c</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#include "bar.h"</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#include "bar.h" // 重复包含</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">                 // 通常不是这么明显的</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">extern inline int func();</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int main() {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  return func();</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |

第一次包含 `<samp class="SANS_TheSansMonoCd_W5Regular_11">"bar.h"</samp>` 时，`<samp class="SANS_TheSansMonoCd_W5Regular_11">#ifndef</samp>` 测试会检查 `<samp class="SANS_TheSansMonoCd_W5Regular_11">BAR_H</samp>` 是否未定义，并返回 `<samp class="SANS_TheSansMonoCd_W5Regular_11">true</samp>`。然后，我们定义宏 `<samp class="SANS_TheSansMonoCd_W5Regular_11">BAR_H</samp>`，并使用一个空的替换列表，这足以定义 `<samp class="SANS_TheSansMonoCd_W5Regular_11">BAR_H</samp>`，并且包含了 `<samp class="SANS_TheSansMonoCd_W5Regular_11">func</samp>` 的函数定义。第二次包含 `<samp class="SANS_TheSansMonoCd_W5Regular_11">"bar.h"</samp>` 时，预处理器不会生成任何标记，因为条件包含测试返回 `<samp class="SANS_TheSansMonoCd_W5Regular_11">false</samp>`。因此，`<samp class="SANS_TheSansMonoCd_W5Regular_11">func</samp>` 只会在最终的翻译单元中定义一次。

选择用于头文件保护的标识符时，一种常见做法是使用文件路径、文件名和扩展名的显著部分，用下划线分隔并全部大写。例如，如果你有一个头文件会通过 `<samp class="SANS_TheSansMonoCd_W5Regular_11">#include "foo/bar/baz.h"</samp>` 被包含，你可以选择 `<samp class="SANS_TheSansMonoCd_W5Regular_11">FOO_BAR_BAZ_H</samp>` 作为头文件保护标识符。

一些集成开发环境（IDE）会自动为你生成头文件保护。避免使用保留的标识符作为头文件保护的标识符，因为这可能会引入未定义的行为。以下划线开头并紧跟大写字母的标识符是保留的。例如，`<samp class="SANS_TheSansMonoCd_W5Regular_11">_FOO_H</samp>` 是一个保留的标识符，作为用户选择的头文件保护标识符并不好，即使你正在包含一个名为 `*_foo.h*` 的文件。使用保留的标识符可能会与实现中定义的宏发生冲突，导致编译错误或代码不正确。

## <samp class="SANS_Futura_Std_Bold_B_11">宏定义</samp>

`<samp class="SANS_TheSansMonoCd_W5Regular_11">#define</samp>` 预处理指令定义了一个宏。你可以使用*宏*来定义常量值或具有通用参数的类似函数的结构。宏定义包含一个（可能为空的）*替换列表*—这是一个代码模式，当预处理器扩展宏时会注入到翻译单元中：

```
#define `identifier` `replacement-list`
```

`<samp class="SANS_TheSansMonoCd_W5Regular_11">#define</samp>` 预处理指令以换行符结束。在以下示例中，`<samp class="SANS_TheSansMonoCd_W5Regular_11">ARRAY_SIZE</samp>` 的替换列表为 `<samp class="SANS_TheSansMonoCd_W5Regular_11">100</samp>`：

```
#define ARRAY_SIZE 100
int array[ARRAY_SIZE];
```

在这里，<samp class="SANS_TheSansMonoCd_W5Regular_11">ARRAY_SIZE</samp>标识符会被<samp class="SANS_TheSansMonoCd_W5Regular_11">100</samp>所替代。如果没有指定替换列表，预处理器将直接删除宏名。你通常可以在编译器的命令行上指定宏定义——例如，使用 Clang 和 GCC 中的<samp class="SANS_TheSansMonoCd_W5Regular_11">-D</samp>标志，或者在 Visual C++中使用<samp class="SANS_TheSansMonoCd_W5Regular_11">/D</samp>标志。对于 Clang 和 GCC，命令行选项<samp class="SANS_TheSansMonoCd_W5Regular_11">-DARRAY_SIZE=100</samp>指定宏标识符<samp class="SANS_TheSansMonoCd_W5Regular_11">ARRAY_SIZE</samp>被替换为<samp class="SANS_TheSansMonoCd_W5Regular_11">100</samp>，产生与前面示例中的<samp class="SANS_TheSansMonoCd_W5Regular_11">#define</samp>预处理指令相同的结果。如果你在命令行上没有指定宏替换列表，编译器通常会提供一个默认的替换列表。例如，<samp class="SANS_TheSansMonoCd_W5Regular_11">-DFOO</samp>通常与<samp class="SANS_TheSansMonoCd_W5Regular_11">#define FOO 1</samp>是等效的。

宏的作用范围持续到预处理器遇到一个<samp class="SANS_TheSansMonoCd_W5Regular_11">#undef</samp>预处理指令，或者直到翻译单元的结束。与变量或函数声明不同，宏的作用范围独立于任何代码块结构。

你可以使用<samp class="SANS_TheSansMonoCd_W5Regular_11">#define</samp>指令来定义一个类似对象的宏或类似函数的宏。*类似函数*的宏是有参数的，并且在调用时需要传递（可能为空的）参数集合，类似于你调用一个函数的方式。与函数不同，宏允许你使用程序的符号执行操作，这意味着你可以创建一个新的变量名，或者引用宏被调用时所在的源文件和行号。*类似对象*的宏是一个简单的标识符，将被一个代码片段所替代。

表 9-5 说明了函数式宏和对象式宏之间的区别。<samp class="SANS_TheSansMonoCd_W5Regular_11">FOO</samp> 是一个对象式宏，在宏展开过程中被替换为标记 <samp class="SANS_TheSansMonoCd_W5Regular_11">(1</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">1)</samp>，而 <samp class="SANS_TheSansMonoCd_W5Regular_11">BAR</samp> 是一个函数式宏，在宏展开过程中被替换为标记 <samp class="SANS_TheSansMonoCd_W5Regular_11">(1</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">(x))</samp>，其中 <samp class="SANS_TheSansMonoCd_W5Regular_11">x</samp> 是调用 <samp class="SANS_TheSansMonoCd_W5Regular_11">BAR</samp> 时指定的任何参数。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-5：</samp> <samp class="SANS_Futura_Std_Book_11">宏定义</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">结果翻译单元</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">#define FOO (1</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">1</samp><samp class="SANS_Futura_Std_Book_11">)</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#define BAR(x) (1</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">(x))</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int i</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">FOO;</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int j</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">BAR(10);</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int k</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">BAR(2</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">2);</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">int i</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">(1</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">1);</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int j</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">(1</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">(10));</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int k</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">(1</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">(2</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">2));</samp> |

函数式宏定义的左括号必须紧跟宏名，中间不能有空格。如果宏名和左括号之间出现空格，那么括号将成为替换列表的一部分，就像对象式宏<samp class="SANS_TheSansMonoCd_W5Regular_11">FOO</samp>一样。宏的替换列表以宏定义中的第一个换行符为终止符。然而，你可以通过在换行符前添加反斜杠（<samp class="SANS_TheSansMonoCd_W5Regular_11">\</samp>）将多行源代码连接起来，从而让你的宏定义更加易于理解。例如，考虑以下计算浮点数参数立方根的<samp class="SANS_TheSansMonoCd_W5Regular_11">cbrt</samp>类型通用宏定义：

```
#define cbrt(X) _Generic((X), \
  long double: cbrtl(X),      \
  default: cbrt(X),           \
  float: cbrtf(X)             \
)
```

该定义等效于，但更易于阅读，以下内容：

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">#define cbrt(X) _Generic((X), long double: cbrtl(X), default: cbrt(X), float: cbrtf(X))</samp>
```

定义宏时的一个危险是，你不能在程序的其他部分继续使用宏的标识符，否则会导致宏替换。例如，由于宏展开，下面的无效程序无法编译：

```
#define foo (1 + 1)
void foo(int i);
```

这是因为预处理器从翻译器接收到的令牌会导致以下无效代码：

```
void (1 + 1)(int i);
```

你可以通过始终遵循一种习惯来解决这个问题，例如将宏名称定义为全大写字母，或在所有宏名称前加上助记符，就像某些匈牙利命名法风格中所做的那样。

> <samp class="SANS_Dogma_OT_Bold_B_15">注意</samp>

匈牙利命名法 *是一种标识符命名约定，其中变量或函数的名称表示其意图或类型，并且在某些方言中，它还表示变量的类型。*

定义宏后，重新定义宏的唯一方法是使用 `<samp class="SANS_TheSansMonoCd_W5Regular_11">#undef</samp>` 指令。一旦取消定义，该命名标识符就不再表示一个宏。例如，表 9-6 中显示的程序定义了一个类似函数的宏，包含一个使用该宏的头文件，然后取消定义该宏，以便以后可以重新定义它。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-6：</samp> <samp class="SANS_Futura_Std_Book_11">取消定义宏</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">结果翻译单元</samp> |
| --- | --- |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">header.h</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">NAME(first)</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">NAME(second)</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">NAME(third)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">enum Names {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  first,</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  second,</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  third,</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">};</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">void func(enum Names Name) {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  switch (Name){</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">    case first:</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">    case second:</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">    case third:</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  }</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">file.c</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">enum Names {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#define NAME(X) X,</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#include "header.h"</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#undef NAME</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">};</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">void func(enum Names Name) {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  switch (Name) {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#define NAME(X) case X:</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#include "header.h"</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#undef NAME</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  }</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |

第一次使用<samp class="SANS_TheSansMonoCd_W5Regular_11">NAME</samp>宏会声明枚举<samp class="SANS_TheSansMonoCd_W5Regular_11">Names</samp>中的枚举项名称。<samp class="SANS_TheSansMonoCd_W5Regular_11">NAME</samp>宏被取消定义，然后重新定义，用于在<samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp>语句中生成<samp class="SANS_TheSansMonoCd_W5Regular_11">case</samp>标签。

取消定义宏是安全的，即使命名标识符不是宏的名称。这个宏定义无论<samp class="SANS_TheSansMonoCd_W5Regular_11">NAME</samp>是否已经定义，都能正常工作。为了简洁起见，本书中通常不遵循这种做法。

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">宏替换</samp>

类函数宏看起来像函数，但行为不同。当预处理器遇到一个宏标识符时，它会调用该宏，宏会展开标识符，并用宏定义中指定的替换列表中的令牌替换它。

对于类似函数的宏，预处理器会在展开宏时，用宏调用中的对应参数替换替换列表中的所有参数。任何在替换列表中以<samp class="SANS_TheSansMonoCd_W5Regular_11">#</samp>符号为前缀的参数，会被替换为一个包含该参数预处理令牌文本的字符串字面量令牌（这个过程有时称为*字符串化*）。表 9-7 中的<samp class="SANS_TheSansMonoCd_W5Regular_11">STRINGIZE</samp>宏会将<samp class="SANS_TheSansMonoCd_W5Regular_11">x</samp>的值进行字符串化。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-7：</samp> <samp class="SANS_Futura_Std_Book_11">字符串化</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源代码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">生成的翻译单元</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">#define STRINGIZE(x) #x</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">const char *str</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">STRINGIZE(12);</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">const char *str</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">"12";</samp> |

预处理器还会删除替换列表中所有出现的 <samp class="SANS_TheSansMonoCd_W5Regular_11">##</samp> 预处理标记，将前面的预处理标记与后面的标记连接起来，这个过程称为 *标记粘贴*。在表 9-8 中，<samp class="SANS_TheSansMonoCd_W5Regular_11">PASTE</samp> 宏用于通过连接 <samp class="SANS_TheSansMonoCd_W5Regular_11">foo</samp>、下划线字符 (<samp class="SANS_TheSansMonoCd_W5Regular_11">_</samp>) 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">bar</samp> 来创建一个新的标识符。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-8：</samp> <samp class="SANS_Futura_Std_Book_11">标记粘贴</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">翻译后的单元</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">#define PASTE(x, y) x ## _ ## y</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int PASTE(foo, bar)</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">12;</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">int foo_bar</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">12;</samp> |

在宏展开后，预处理器会重新扫描替换列表以展开其中的额外宏。如果预处理器在重新扫描时发现正在展开的宏名称——包括在替换列表中嵌套宏展开的重新扫描——它不会再次展开该名称。此外，如果宏展开结果形成了与预处理指令相同的程序文本片段，则该片段不会被当作预处理指令处理。

在宏展开过程中，替换列表中的重复参数名称会多次被调用时传入的参数所替代。如果宏调用的参数涉及副作用，这可能会产生令人意外的效果，正如在表 9-9 中所示。这一问题在 CERT C 规则 PRE31-C “避免在不安全宏的参数中使用副作用”中有详细说明。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-9：</samp> <samp class="SANS_Futura_Std_Book_11">不安全的宏展开</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">翻译后的单元</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">#define bad_abs(x) (x >=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">0 ? x : -x)</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">int func(int i) {</samp><samp class="SANS_Futura_Std_Book_11">  </samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  return bad_abs(i++);</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">int func(int i) {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  return (i++</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">>=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">0 ? i++</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">: -i++);</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp> |

在表 9-9 中的宏定义里，每个宏参数<samp class="SANS_TheSansMonoCd_W5Regular_11">x</samp>都会被宏调用参数<samp class="SANS_TheSansMonoCd_W5Regular_11">i++</samp>替换，导致<samp class="SANS_TheSansMonoCd_W5Regular_11">i</samp>被递增两次，这种情况是程序员或审查者在阅读原始源代码时很容易忽视的。像<samp class="SANS_TheSansMonoCd_W5Regular_11">x</samp>这样的参数以及替换列表本身，通常应当完全加括号，例如<samp class="SANS_TheSansMonoCd_W5Regular_11">((x) >=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">0 ? (x) : -(x))</samp>，以防止参数<samp class="SANS_TheSansMonoCd_W5Regular_11">x</samp>与替换列表中的其他元素以意外的方式结合。

GNU 的*语句表达式*允许你在表达式中使用循环、switch 语句和局部变量。语句表达式是 GCC、Clang 和其他编译器支持的非标准编译器扩展。通过使用语句表达式，你可以将<samp class="SANS_TheSansMonoCd_W5Regular_11">bad_abs(x)</samp>重写为如下形式：

```
#define abs(x) ({               \
  auto x_tmp = x;               \
  x_tmp >= 0 ? x_tmp : x_tmp;   \
})
```

你可以安全地使用带有副作用操作数的<samp class="SANS_TheSansMonoCd_W5Regular_11">abs(x)</samp>宏。

另一个潜在的惊讶是，函数式宏调用中的逗号总是被解释为宏参数分隔符。C 标准中的<samp class="SANS_TheSansMonoCd_W5Regular_11">ATOMIC_VAR_INIT</samp>宏（在 C23 中已删除）演示了这种危险（表 9-10）。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-10：</samp> <samp class="SANS_Futura_Std_Book_11">该</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">ATOMIC_VAR_INIT</samp> <samp class="SANS_Futura_Std_Book_11">宏</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源代码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">结果翻译单元</samp> |
| --- | --- |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">stdatomic.h</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#define ATOMIC_VAR_INIT(value) (value)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11"><error></samp> |
| <samp class="SANS_Futura_Std_Book_Oblique_I_11">foo.c</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#include <stdatomic.h></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">struct S {</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">  int x, y;</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">};</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">Atomic struct S val</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">ATOMIC_VAR_INIT({1, 2});</samp> |

这段代码无法正确翻译，因为 <samp class="SANS_TheSansMonoCd_W5Regular_11">ATOMIC_VAR_INIT({1, 2})</samp> 中的逗号被当作函数式宏参数分隔符，导致预处理器将宏解释为包含两个语法无效的参数 <samp class="SANS_TheSansMonoCd_W5Regular_11">{1</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">2}</samp>，而不是一个有效的参数 <samp class="SANS_TheSansMonoCd_W5Regular_11">{1, 2}</samp>。这个可用性问题是 <samp class="SANS_TheSansMonoCd_W5Regular_11">ATOMIC_VAR_INIT</samp> 宏在 C17 中被弃用，并在 C23 中被移除的原因之一。

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">类型通用宏</samp>

C 编程语言不允许像 Java 和 C++ 等其他语言那样，基于传递给函数的参数类型来重载函数。然而，有时你可能需要根据参数类型改变算法的行为。例如，<samp class="SANS_TheSansMonoCd_W5Regular_11"><math.h></samp> 中有三个 <samp class="SANS_TheSansMonoCd_W5Regular_11">sin</samp> 函数（<samp class="SANS_TheSansMonoCd_W5Regular_11">sin</samp>，<samp class="SANS_TheSansMonoCd_W5Regular_11">sinf</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">sinl</samp>），因为每种浮点数类型（<samp class="SANS_TheSansMonoCd_W5Regular_11">double</samp>，<samp class="SANS_TheSansMonoCd_W5Regular_11">float</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">long double</samp>）的精度不同。通过使用通用选择表达式，你可以定义一个单一的类似函数的标识符，在调用时根据参数类型委托给正确的底层实现。

*通用选择表达式*将其未求值的操作数表达式的类型映射到一个关联表达式。如果没有任何关联类型匹配，它可以选择性地映射到一个默认表达式。你可以使用*类型通用宏*（包含通用选择表达式的宏）使你的代码更具可读性。在表 9-11 中，我们定义了一个类型通用宏，用于从<samp class="SANS_TheSansMonoCd_W5Regular_11"><math.h></samp>中选择正确的<samp class="SANS_TheSansMonoCd_W5Regular_11">sin</samp>函数变体。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-11：</samp> <samp class="SANS_Futura_Std_Book_11">作为宏的通用选择表达式</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始来源</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">结果</samp> <samp class="SANS_TheSansMonoCd_W7Bold_B_11">_ 通用</samp> <samp class="SANS_Futura_Std_Heavy_B_11">解析</samp> |
| --- | --- |

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">#define singen(X) _Generic((X), \</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  float: sinf,                  \</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  double: sin                   \</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  long double: sinl             \</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">)(X)</samp>

<samp class="SANS_TheSansMonoCd_W5Regular_11">int main() {</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  printf("%f, %Lf\n",</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">    singen(3.14159),</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">    singen(1.5708L)</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  );</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">int main() {</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  printf("%f, %Lf\n",</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">    sin(3.14159),</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">sinl(1.5708L)</samp> 
<samp class="SANS_TheSansMonoCd_W5Regular_11">);</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp>
```

|

通用选择表达式的控制表达式<samp class="SANS_TheSansMonoCd_W5Regular_11">(X)</samp>尚未求值；表达式的类型从<samp class="SANS_TheSansMonoCd_W5Regular_11">type : expr</samp>映射列表中选择一个函数。通用选择表达式从这些函数设计符号中选择一个（可以是<samp class="SANS_TheSansMonoCd_W5Regular_11">sinf</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">sin</samp>或<samp class="SANS_TheSansMonoCd_W5Regular_11">sinl</samp>），然后执行该函数。在这个例子中，第一次调用<samp class="SANS_TheSansMonoCd_W5Regular_11">singen</samp>时，参数类型是<samp class="SANS_TheSansMonoCd_W5Regular_11">double</samp>，因此通用选择解析为<samp class="SANS_TheSansMonoCd_W5Regular_11">sin</samp>，而第二次调用<samp class="SANS_TheSansMonoCd_W5Regular_11">singen</samp>时，参数类型是<samp class="SANS_TheSansMonoCd_W5Regular_11">long double</samp>，因此解析为<samp class="SANS_TheSansMonoCd_W5Regular_11">sinl</samp>。因为该通用选择表达式没有<samp class="SANS_TheSansMonoCd_W5Regular_11">default</samp>关联，如果<X>的类型与任何已关联类型不匹配，则会发生错误。如果你为通用选择表达式包含了默认关联，它将匹配所有未作为关联使用的类型，包括一些你可能没有预料到的类型，如指针或结构体类型。

当结果值的类型依赖于宏参数的类型时，使用类型泛化宏扩展可能会变得困难，就像表格 9-11 中的<code>singen</code>示例。例如，调用<code>singen</code>宏并将结果赋值给特定类型的对象，或者将其结果作为参数传递给<code>printf</code>，可能会出现错误，因为所需的对象类型或格式说明符取决于调用的是<code>sin</code>、<code>sinf</code>还是<code>sinl</code>。你可以在 C 标准库的<code><tgmath.h></code>头文件中找到数学函数的类型泛化宏示例。

C23 通过引入使用<code>auto</code>类型说明符的自动类型推断部分解决了这个问题，详细内容见第二章。在使用类型泛化宏初始化对象时，考虑使用自动类型推断，以避免在初始化时发生不必要的转换。例如，以下文件范围的定义

```
static auto a = sin(3.5f);
static auto p = &a;
```

被解释为如下形式：

```
static float a = sinf(3.5f);
static float *p = &a;
```

实际上，<code>a</code>是一个浮动类型，而<code>p</code>是一个浮动类型的指针<code>*</code>。

在表格 9-12 中，我们将<code>main</code>中声明的两个变量的类型从表格 9-11 中的类型替换为<code>auto</code>类型说明符。这使得调用类型泛化宏更为方便，尽管这并不是严格必要的，因为程序员也可以推导出这些类型。<code>auto</code>类型说明符在调用类型泛化的类似函数的宏时非常有用，因为结果值的类型依赖于宏参数，从而避免在初始化时发生意外的类型转换。

<samp class="SANS_Futura_Std_Heavy_B_11">表格 9-12:</samp> <samp class="SANS_Futura_Std_Book_11">具有自动类型推断的类型泛化宏</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源代码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">结果</samp> <samp class="SANS_TheSansMonoCd_W7Bold_B_11">_ 泛化</samp> <samp class="SANS_Futura_Std_Heavy_B_11">解析</samp> |
| --- | --- |

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">#define singen(X) _Generic((X), \</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  float: sinf,                  \</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  double: sin,                  \</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  long double: sinl             \</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">)(X)</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">int main(void) {</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">auto f</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">singen(1.5708f);</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">auto d</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">singen(3.14159);</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">int main(void) {</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  auto f</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">sinf(1.5708f);</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">  auto d</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">sin(3.14159);</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">}</samp>
```

|

你还可以在声明类型泛化宏中的变量时使用<code>auto</code>类型说明符，尤其是在你不知道参数类型的情况下。

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">嵌入式二进制资源</samp>

你可能会发现，在运行时你需要动态加载数字资源，比如图像、声音、视频、文本文件或其他二进制数据。相反，将这些资源在编译时加载可能更为有利，这样它们可以作为可执行文件的一部分存储，而不是动态加载。

在 C23 之前，有两种常见的方法将二进制资源嵌入到程序中。对于有限的二进制数据，可以将数据指定为常量大小数组的初始化器。然而，对于较大的二进制资源，这种方法可能会引入显著的编译时间开销，因此需要使用链接脚本或其他后处理方法来保持合理的编译时间。

C23 增加了 <samp class="SANS_TheSansMonoCd_W5Regular_11">#embed</samp> 预处理指令，可以像逗号分隔的整数常量列表一样，将数字资源直接嵌入源代码中。这个新指令允许实现优化编译时间效率，当使用嵌入的常量数据作为数组初始化器时，可以提高效率。通过使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">#embed</samp>，实现不需要分别解析每个整数常量和逗号标记；它可以直接检查字节，并使用更高效的资源映射。

表 9-13 展示了将二进制资源 *file.txt* 嵌入作为 <samp class="SANS_TheSansMonoCd_W5Regular_11">buffer</samp> 数组声明的初始化器的示例。在这个示例中，*file.txt* 包含 ASCII 文本 <samp class="SANS_TheSansMonoCd_W5Regular_11">meow</samp>，以简短代码列表为目的。通常，嵌入的是显著更大的二进制资源。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-13：</samp> <samp class="SANS_Futura_Std_Book_11">嵌入二进制资源</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">原始源</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">结果翻译单元</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">unsigned char buffer[]</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">{</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">#embed <file.txt></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">};</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">unsigned char buffer[]</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">{</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">109, 101, 111, 119</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">};</samp> |

与 <samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp> 类似，<samp class="SANS_TheSansMonoCd_W5Regular_11">#embed</samp> 指令中指定的文件名可以用尖括号或双引号括起来。与 <samp class="SANS_TheSansMonoCd_W5Regular_11">#include</samp> 不同，嵌入资源没有 *系统* 或 *用户* 的概念，因此这两种形式的唯一区别是，双引号形式会先从与源文件相同的目录开始搜索资源，然后再尝试其他搜索路径。编译器提供了一个命令行选项来指定嵌入资源的搜索路径；有关更多细节，请参考编译器文档。

<samp class="SANS_TheSansMonoCd_W5Regular_11">#embed</samp> 指令支持多个参数来控制哪些数据嵌入到源文件中：<samp class="SANS_TheSansMonoCd_W5Regular_11">limit</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">suffix</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">prefix</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">if_empty</samp>。其中最有用的参数是 <samp class="SANS_TheSansMonoCd_W5Regular_11">limit</samp> 参数，用于指定嵌入多少数据（以字节为单位）。如果在编译时只需要文件头部的内容，或者文件是某些操作系统中像 */dev/urandom* 这样的 *无限* 资源，这个参数会很有用。<samp class="SANS_TheSansMonoCd_W5Regular_11">prefix</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">suffix</samp> 参数分别在嵌入的资源前后插入标记（如果资源已找到且不为空）。如果嵌入的资源被找到但没有内容（包括当 <samp class="SANS_TheSansMonoCd_W5Regular_11">limit</samp> 参数被显式设置为 0 时），则 <samp class="SANS_TheSansMonoCd_W5Regular_11">if_empty</samp> 参数会插入标记。

类似于 <samp class="SANS_TheSansMonoCd_W5Regular_11">__has_include</samp>，你可以使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">__has_embed</samp> 预处理器操作符测试是否能找到嵌入的资源。该操作符返回：

+   <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_EMBED_FOUND__</samp> 如果资源已找到且不为空

+   <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_EMBED_EMPTY__</samp> 表示资源已找到且为空

+   <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_EMBED_NOT_FOUND__</samp> 表示未找到资源

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">预定义宏</samp>

实现定义了一些宏，无需你包含头文件。这些宏被称为*预定义宏*，因为它们是由预处理器隐式定义的，而不是由程序员显式定义的。例如，C 标准定义了各种宏，可以用来查询编译环境或提供基本功能。实现的其他方面（如编译器或目标操作系统）也会自动定义宏。表 9-14 列出了 C 标准定义的一些常见宏。你可以通过向 Clang 或 GCC 编译器传递 <samp class="SANS_TheSansMonoCd_W5Regular_11">-E -dM</samp> 标志，获取完整的预定义宏列表。有关更多信息，请查阅你的编译器文档。

<samp class="SANS_Futura_Std_Heavy_B_11">表 9-14:</samp> <samp class="SANS_Futura_Std_Book_11">预定义宏</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">宏名称</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">替换及其目的</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__DATE__</samp> | <samp class="SANS_Futura_Std_Book_11">一个字符串字面量，表示预处理翻译单元的翻译日期，格式为</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">Mmm dd yyyy</samp><samp class="SANS_Futura_Std_Book_11">。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__TIME__</samp> | <samp class="SANS_Futura_Std_Book_11">一个字符串字面量，表示预处理翻译单元的翻译时间，格式为</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">hh:mm:ss</samp><samp class="SANS_Futura_Std_Book_11">。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__FILE__</samp> | <samp class="SANS_Futura_Std_Book_11">一个字符串字面量，表示当前源文件的假定文件名。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__LINE__</samp> | <samp class="SANS_Futura_Std_Book_11">一个整数常量，表示当前源代码行的假定行号。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC__</samp> | <samp class="SANS_Futura_Std_Book_11">如果实现符合 C 标准，则为整数常量 1。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_HOSTED__</samp> | <samp class="SANS_Futura_Std_Book_11">如果实现是托管实现，则为整数常量 1；如果是独立实现，则为整数常量 0。此宏由实现条件性地定义。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_VERSION__</samp> | <samp class="SANS_Futura_Std_Book_11">一个整数常量，表示编译器目标的 C 标准版本，例如</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">202311L</samp> <samp class="SANS_Futura_Std_Book_11">表示 C23 标准。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_UTF_16__</samp> | <samp class="SANS_Futura_Std_Book_11">如果类型为</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">char16_t</samp> <samp class="SANS_Futura_Std_Book_11">的值是 UTF-16 编码，则为整数常量 1。该宏由实现条件性定义。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_UTF_32__</samp> | <samp class="SANS_Futura_Std_Book_11">如果类型为</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">char32_t</samp> <samp class="SANS_Futura_Std_Book_11">的值是 UTF-32 编码，则为整数常量 1。该宏由实现条件性定义。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_NO_ATOMICS__</samp> | <samp class="SANS_Futura_Std_Book_11">如果实现不支持原子类型，包括</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">_Atomic</samp> <samp class="SANS_Futura_Std_Book_11">类型限定符和</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"><stdatomic.h></samp> <samp class="SANS_Futura_Std_Book_11">头文件，则为整数常量 1。该宏由实现条件性定义。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_NO_COMPLEX__</samp> | <samp class="SANS_Futura_Std_Book_11">如果实现不支持复数类型或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"><complex.h></samp> <samp class="SANS_Futura_Std_Book_11">头文件，则为整数常量 1。该宏由实现条件性定义。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_NO_THREADS__</samp> | <samp class="SANS_Futura_Std_Book_11">如果实现不支持</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"><threads.h></samp> <samp class="SANS_Futura_Std_Book_11">头文件，则为整数常量 1。该宏由实现条件性定义。</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">__STDC_NO_VLA__</samp> | <samp class="SANS_Futura_Std_Book_11">如果实现不支持可变长度数组，则为整数常量 1。该宏由实现条件性定义。</samp> |

## <samp class="SANS_Futura_Std_Bold_B_11">总结</samp>

在这一章中，你学习了预处理器提供的一些功能。你学习了如何将程序文本片段包含到翻译单元中，如何条件编译代码，如何将二进制资源嵌入到程序中，以及如何按需生成诊断信息。然后，你学习了如何定义和取消定义宏，宏是如何被调用的，以及实现中预定义的宏。预处理器在 C 语言编程中很常见，但在 C++ 编程中则较少使用。使用预处理器容易出错，因此最好遵循*The CERT C Coding Standard*中的建议和规则。

在下一章中，你将学习如何将程序结构化为多个翻译单元，从而创建更易维护的程序。

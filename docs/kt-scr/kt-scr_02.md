

## 第一章：1 Kotlin 基础



![](img/icon.jpg)

本章将引导你了解 Kotlin 编程语言的基本构建模块。我们将探索语言的核心特性，如注释、变量、运算符、流程控制结构、函数（包括 Lambda 表达式）以及基本的输入输出技术。

这些元素结合起来，允许你在代码中管理和操作数据，控制程序的行为，使其能够动态响应不同的场景，同时保持代码的良好组织和易于维护。理解这些基本元素也为第二章中讨论的更复杂语言特性打下基础，例如数组、集合和自定义数据结构（包括类）。

这里涉及的主题是任何编程语言中的核心元素，是应用程序开发的基础。如果你已经使用过其他语言，这些元素在 Kotlin 中看起来会很熟悉。反之，如果 Kotlin 是你的第一种语言，你在这里学到的知识也可以轻松迁移到其他语言。我们将以实践的方式探索这些组件，每个新想法都有简短的代码片段进行说明。在本章的末尾，我们将通过一个简单的项目将所有内容串联起来。

我假设你正在使用 IntelliJ IDEA 的免费版本作为开发环境（IDE）来开发和运行代码。有关安装、设置和使用该工具的说明，请参见附录，并试着运行一个基本的“Hello, world!”程序。

### 使用注释

*注释* 是代码文件中一行（或多行）解释性文本，编译器在运行代码时会忽略这些文本。文本的目的是提供有用的提示，例如下一段代码的作用、为什么选择特定方法，或如何在代码段中正确使用某个语言特性。在编写代码时，你应该插入注释，以提醒自己每一段代码的含义。经验丰富的程序员知道，文档化代码是防止将来遗忘重要细节的关键。而且，当其他人使用或基于你的代码进行开发时，你的注释可能会成为救命稻草。

在 Kotlin 中，你有两种主要方式来添加注释。第一种是使用 // 来开始单行注释。编译器会忽略双斜杠后的内容。另一种方法是使用 /* 和 */ 来开始和结束跨越多行的注释。以下是这两种注释风格的示例：

```
// This is a single-line comment.

/*
   This code block will be ignored by the compiler
   as it is inside a multiline comment block.
*/
```

Kotlin 还提供了第三种类型的注释，用于自动生成文档。这种注释以 /** 开始，以 */ 结束。文档注释用于更正式地描述变量、函数和类，并且通常包含 @param、@return 和 @throws 等标签，用以解释代码的标准部分。以下是一个比较多行注释和文档注释的示例：

```
/* This is a multiline comment
   used for providing useful tips or reminders. */

/**
* This is a documentation comment.
*
* @param name The name of the person
* @return The greeting string
*/
fun greet(name: String): String {
    return "Hello, $name!"
}
```

虽然这两种类型的注释使用了相似的语法，但它们的目的不同。多行注释旨在代码文件内部阅读。而文档注释则是为了从代码文件中导出，以生成正式的文档供其他开发人员参考生产就绪代码。

### 变量

在编程中，*变量*是赋予数据元素的名称。为了简单起见，我们可以将变量视为存储计算机内存中各种数据类型的容器。一旦赋值，变量名就可以作为它所代表的值的代名词。通过这种方式，变量使我们能够存储和管理数据，从而实现程序中信息的持久性。

每个变量应该有一个有意义的名称，清楚地描述它的用途或功能，或者反映所赋予数据的性质。例如，存储一个人名字的变量可以叫做 name，而存储一个人年龄的变量可以叫做 age。根据约定，变量名应由小写单词组成，或者使用*驼峰命名法*连接多个单词。在后一种情况下，单词之间没有空格，每个单词的首字母大写，例如 lastName 或 ageInYears。

在 Kotlin 中，你可以通过使用关键字如 val 或 var 声明变量的名称，并为其*初始化*（赋值）。(*关键字*是编程语言中具有特殊含义的保留字。关键字不能作为标识符使用——例如，不能用作变量名或函数名。) 你选择哪个关键字取决于你是否希望变量的值在程序执行期间保持不变或发生变化。使用 val 声明的变量是*只读的*，意味着其值在初始化后不能更改。使用 var 声明的变量是*可变的*，意味着该变量在初始化后可以被赋予不同的值。你可以根据需要多次更改可变变量的值。

参考这个例子，我们使用两个变量创建一个消息：

```
fun main() {
    val name = "John Sinclair"
    val age = 30
    println("$name is $age years old")
}
```

我们声明了两个变量，name 和 age，并分别为它们赋值为“John Sinclair”和 30。这两个变量都是使用 val 关键字声明的，因此它们不能在之后被重新赋值。然后，我们通过在每个变量名前加上美元符号（$）将这两个变量包含在要打印到控制台的消息中。（我们将在“处理字符串”一章中详细讨论这种语法的工作原理，请参见第 14 页。）如果你运行这段代码（在 IntelliJ IDEA 中使用 CTRL-SHIFT-F10），输出应该如下所示：

```
John Sinclair is 30 years old
```

注意输出中显示的是赋给 name 和 age 变量的值，而不是变量名本身。但如果我们希望在程序执行过程中为这些变量赋予新值怎么办？为此，我们必须使用 var 关键字，而不是 val，如下所示：

```
fun main() {
    var name = "John Sinclair"
    var age = 30
    println("$name is $age years old")
  ❶ name = "John Sinclair Jr."
    age = 12
    println("$name is $age years old")
}
```

在这里，我们使用 `var` 关键字声明了 `name` 和 `age` 变量，赋予它们与之前相同的初始值。然后我们给它们分配了新值 ❶。注意第二次赋值时，我们不再需要 `var`（或 `val`）关键字。一旦我们第一次声明并初始化了变量，就可以仅使用变量名来操作它。

如果现在运行程序，应该看到以下内容：

```
John Sinclair is 30 years old
John Sinclair Jr. is 12 years old
```

我们已经成功地重新分配了变量名，因为它们是用 `var` 关键字声明的。尝试将 `var` 关键字改回 `val`，然后重新运行代码。IDE 会立即生成一条错误信息，说明不能给用 `val` 声明的变量赋新值，在修复错误之前无法运行程序。

#### 常量

Kotlin 还提供了 `const` 关键字（*constant* 的缩写），用于在文件开始时设置不可变的变量值。该值必须在代码编译期间已知。仅允许对原始数据类型或字符串使用 `const` 声明变量。（我们将在下一节中讨论 Kotlin 的常见数据类型。）明智地使用常量有两个重要的好处：它提高了程序访问固定值的效率，并通过避免在代码深处硬编码没有明确上下文的“魔法数字”来提高代码的可读性。以下是使用 `const` 关键字创建变量的示例：

```
const val PI = 3.14159265359
```

在这种情况下，我们知道数学常量 pi 的值，并且我们知道这个值在程序执行过程中不会改变，所以在程序开始时使用 `const` 关键字声明它是合理的。在 Kotlin 中，习惯上使用全大写字母来表示顶级常量的名称，正如我们在这里为 PI 所做的那样。多个单词可以使用下划线连接。

Kotlin 还有许多其他命名约定适用于各种代码构造。表 1-1 总结了最常见的命名约定。

表 1-1：Kotlin 中的命名约定

| 名称 | 约定 | 示例 |
| --- | --- | --- |
| 包名 | 使用小写字母且不带下划线。连接多个单词或使用驼峰式命名法。使用反向域名表示法（由 IDE 自动生成）。 | org.example.myProject |
| 类名 | 对于类和继承名称，使用 PascalCase。选择名词或名词短语。 | FlightSimulation |
| 函数名 | 对于函数和方法名称，使用驼峰式命名法。使用动词或动词短语。 | calculateShortestPath() |
| 变量名 | 使用单个单词或驼峰式命名法连接多个单词。选择一个描述变量目的、功能或属性的单词（使其有意义）。 | username |
| 常量和最终变量名 | 使用大写字母并用下划线分隔单词。 | MAX_VALUE |

这些命名约定基于 [Kotlin 官方文档](https://kotlinlang.org) 中的建议。我们将在讨论与之相关的代码构造时重新回顾它们。

#### 常见数据类型

代码中的一个值可以是各种*数据类型*。例如，一个值可能表示数字、一些文本或逻辑值（真或假）。在 Kotlin 中，每个变量都与特定的数据类型相关联，一旦变量的数据类型被设置，它就不能包含其他类型的值。一个持有数值的变量可以关联不同的类型，例如，Int 仅用于整数，或者 Double 或 Float 用于包含小数部分的数字。一个持有文本值的变量可以是 Char 类型（单个字符）或 String 类型（多个字符）。一个逻辑值将是 Boolean 类型。表 1-2 列出了 Kotlin 中常见的数据类型及其主要特征。

表 1-2：Kotlin 常见数据类型

| 数据类型 | 描述 | 大小（以位为单位） | 值的范围 |
| --- | --- | --- | --- |
| Byte | 有符号整数 | 8 | –128 到 127 |
| Short | 有符号整数 | 16 | –32,768 到 32,767 |
| Int | 有符号整数 | 32 | –2,147,483,648 到 2,147,483,647 |
| Long | 有符号整数 | 64 | –9,223,372,036,854,775,808 到 9,223,372,036,854,775,807 |
| Float | 浮点数（单精度） | 32 | –3.4028235E+38 到 3.4028235E+38 |
| Double | 浮点数（双精度） | 64 | –1.7976931348623157E+308 到 1.7976931348623157E+308 |
| Char | 16 位 Unicode 字符 | 16 | 0 到 65,535（十进制） |
| Boolean | 表示真或假 | 1 | true 或 false |
| String | 字符序列 | 可变 | N/A |

我们根据特定问题的需求选择变量的数据类型，重点考虑数据类型能够容纳的值、精度级别和内存使用等因素。例如，如果你知道一个数值变量只会保存整数值，那么 Int 会比 Float 更合适。如果这些值需要非常大，那么 Long 会比 Int 更适用。

##### 类型推断

在 Kotlin 中声明变量时，并不强制要求显式指定其数据类型。Kotlin 编译器擅长根据赋予的值*推断*变量的数据类型。例如，在此代码中，Kotlin 会推断出 name 是 String 类型，因为它的值是由引号括起来的一系列字符：

```
val name = "John Sinclair"
```

你也可以选择显式声明变量的数据类型。以下是如何显式声明 name 为 String 类型：

```
val name: String = "John Sinclair"
```

要声明数据类型，我们在变量名后加冒号，后面跟上所需的类型。这可以是任何合法的数据类型，包括你可能创建的自定义数据类型，用于表示具有特定属性和行为的复杂结构（例如，类或数据类，我们将在第二章中讨论）。

对于数值类型，Kotlin 会推断如果变量第一次被赋予一个整数值，则为 Int 类型；如果赋值为一个带小数部分的值，则为 Double 类型。如果需要不同的数值类型，可以通过在值的末尾使用类型后缀显式地指明，例如 L 表示 Long，f 表示 Float。例如：

```
val regularInt = 42
val floatNumber = 3.14f
val longNumber = 123456789L
```

在这段代码中，regularInt 默认被推断为 Int 类型，而 floatNumber 和 longNumber 则通过使用 f 和 L 后缀显式声明为 Float 和 Long 类型。

##### 类型转换

*类型转换*，也称为*类型转换*，是将变量或表达式的数据类型转换为另一种兼容数据类型的过程。（*表达式*是评估为特定数据类型的代码片段。）这个过程主要用于解决类型不匹配问题。通常，Kotlin 会执行严格的类型检查，以防止常见的运行时错误来源，例如意外的类型转换。只有在不存在数据丢失或意外行为的风险时，才允许隐式类型转换。例如，可以隐式地将较小的数值类型提升为较大的数值类型，因为不存在数据丢失的风险，如下所示：

```
val intNumber = 22  // type inferred as Int
val longNumber: Long = intNumber  // implicit type casting
```

我们获取 intNumber 变量的值并将其赋给 longNumber 变量，隐式地将该值从 Int 类型转换为 Long 类型。这可能是有效的，但大多数 IDE 的默认设置是完全禁止使用隐式类型转换。相反，建议你使用显式的类型转换方法来实现类型转换。在 Kotlin 中，常见的类型转换方法包括 toByte()、toInt()、toLong()、toShort()、toDouble()、toFloat()、toChar()和 toString()。下面是一个显式类型转换的例子：

```
val intNumber = 44  // type inferred as Int
val doubleNumber: Double = intNumber.toDouble()
```

我们首先创建 intNumber 变量并赋值为 44。编译器将推断 intNumber 为 Int 类型。然后，我们使用 toDouble()方法将其显式转换为 Double 类型，并将其赋值给 doubleNumber。

由于类型转换仅在相关数据类型兼容时才允许，并非所有转换都是可能的。例如，你不能总是将文本类型转换为数值类型或逻辑类型。为了说明这一点，尝试运行以下代码行：

```
val message: String = "Hello, world!"
val intValue: Int = message.toInt()
```

在这里，我们尝试将消息变量中的字符串通过 toInt()方法转换为整数。这将在运行时抛出 NumberFormatException 错误，表示由于数据类型不兼容，转换无法完成。这个错误看起来是合理的：Kotlin 怎么知道“Hello, world!”字符串的数字等价物呢？

### 操作符

*操作符*是用于操作代码中变量和其他值的特殊符号。每个操作符执行特定的数学、逻辑或基于文本的操作。在本节中，我们将回顾 Kotlin 中最常见的操作符类别。

#### 算术

算术运算符用于执行基本的数学运算，如加法（+）、减法（-）、乘法（*）和除法（/）。以下是一些如何在 Kotlin 中使用算术运算符的例子：

```
val a = 20
val b = 7
val sum = a + b            // addition, yields 27
val difference = a – b     // subtraction, yields 13
val product = a * b        // multiplication, yields 140
val quotient = a / b       // division, yields 2
```

在这里，我们对 a 和 b 变量应用了四个主要的算术运算。请注意，当你使用除法运算符 `/` 除以两个整数时，结果也是一个整数，任何小数部分都会被舍弃。在这种情况下，20 / 7 的结果是 2，而不是 2.857143。如果你需要保留小数部分，必须将其中一个数字转换为浮点数，如下所示：

```
val a = 20
val b = 7
val quotientInt = a / b               // integer division
val quotientFloat = a.toFloat() / b   // real division
```

在这里，`quotientInt` 的值为 2，但 `quotientFloat` 的值为 2.857143，因为我们使用 `toFloat()` 将 a 从整数转换为浮点数。

*余数* 或 *取模* 运算符是我们在本书中将多次使用的另一个数学运算符。它由 `%` 符号表示。这个运算符仅返回两个数字整数除法的余数。以下是一个例子：

```
val a = 20
val b = 7
val result = a % b // The result is 6.
```

在这个例子中，`%` 运算符返回当 a 被 b 除时的余数。由于 20 除以 7 的余数是 6，所以结果的值是 6。你能猜出如果我们交换这两个数字——也就是计算 7 % 20，结果会是多少吗？另外，整数除法 7 / 20 的结果会是多少呢？这些问题可能听起来很简单，但我鼓励你写几行代码来验证你的猜测。

Kotlin 使用与常规数学相同的运算符优先级：除法和乘法优先于加法和减法。为了避免对运算顺序的混淆，最好使用括号来清晰地隔离不同的运算块。例如：

```
fun main() {
    // example without parentheses
    val resultWithoutParentheses = 5 + 3 * 2
    println("Result without parentheses: $resultWithoutParentheses")

    // example with parentheses
    val resultWithParentheses = (5 + 3) * 2
    println("Result with parentheses: $resultWithParentheses")
}
```

在第一个计算中，5 + 3 * 2，乘法优先于加法，因此计算为 5 + (3 * 2)，结果为 11。第二个计算中，(5 + 3) * 2，括号内的加法先执行，然后是乘法，结果为 16。这演示了如何通过使用括号来明确和控制数学表达式中的运算顺序。

#### 赋值

赋值运算符用于给变量赋值。在本章的例子中，我们已经使用了主要的赋值运算符（=）来初始化变量的值。其他赋值运算符，如 `+=` 和 `-=`，会修改变量的现有值。以下是一些例子：

```
var a = 10
a += 5         // equivalent to a = a + 5 (a becomes 15)
a -= 5         // equivalent to a = a – 5 (a becomes 5)
a *= 5         // equivalent to a = a * 5 (a becomes 50)
a /= 5         // equivalent to a = a / 5 (a becomes 2)
```

赋值 `a += 5` 相当于说：“取 a 的值，给它加 5，然后将结果放回 a 变量中。”其他三个算术运算的赋值运算符也有类似的用法。

如果字符串变量是用 `var` 声明的，你也可以尝试使用 `+=`。例如：

```
var s = "John Smith"
s += " Jr."           // The s becomes "John Smith Jr."
```

请注意，这个操作本质上是创建一个新的字符串并将其赋值给之前使用的变量名，而不是直接修改旧的字符串（旧字符串会被丢弃）。对于字符串，其他赋值运算符（例如，-=）会产生错误。

#### 一元

大多数运算符都有两个操作数，而一元运算符只有一个。*增量*（++）和 *减量*（--）一元运算符分别将变量的值增加或减少 1。以下是如何在 Kotlin 中使用这些运算符：

```
var a = 10
a++         // equivalent to a = a + 1 (a becomes 11)
a--         // equivalent to a = a – 1 (a becomes 10 again)
```

本质上，a++ 是 a += 1 的简写，a += 1 又是 a = a + 1 的简写。同样，a-- 等同于 a -= 1。

#### 关系

关系运算符比较两个值并根据比较结果返回布尔值（true 或 false）。这些运算符包括用于相等和不等的 == 和 !=，以及用于大于和小于的 > 和 <。以下是这些运算符的示例：

```
val a = 10
val b = 5
val isEqual = (a == b)      // equality check
val isNotEqual = (a != b)   // inequality check
val isGreater = (a > b)     // greater than check
val isLesser = (a < b)      // less than check
```

在这个代码段中，isEqual 将是 false，因为 a 和 b 不相等，isNotEqual 将是 true。与此同时，isGreater 将是 true，因为 a 大于 b，isLesser 将是 false。请注意，我们将每个比较放在括号中。这并不是严格必要的，但它有助于在视觉上将比较与它所参与的赋值操作分开。

前面的例子使用了数值，但关系运算符也可以用于比较字符串：

```
val text1 = "Hello"
val text2 = "World"
val isNotEqual = (text1 != text2) // true
val isGreater = (text1 > text2)   // false
```

在 Kotlin 中，字符串是按字典顺序逐字符比较的，基于它们的 Unicode 值。比较从每个字符串的第一个字符开始，直到找到差异或其中一个字符串结束为止。第一个不同字符的 Unicode 值较小的字符串被视为较小的字符串。这意味着字母表中较前的字母被认为较小，大写字母被认为较小于小写字母。

#### 逻辑

逻辑运算符用于对布尔值执行逻辑运算，如 AND（&&）、OR（||）和 NOT（!）。以下是如何在 Kotlin 中使用逻辑运算符的示例：

```
val x = true
val y = false

val andResult = (x && y)   // logical AND operation (returns false)
val orResult = (x || y)    // logical OR operation (returns true)
val notResult = !x         // logical NOT operation (returns false)
```

涉及两个布尔值的逻辑操作的结果可以通过一个 *真值表* 来总结，如表 1-3 所示。真值表显示了每个可能输入值组合对应的输出结果。

表 1-3：两个逻辑值的真值表

| Value 1 | Value 2 | AND | OR |
| --- | --- | --- | --- |
| true | true | true | true |
| true | false | false | true |
| false | true | false | true |
| false | false | false | false |

在这个表中，操作数是布尔值，可以是 true 或 false。例如，在第一行中，Value 1 和 Value 2 都为 true。对这些操作数进行 AND 操作的结果是 true，OR 操作的结果也是 true。与 AND 和 OR 不同，NOT 操作只有一个布尔操作数，并且该操作数会被取反。例如，NOT 操作符将 true 变为 false。

### 操作字符串

在 Kotlin 中，*字符串*是由 String 数据类型表示的一系列字符。字符串在程序中非常有用，可以用来存储和处理文本数据。它们通常用于表示单词、句子以及其他文本信息。用户输入的数据通常也会先作为字符串读取，然后根据需要通过函数如 toInt()、toDouble()和 toBoolean()转换为其他类型。

字符串中的各个字符是按顺序编号的，或者说是*索引*，从零开始。你可以通过在表示该字符串的变量名后面加上方括号中的索引来访问字符串中的特定字符。例如，要获取 msg 变量中字符串的第二个字符，可以使用 msg[1]。另外，你还可以使用 String 类的 get()方法来检索特定索引处的字符。例如，msg.get(1)返回与 msg[1]相同的第二个字符。

在本节中，我们将讨论一些常见的字符串操作技巧。在阅读时请记住，Kotlin 中的字符串是不可变对象，因此一旦创建了一个字符串，它的内容是无法更改的。任何看似修改字符串的操作都会创建一个新字符串，原始值会被丢弃。

#### 连接

*连接*是将两个或多个字符串合并为一个字符串的过程。在 Kotlin 中，你可以使用多种方式实现这一点。例如，你可以使用+运算符，或者你可以使用字符串的 plus()方法。这里演示了这两种技术：

```
val a = "Hello,"
val b = "world!"

// Use the plus (+) operator.
var c = a + " " + b
println(c) // output: Hello, world!

// Use the plus() method of the String class.
c = a.plus(" ").plus(b)
println(c) // output: Hello, world!
```

在这段代码中，我们首先创建了两个字符串变量 a 和 b，分别赋值为"Hello,"和"world!"。然后我们使用+运算符将两个字符串连接（拼接）在一起，并在它们之间添加一个空格（字符串" "），将结果字符串赋值给 c 变量。println(c)的输出是：

```
Hello, world!
```

注意我们在同一个表达式中调用了两次 plus()方法，将字符串 a 与空格以及字符串 b 连接起来。这种技术被称为*方法链*；第二次方法调用是应用于第一次方法调用的结果。

另一种连接多个字符串的方法是使用 buildString 函数，如以下示例所示：

```
val c = buildString {
           append("Hello,")
           append(" ")
           append("world!")
       }
println(c) // output: Hello, world!
```

我们创建了一个变量 c 来存储连接后的字符串，并通过一次调用 buildString 函数将所有字符串片段附加在一起。

#### 字符串模板

字符串中出现在开头和结尾的引号之间的大多数字符会被字面理解为普通文本。然而，*字符串模板*是 Kotlin 中的一个强大功能，它允许你在字符串中嵌入代码。它们是一种简洁而富有表现力的方式，可以将静态文本与来自变量、表达式甚至函数调用的动态值结合起来。如我们在最初讨论变量时所暗示的那样，字符串模板使用美元符号（$）来表示接下来的内容应被视为代码，而不是字面文本。例如，考虑以下代码片段：

```
val name = "John"
val age = 30
val message = "My name is $name and I'm $age years old."
println(message)
```

在这里，我们使用 $ 符号将变量 name 和 age 嵌入到消息字符串模板中。这些变量的值在字符串评估时会自动被替换为实际的值。因此，当你运行这段代码时，输出应该像这样：

```
My name is John and I'm 30 years old.
```

注意，John 和 30 已经替换了字符串中的 $name 和 $age。比较字符串模板语法与我们使用字符串连接生成相同消息的方式：

```
val message = "My name is " + name + " and I'm " + age + " years old."
```

字符串模板版本更加易读，省去了包含所有 + 操作符以及记得在每个变量前后添加空格的繁琐。这并不是说字符串连接永远没有用处，但如果你的目标是将代码中的值注入到字符串中，字符串模板可能是更好的选择。

字符串模板还可以处理更复杂的表达式，通过在美元符号后面使用大括号（{和}符号）将其括起来。这允许你在模板中直接执行计算、访问对象属性或调用函数。下面是一个例子：

```
val x = 20
val y = 15
val result = "$x + $y = ${x + y}"
println(result) // output: 20 + 15 = 35
```

这个字符串模板中的 ${x + y} 告诉 Kotlin 将 x 和 y 变量的值相加，并将结果插入到字符串中。

#### 转义序列

*转义序列* 是在字符串中表示像空白符这样难以直接输入的字符的特殊字符组合。它们以反斜杠为前缀。例如，转义序列 \n 表示换行符，\t 表示制表符。转义序列常用于字符串模板中以格式化输出。下面是一个例子：

```
fun main() {
    val name = "John"
    val age = 30

    // using escape characters in string template
    val message = "Name: $name\nAge: $age"

    println(message)
}
```

在这个例子中，消息字符串中间的 \n 添加了一个换行符，在姓名和年龄之间创建了一个行断裂，从而改善了输出的格式。如果你运行代码，输出应该会分成两行，如下所示：

```
Name: John
Age: 30
```

其他常见的转义序列包括 \\ 表示反斜杠和 \$ 表示美元符号。这些是必需的，因为如果没有这些符号，字符串中的反斜杠会被解释为转义序列的开始，而美元符号会被解释为开始 Kotlin 代码并将其插入到字符串模板中。

### Null 和可空类型

*Null* 表示没有值。默认情况下，Kotlin 的类型系统假设变量不能包含 null。考虑这个例子：

```
var str: String = "Hello, world!"  // valid initialization
str = null  // invalid, will result in compilation error
```

str 变量被声明为 String 类型，因此它的值必须是一个字符串。尝试将该变量设置为 null 将会触发错误。如果你想允许变量为 null，必须通过在类型声明后附加 ? 来显式声明变量为*可空类型*，如下所示：

```
var str: String? = "hello world" // valid initialization
str = null // reassigned to null, no compilation error
```

类型声明 str: String? 表示 str 变量可以包含字符串或 null。由于该变量是 String? 可空类型，因此将其设置为 null 现在是有效的，并且不会导致错误。

Kotlin 的默认非空类型系统旨在防止 *空指针异常*，这是在允许变量具有 null 值的语言中常见的运行时错误。空指针异常发生在程序尝试使用空引用访问或操作数据时，而空引用不指向有效的内存位置或对象。正确处理空值对于防止这些异常和程序崩溃至关重要。

你可以通过多种方式确保 Kotlin 中的空安全性。其中一种方法是在访问可空变量的属性或方法之前，显式地检查它是否为 null。例如：

```
val str: String? = "Hello, world!"
val len = if (str != null) str.length else -1
```

在这个示例中，我们通过使用 if...else 条件语句检查变量 str 是否为 null。如果 str 不是 null，则访问其 length 属性；否则，将 -1 赋值给 len。（我们将在下一节讨论条件语句。）

另一种机制是 Kotlin 的 *安全调用运算符* (?.)，它允许我们在可空对象上调用方法，而不会引发错误。如果对象为 null，结果也将是 null；否则，方法将像往常一样被调用。例如：

```
val len = str?.length
```

在这种情况下，如果 str 为 null，则 len 将被赋值为 null；否则，len 将被赋值为 str 的长度（字符数）。

Kotlin 还提供了 *Elvis 运算符* (?:)。它与安全调用运算符一起使用时，可以为涉及可空对象的表达式提供默认值（而非 null）。如果对象不是 null，则正常评估表达式；否则，将使用默认值。例如：

```
val len = str?.length ?: -1
```

在这种情况下，如果 str 不是 null，则其长度将被赋值给 len 变量；否则，将使用 ?: 运算符后的值（-1）。

> 注意

*到目前为止，我们讨论的示例主要集中在* String? *可空类型，但请注意，* ? *运算符也可以应用于其他数据类型，如* Int*、* Double*，甚至是* Boolean*。在处理用户输入时，使用可空类型的灵活性特别有帮助。*

最后，Kotlin 还有一个相关的运算符，叫做 *空断言运算符*（也称为 *双感叹号运算符*），用两个感叹号 (!!) 表示。它可以用来断言一个可空变量不为 null，尽管编译器无法保证这一点。使用 !! 是在告诉编译器你确信某个可空变量不为 null，这样编译器就会跳过 null 安全检查。以下是一个示例：

```
val name: String? = "John"
val length = name!!.length
```

我们将 name 声明为可空字符串，但在访问字符串的长度时使用 !!，这意味着我们断言它不为 null。如果 name 实际上为 null，代码将抛出 NullPointerException。因此，最好避免或限制使用空断言运算符，而是使用更安全的构造，如安全调用 (?.) 和空检查 (?:)。或者，旨在设计代码以减少可空类型，从而提高可靠性和可预测性。

### 流程控制

*流程控制*是编程中的一个重要方面，它提供了机制来调节代码的执行时机和方式。Kotlin 的流程控制结构使开发者能够通过有效管理语句的顺序和控制程序的行为，创建灵活且动态的程序。在本节中，我们将讨论两种重要的控制结构：条件语句和循环。这些概念是任何编程语言的基础。

#### 条件语句

条件语句允许你根据特定的测试来决定程序应该做什么。Kotlin 有两种主要的条件语句：if 和 when。它们都引入了代码的分支结构，即程序可以根据不同情况走不同的分支。一般来说，if 语句适用于直接的二元决策或面对有限条件时；而如果你需要处理多个条件、管理各种情况，或者在实现分支逻辑时希望代码更加简洁和结构化，when 可能是你的首选工具。

##### if 语句

当给定条件的计算结果为真时，if 语句会运行一段代码。以下是一个简单的示例：

```
val x = 10
if (x > 0) println("x is positive")
```

if 语句的条件，在本例中为 x > 0，必须是一个能够计算出布尔值（真或假）的表达式，并且必须放在 if 关键字后面的括号中。如果条件为真，条件后的代码将被执行，因此这段代码仅在变量 x 为正值时打印消息。如果 x 不是正数，println 语句将被跳过。

if 语句可以有一个可选的 else 子句，当测试表达式计算结果为假时，else 子句会被执行。一旦包含了 else 子句（或者只有 if 子句但包含了多行代码），每个子句的主体应该缩进并用花括号括起来，如下所示：

```
val x = -10
if (x > 0) {
    println("x is positive")
} else {
    println("x is not positive")
}
```

这次，由于 x > 0 条件计算结果为假，else 子句中的代码将被执行。注意，左花括号与 if 或 else 关键字在同一行，而右花括号则在该子句最后一条语句之后的新一行上。

你可以通过在初始 if 语句和最终 else 语句之间添加 else if 子句，扩展 if...else 结构来包含三个或更多的可能分支。每个 else if 子句都会添加一个新条件，用于测试前一个条件是否为假。以下是一个示例：

```
fun main() {
    val a = 100
    val b = -30
  ❶ val max: Int

    if (a > b) {
        max = a
        println("a is greater than b.")
        println("max of $a and $b is: $max")
    } else if (a < b) {
        max = b
        println("b is greater than a.")
 println("max of $a and $b is: $max")
    } else
        println("a and b have the same value: $a")
}
```

在这里，我们初始化了两个变量`a`和`b`，分别赋值为 100 和-30。随后，我们声明了一个类型为 Int 的`max`变量，但没有提供初始值❶。（在 Kotlin 中，只要变量在首次使用之前会被初始化，这是允许的。）然后，我们使用`if...else if...else`结构来比较`a`和`b`的值并打印相应的消息。首先，`if`子句测试`a`是否大于`b`。如果不成立，`else if`子句会测试`a`是否小于`b`。如果这个条件也不成立，那么`a`和`b`必须相等，因为`else`子句这么说。

这种控制结构的语法是：

```
if (`condition 1`) {
    // code to execute when condition 1 is true
} else if (`condition 2`) {
    // code to execute when condition 2 is true
} else {
    // code to execute when conditions 1 and 2 are not true
}
```

你可以通过添加更多的`else if`块或完全删除它们来调整这个模板，具体取决于你的需求。

##### when 语句

`when`语句会将一个值与多个条件进行比较，并执行第一个匹配条件的代码块。如果你熟悉 Java、C 或 C++等语言中的`switch`语句，概念是类似的。`when`语句还可以包含一个`else`子句，用于在没有条件匹配时执行，如下所示：

```
fun main() {
    val x = 5

    when {
        x > 0 -> println("x is positive")
        x == 0 -> println("x is zero")
        x < 0 -> println("x is negative")
        else -> println("x is not a real number")
    }
}
```

我们将 5 赋值给变量 x，然后使用`when`语句测试该变量的值。`when`语句的每一行都有自己的条件测试（如`x > 0`），后跟`->`符号，指向在条件为真时应执行的表达式。只要找到一个为真的条件，`when`语句将跳过其余部分，即使它包含其他可能满足的测试。在这个例子中，由于 x 大于 0，`when`语句会打印“x 是正数”。

与`if`语句一样，在`when`语句中包含`else`子句是可选的。然而，通常建议提供一个`else`子句；它通过为未匹配的情况提供后备选项，从而提高了代码的健壮性。

也可以在`when`关键字后立即用括号提供要测试的变量。在这种情况下，`when`语句会根据该变量的确切值或值的范围进行测试，而无需重复变量名。例如：

```
fun main() {
    val hour = 13

    when (hour) {
        in 0..11 -> println("Good morning")
        in 12..16 -> println("Good afternoon")
        in 17..23 -> println("Good evening")
        else -> println("Invalid hour")
    }
}
```

在这里，我们将`hour`变量传递给`when`语句，基于该变量的值打印不同的问候语。例如，0..11 中的条件测试`hour`的值是否在 0 到 11 之间（包括 0 和 11）。我们将在下一节讨论循环时，更详细地介绍如何使用`..`运算符指定值的范围。

#### 循环

*循环*是编程中不可或缺的结构，它们允许你多次重复一段代码。Kotlin 提供了几种类型的循环，每种都有其特定的使用场景和优势。在本节中，我们将探讨 Kotlin 中的循环，包括如何指定迭代的范围。

##### for 循环

一个 for 循环通过集合中的元素进行迭代，比如数组、列表或范围。一个常见的用法是遍历一系列数字，从而有效地创建一个固定次数重复的循环。正如我们刚才在 when 语句中看到的那样，Kotlin 使用 .. 运算符来指定一个包含上限的范围。下面是这种语法如何与 for 循环配合使用的：

```
// inclusive range (1 to 4)
for (i in 1..4) {
    println("Current value of i is: $i")
}
```

一个 for 循环的逻辑由紧随其后的圆括号中的内容给出。在这种情况下，我们创建了循环变量 i，它取值 1 到 4（包含 4）。在循环体中（由花括号括起来），我们使用字符串模板打印 i 的当前值。这个 for 循环应产生如下输出：

```
Current value of i is: 1
Current value of i is: 2
Current value of i is: 3
Current value of i is: 4
```

如果你想创建一个不包含最后一个值的范围，可以使用 until 关键字，而不是 .. 运算符。此外，无论使用哪种类型的范围，都可以指定一个 *步长* 值，以便以除 1 以外的其他增量来递增循环变量。这里我们使用一个步长为 3 的 until 范围：

```
// exclusive range with step
for (i in 1 until 10 step 3) {
    println("Current value of i is: $i")
}
```

在这个例子中，循环变量 i 从 1 开始，每次循环递增 3，依次取 4 和 7 的值，直到循环终止。输出应该如下所示：

```
Current value of i is: 1
Current value of i is: 4
Current value of i is: 7
```

请注意，当 i 为 10 时没有输出行。这是因为我们使用了 until，它排除了范围的上限。

如果你需要让 for 循环以相反的顺序进行迭代，可以创建一个使用 downTo 关键字的范围。这个关键字允许你指定一个范围，其中循环变量从较高的值开始并递减到较低的值。与 .. 运算符一样，downTo 范围是包含上限的。下面是它的用法：

```
for (i in 4 downTo 1) {
    println("Current value of i is: $i")
}
```

这个 for 循环应输出如下内容：

```
Current value of i is: 4
Current value of i is: 3
Current value of i is: 2
Current value of i is: 1
```

借助 downTo 关键字，循环变量 i 从 4 递减到 1。

##### continue 和 break 语句

Kotlin 允许使用 continue 和 break 关键字中断 for 循环的流程。通常，这些关键字与 if 语句结合使用，当满足某个条件时中断循环。continue 关键字会停止当前迭代并立即跳到下一次迭代。下面是一个示例：

```
for (i in 1..4) {
    if (i == 3) {
        // Skip the current iteration when i is 3.
        continue
    }
    println("Current value of i is: $i")
}
```

当循环变量设置为 3 时，循环将继续，并进入下一个循环变量的值。因此，当 i 为 3 时，println() 函数不会执行，输出如下：

```
Current value of i is: 1
Current value of i is: 2
Current value of i is: 4
```

相比之下，break 关键字会完全终止一个 for 循环，如下所示：

```
for (i in 1..4) {
    if (i == 3) {
        // Exit the loop when i is 3.
        break
    }
    println("Current value of i is: $i")
}
```

当循环变量等于 3 时，这个循环会“中断”。因此，输出应如下所示：

```
Current value of i is: 1
Current value of i is: 2
```

即使范围内还有一些值，break 关键字也会提前结束循环。

##### 嵌套和命名的 for 循环

在一个 for 循环内嵌套另一个 for 循环是很常见的，这样内部的整个 for 循环会根据外部循环的次数多次执行。这里是一个嵌套 for 循环的示例，它打印一个方形的星号模式：

```
fun main() {
    val size = 4 // Change this value to adjust the size of the square.

    // nested for loops to print a square pattern of asterisks
    for (i in 1..size) {
        for (j in 1..size) {
          ❶ print("* ")
        }
      ❷ println() // Move to the next line after each row.
    }
}
```

在这个示例中，外循环`for (i in 1..size)`遍历行，而内循环`for (j in 1..size)`则遍历每一行中的列。`print("* ")`语句为每个元素打印一个星号后跟一个空格。与`println()`不同，`print()`函数❶每次调用时不会自动添加换行符，因此每次外循环执行时，内循环会将一系列星号打印在同一行。内循环结束后的空`println()`语句❷将光标移到下一行，以分隔不同的行。假设`size`设为 4，代码的输出应该是这样的：

```
* * * *
* * * *
* * * *
* * * *
```

当你有嵌套循环时，给每个循环分配一个名称可能会很有帮助——虽然不是绝对必要的——名称位于`for`关键字之前，并且必须后跟一个`@`符号。如果循环被命名，你可以通过在关键字后添加循环名称，显式地将`continue`和`break`等关键字应用于某个特定的循环。这让你可以更好地控制嵌套循环何时以及如何被打断。以下是一个示例：

```
loop1@ for (i in 1..5) {
    loop2@ for (j in 1..5) {
        print("$i,$j ")
      ❶ if (i == j) break@loop2
    }
    println()
}
```

我们有两个嵌套的`for`循环，分别命名为`loop1`和`loop2`。循环变量`i`和`j`的取值范围都从 1 到 5（包括 1 和 5）。暂时忽略`loop2`内部的条件逻辑，这个嵌套循环将会执行总共 25 次（5 × 5），打印每一对`(i,j)`，首先是`(1,1)`到`(1,5)`，然后是`(2,1)`到`(2,5)`，以此类推。输出结果如下，每次完整执行内循环后，`println()`确保每组五个对值会被打印在自己的一行：

```
1,1 1,2 1,3 1,4 1,5
2,1 2,2 2,3 2,4 2,5
3,1 3,2 3,3 3,4 3,5
4,1 4,2 4,3 4,4 4,5
5,1 5,2 5,3 5,4 5,5
```

现在考虑一下内循环中的条件逻辑❶。当`i`和`j`相等时，它会特别针对`loop2`应用`break`关键字（使用语法`break@loop2`），从而终止内循环并返回到外循环，执行`println()`的调用。（注意，当循环名称被赋值时，`@`符号位于名称之后，但当名称被引用时，`@`符号则位于名称之前。）这个逻辑仅打印(i,j)对的左下部分，直到主对角线，`i`和`j`相等的位置：

```
1,1
2,1 2,2
3,1 3,2 3,3
4,1 4,2 4,3 4,4
5,1 5,2 5,3 5,4 5,5
```

事实上，在这里指定`break`应用于`loop2`并不是必须的，因为默认情况下，像`break`和`continue`这样的关键字应用于它们所在的最内层循环——在这个例子中是`loop2`。尽管如此，包含循环名称有助于明确代码的意图。此外，考虑到另一种实现相似结果的方式是将`break@loop2`替换为`continue@loop1`，在这种情况下，引用循环名称变得是必要的。我建议你尝试做这个修改作为练习——你还需要思考如何处理`println()`的调用，以保持输出格式整齐。

##### `while` 循环

while 循环最适合在你需要反复执行一个代码块，但又无法预先知道具体循环次数的情况下使用。它会一直循环，直到满足终止条件。条件放在 while 关键字后面的括号中，在循环体开始之前。以下是一个例子：

```
var count = 0
while (count < 4) {
    println("Current value of count: $count")
    count++
}
```

我们将 count 变量初始化为 0，然后创建一个 while 循环，只要条件 count < 4 为真，循环就会继续执行。每次重复之前，循环都会检查这个条件。在循环内部，我们打印 count 的当前值，然后使用一元 ++ 运算符将其值增加 1，为下一次迭代做准备。这样应该会产生以下输出：

```
Current value of count: 0
Current value of count: 1
Current value of count: 2
Current value of count: 3
```

当循环执行到第四次时，count 从 3 增加到 4。然后，当循环准备开始第五次迭代时，它发现循环条件不再为真，循环终止。

另一种 while 循环的写法是使用条件 while (true)。由于 true 总是计算为真，这理论上会设置一个无限循环。实际的终止循环逻辑则被移到循环体内部。以下是之前的 while 循环，用这种方式实现的例子：

```
var count = 0
while (true) {
    println("Current value of count: $count")
    count++
    if (count >= 4) break
}
```

这次我们在循环体的末尾使用 if 语句来触发 break 关键字，当 count 大于或等于 4 时终止循环。如果没有这个条件，程序将陷入无限循环，导致程序一直运行下去。

while 循环的另一种变体是 do...while 循环，其语法如下：

```
do {
    // code to be executed
} while (`condition`)
```

do...while 循环在每次迭代后检查停止条件，而不是在之前检查。这确保了循环至少会执行一次。相比之下，如果常规 while 循环的条件在循环开始前已经为假，它将根本不会执行。

就像 for 循环一样，你可以嵌套多个 while 循环，并且可以与 continue 关键字和 break 一起使用。

### 函数

*函数*是一个可重用的代码块，用于执行特定任务或计算。函数是任何 Kotlin 程序的基本构建块，用于封装逻辑、促进代码重用以及改善代码组织。Kotlin 的标准库提供了许多内置函数，简化了常见的编程任务。一个例子是我们在本章中一直使用的 println() 函数，用于将文本输出到控制台；其他示例包括各种数学函数，其中一些我们稍后将探讨。对于更专门的任务，你需要创建自己的自定义函数。我们也会讨论如何实现这一点。

#### 内置数学函数

在本书中，我们将利用标准 Kotlin 库中预包装的许多数学函数。例如，你可以轻松地使用 sqrt() 函数计算一个数字的平方根，或者使用 pow() 函数将一个值提升到特定的幂（指数）。这些函数是 kotlin.math 包的一部分，必须在程序开始时使用 import 关键字进行*导入*。下面是一个使用这两个函数的简单程序：

```
import kotlin.math.sqrt
import kotlin.math.pow

fun main() {
    val x = 100.0
    val y = 10.0

    val squareRoot = "The square root of $x is: ${sqrt(x)}"
    val toThePower2 = "$y raised to the 2nd power is: ${y.pow(2.0)}"

    println(squareRoot)
    println(toThePower2)
}
```

首先，我们导入需要的两个数学函数。然后，我们在字符串模板中使用它们，使用 ${} 语法计算 x 的平方根（squareRoot）和 y 的二次方（toThePower2），该语法在“字符串模板”一节中讨论过，见第 15 页。该代码段应产生以下输出：

```
The square root of 100.0 is: 10.0
10.0 raised to the 2nd power is: 100.0
```

在某些情况下，你可能需要在同一个模块中使用许多内置函数。从技术上讲，可以通过在导入语句中包含星号（*）来导入整个集合。例如，`import kotlin.math.*` 会导入 kotlin.math 模块中的所有函数。然而，通常认为只导入所需的函数是一种好习惯。这种做法有助于避免*命名空间污染*，即你的代码被不必要的—或者更糟糕的是，冲突的—标识符（如变量名和函数名）所杂乱。只导入你需要的内容，可以让你在命名自己的变量和函数时更加灵活，避免与内置函数的名称发生冲突。

kotlin.math 模块中的其余函数处理三角学和其他有用的数学计算。有关可用的标准数学函数的完整列表及使用说明，请查阅官方 Kotlin 文档中的 kotlin.math，网址是[`kotlinlang.org`](https://kotlinlang.org)。

#### 自定义函数

当你的应用程序中有一些代码完成特定任务时，尤其是那些会被重复执行的任务，通常会将这些代码封装成一个自定义函数。这样可以保持代码的组织性和高效性。每个自定义函数必须在使用之前*声明*或定义。下面是 Kotlin 中函数声明的语法：

```
fun `functionName`(`parameter1`: `Type`,
                 `parameter2`: `Type`, ...): `ReturnType` {
    // function body
}
```

声明以`fun`关键字开始，后跟函数名和一对圆括号。在圆括号内，提供函数的*参数*名称（如果有），以及它们的数据类型。这些参数充当占位符，用于接收函数被调用时传递的值。它们允许你将数据传递给函数。一个函数可以有多个不同数据类型的参数（包括其他函数作为参数），或者没有任何参数，在这种情况下，函数名后面会跟着一对空括号。当函数被调用时，会为参数提供特定的值，这些值称为*实参*。请注意，函数参数在函数体内被隐式视为只读（不可变）变量。不能对函数参数使用`val`或`var`。

在参数列表之后，函数声明继续以冒号（:）和函数的*返回类型*。这指定了函数将生成并提供给调用者的值的数据类型。例如，我们在《内建数学函数》一章中讨论的内建`sqrt()`函数返回其参数的平方根，可以是 Double 或 Float。如果一个函数不返回任何值，你可以省略返回类型。它将被视为`Unit`，类似于其他语言中的`void`类型。例如，如果一个函数的目的是将输出打印到控制台、修改全局变量、修改作为参数传递给函数的数组或对象元素，或者调用其他函数，它就不会返回任何值。

综合来看，函数名以及参数名和类型定义了函数的*签名*。编译器使用函数签名来决定在多个具有相同名称但参数不同的函数之间使用哪一个（这种做法称为*函数重载*，我们稍后会讨论）。返回类型不是函数签名的一部分，但它仍然是函数声明的重要部分。

一旦函数签名和返回类型被指定（如适用），剩下的就是声明函数的*主体*，它被花括号包围。这是函数被调用时会执行的代码块。它可能包括额外的变量声明、条件语句、循环和表达式——任何函数完成工作所需的内容。

现在让我们看一个执行简单任务的实际函数：将两个整数相加并返回结果。以下是该函数的声明：

```
fun add(x: Int, y: Int): Int {
    return x + y
}
```

我们声明了一个名为 add()的函数，它接受两个参数 x 和 y，类型都是 Int，并返回一个类型为 Int 的值。函数体计算 x + y，并使用 return 关键字将结果返回给函数调用者。请注意，如果返回值的类型与函数声明的返回类型不同，编译器将生成错误。在这种情况下，由于 x 和 y 都是整数，x + y 的结果也将是整数。

在声明了 add()函数后，我们可以在 main()中这样调用它：

```
fun main() {
    // Declare the variables.
    val a = 3
    val b = 6

    // Call the function to add two integers.
    val sum = add(a, b)
    println("The sum of $a and $b is $sum.")
}
```

我们声明了 a 和 b 变量，并将它们分别初始化为 3 和 6。接下来，我们声明 sum 并将其赋值为 add()返回的结果。运行这段代码应输出以下内容：

```
The sum of 3 and 6 is 9.
```

Kotlin 强制类型检查，因此编译器会标记参数类型与传递给函数的实参类型不匹配的错误。参数的数量也应该与函数声明的参数数量匹配，除非某些参数被赋予了默认值。

##### 提供默认参数值

如果一个参数在大多数情况下函数被调用时具有相同的值，可以在函数声明时为该参数设置一个默认的预设值。这样，只有在你希望该参数的值与默认值不同的时候，才需要提供一个参数值。具有默认值的参数应当在函数声明中列在最后。以下是如何声明一个默认参数值的示例：

```
fun greet(name: String, greeting: String = "Hello") {
    println("$greeting $name!")
}
```

greet()函数接受两个参数 name 和 greeting，并将它们结合起来打印出定制的问候语。每次调用该函数时都需要提供 name 的值，但如果没有指定 greeting 的值，函数将使用默认值“Hello”。这个默认值是在参数列表中设置的，位于参数的数据类型之后。

如果我们使用 greet("Nathan")调用该函数，仅为 name 参数提供一个值，则应得到以下输出，其中包含问候语的默认值：

```
Hello Nathan!
```

考虑一下，如果你希望这个函数打印“早上好，Nathan！”作为信息，你会怎么调用它？

##### 使用命名参数

当一个函数有很多参数时，跟踪它们的顺序和类型可能会很麻烦。在这种情况下，使用*命名参数*会非常方便。这是一种函数调用方式，你在调用时同时包括参数名和所需的参数值。有了参数名，参数的顺序可以任意排列。

假设你声明了一个包含四个参数的函数：

```
fun printPersonInfo(firstName: String, lastName: String,
                    age: Int, gender: String) {
    println("Person info: $firstName $lastName, " +
            "Age: $age, Gender: $gender")
}
```

使用命名参数调用函数，可以避免记住参数声明顺序的负担：

```
printPersonInfo(lastName = "Keller", firstName = "Jeffrey",
                age = 40, gender = "Male")
```

在这里，每个参数都以 parameterName = value 的形式提供。由于使用了命名参数，即使参数顺序不正确，这个函数调用也能正常工作。只要为所有参数提供了名称，或者编译器能够确定参数的顺序，这都是被允许的。

##### 重载一个函数

*函数重载*在 Kotlin 中允许你在同一作用域内定义多个同名函数，但它们的参数列表不同。它们可能有不同数量的参数，或者参数的数据类型不同。以下是函数重载的一个例子：

```
// function to add two integers
fun add(a: Int, b: Int): Int {
    return a + b
}

// function to add two doubles
fun add(a: Double, b: Double): Double {
    return a + b
}
```

我们声明了两个名为 add() 的函数，参数列表不同；一个用于加法运算两个整数，另一个用于加法运算两个浮点数。当调用 add() 函数时，编译器将通过比较传入的参数类型和已声明的函数签名来确定调用哪个版本的函数。这是你调用这两个函数的方式：

```
val result1 = add(2, 3)
val result2 = add(40.5, 23.9)
```

通过函数重载，你可以使用相同的函数名来执行在概念上做相同事情（在此案例中为加法），但使用不同的参数类型。这使得你的代码更具可读性、直观性和抗错误性。在这个例子中，我们预见到可能需要同时对浮点数和整数进行加法运算。重载该函数使我们能够在不触发错误的情况下进行任意一种操作。

##### 引用一个函数而不调用它

在 Kotlin 中，你可以使用成员引用操作符 (::) 来通过函数名引用一个函数，而不实际调用它。这在许多情况下都很有用，例如当你需要将函数引用分配给一个变量时。假设你有两个函数，正在决定在代码中使用哪个。也许它们都是完成同一任务的方式，你想看看哪个更高效，或者它们实现了两种不同的操作，在不同的情况下更合适。与其重写所有代码去调用其中一个函数，不如将适当的函数引用分配给一个变量，然后通过该变量调用函数（无论你选择哪一个），以最小化对代码的修改。以下是一个示例，说明这是如何实现的：

```
fun add(x: Double, y: Double): Double {
    return x + y
}

fun multiply(x: Double, y: Double): Double {
    return x * y
}

// Change this condition to use add() or multiply().
val useAdd = true

fun main() {
    // Declare a function variable using member reference.
  ❶ val selectedFunction = if (useAdd) ::add else ::multiply

    val x = 3.0
    val y = 4.0

    // Calculate the value of the selected function.
  ❷ val result = selectedFunction(x, y)

    // Print the result.
    println("Result: $result")
}
```

我们首先声明了两个函数：add()计算 x 和 y 的和，multiply()计算 x 和 y 的积。我们只希望在 main()中使用其中一个函数。为了控制使用哪个函数，我们声明一个 Boolean 类型的变量 useAdd，并将其设置为 true。在 main()函数内部，我们创建了另一个名为 selectedFunction 的变量，并使用*条件表达式语法*来设置它的值为其中一个函数❶。这种语法使用 if...else 结构根据条件返回一个值并将其赋给变量——在这个例子中，是根据 useAdd 变量的状态。如果 useAdd 为 true，selectedFunction 将被赋值为对 add()的引用；否则，它将引用 multiply()。请注意，我们在每个函数名称前面都加上了::操作符，并且在函数名称后面没有加上括号，因为我们是在引用函数而不是调用它们。通过 selectedFunction 变量持有一个函数的引用，我们现在可以通过调用 selectedFunction()来调用该函数，而不是直接调用 add()或 multiply()❷。我们将返回的值存储在 result 变量中，并将其打印到控制台。

尝试将 useAdd 的值从 true 改为 false，切换使用 add()和 multiply()。然后考虑这种解决方案在切换两个函数之间的便利性，特别是当你需要在代码的多个地方使用函数时。我们无需在每个使用位置更新函数名称，只需更改 useAdd 的值，并依赖 selectedFunction 变量来代替我们想要的函数。

::操作符在需要将函数引用作为参数传递给另一个函数时特别有用。以下是一个示例：

```
fun printMessage(message: String) {
    println(message)
}

fun applyFunction(function: (String) -> Unit, input: String) {
    function(input)
}

fun main() {
    // using :: to reference the printMessage function
    applyFunction(::printMessage, "Hello, Kotlin!")
}
```

我们定义了一个名为 printMessage()的函数，它接收一个字符串参数并将其打印到控制台。我们还定义了另一个名为 applyFunction()的函数，它有两个参数：function，用于保存对某个函数的引用；input，一个字符串。函数参数的类型需要与它所引用的函数的参数类型和返回类型匹配；（String）-> Unit 表示该函数将接受一个字符串作为参数并且不返回任何值。在 applyFunction()的函数体内，我们调用传入的任意函数，使用输入的字符串作为其参数。

在 main()中，我们使用::创建对 printMessage()的引用，并将其与字符串"Hello, Kotlin!"一起作为第二个参数传递给 applyFunction()。这将有效地使 applyFunction()调用 printMessage()，并将给定的字符串打印到控制台。输出应该是：

```
Hello, Kotlin!
```

当然，::操作符的用途远不止于我们在这里讨论的内容。我鼓励你参考官方的 Kotlin 文档，探索该操作符的其他用例。

### 范围函数

在 Kotlin 中，*范围函数* 是一组内置函数，用于管理变量的作用域、访问对象的属性并在特定上下文中执行代码块。Kotlin 中的范围函数包括 run、with、let、also 和 apply。它们常用于简化和提高代码的可读性，特别是在处理对象或管理操作流时。下面是如何使用 run 函数的一个简单示例：

```
val result = run {
    val x = 10
    val y = 20
    x + y // The value of this final expression is returned.
}
println("Result: $result") // prints "Result: 30"
```

我们首先声明一个名为 result 的变量。其值由使用 run 范围函数执行的代码块中的最后一个表达式决定。在这个代码块内，我们定义并赋值给两个整数，最后一个表达式计算它们的和。最终表达式的结果将由代码块返回并赋值给 result 变量。最后，我们使用 println() 打印 result 的值，结果会显示 "Result: 30"。

### Lambda 表达式

*Lambda 表达式*，通常简称为 *lambdas*，是一种以灵活简洁的方式定义和传递类似函数代码块的方法。它们本质上是匿名函数，允许你在不指定名称的情况下动态创建函数。Lambda 表达式是函数式编程的基础，函数式编程是一种以函数为主要构建块的编程风格或范式。它们使得操作 *高阶函数* 变得更加容易，*高阶函数* 是可以接受函数作为参数、将函数作为返回值，或者两者兼有的函数。高阶函数有助于创建可重用和模块化的代码，这些代码可以通过不同的函数进行定制。

这是一个简单的 lambda 示例，它接受一个名字并生成一个问候语：

```
val greet (String) -> String = {name -> "Hello, $name!"}
```

lambda 本身是被大括号括起来的代码部分：{name -> "Hello, $name!"}。它由输入参数（在本例中只有一个，name）和一个主体（"Hello, $name!"）组成，中间通过箭头（->）符号分隔。可以把这个箭头看作是将参数传递给 lambda 主体。lambda 主体中的 return 关键字是隐含的；如果主体只包含一个表达式，那么该表达式将自动作为返回值。

在这个例子中，我们将 lambda 赋值给 greet 变量。在赋值运算符前的 (String) -> String 指定了 lambda 的参数类型和返回类型，同样通过 -> 符号分隔。我们也可以将这些类型声明直接包含在 lambda 中，在这种情况下，我们将整个表达式写作：

```
val greet = {name: String -> "Hello, $name!"}
```

在这里，我们在大括号内指定了 name 参数的类型为 String。使用这种语法，返回类型和 return 关键字本身是隐含的。

无论我们使用哪种语法，现在都有一个返回字符串问候语的函数，并且该函数存储在 greet 变量中。因此，我们可以像调用普通函数一样，通过该变量调用 lambda：

```
println(greet("Alice")) // output: Hello, Alice!
println(greet("Bob"))   // output: Hello, Bob!
```

lambda 通常用于快速处理数据，比如加法或计算一个数字的平方：

```
val sum: (Int, Int) -> Int = {a, b -> a + b}
println(sum(3, 4)) // output: 7

val square: (Int) -> Int = {it * it}
println(square(5)) // output: 25
```

Lambda 参数可以显式指定类型，也可以由 Kotlin 自动推断类型。对于简单的 lambda，Kotlin 可以自动推断类型。另外，如果 lambda 只有一个参数，可以省略参数声明，在 lambda 体内直接使用隐式的`it`关键字作为参数的代名词。这就是我们为平方 lambda 所做的：`{it * it}`表示该 lambda 将接受一个未命名的单一参数并将其自身相乘。

Lambda 表达式可以跨越多行以执行更复杂的任务，并且可以像 for 循环一样嵌套。我们将在下一部分中使用多行嵌套的 lambda 来复制文件内容。

### 基本输入和输出

现在大多数商业软件都有图形用户界面（GUI），使得您可以轻松地与其互动。您可以使用第三方工具（如 JavaFX 或 Jetpack Compose）为 Kotlin 应用程序创建 GUI，但本书不涉及这一部分。相反，在本节中，我们将专注于如何在 Kotlin 中处理基于文本的输入和输出。这有助于您快速测试和调试代码。基于文本的输出对于脚本编写、记录日志以及监控计算机和设备网络上的活动非常有用，这也是系统管理员经常做的事情。

#### 基于控制台的输入和输出

要从控制台获取用户输入，请使用 readln()函数。它将返回用户输入的任何文本，或者如果用户仅按下 ENTER 键，则返回一个空字符串。以下是一个示例：

```
println("Enter some text:")
val userInput = readln()
println("You entered: $userInput")
```

在这里，用户输入（一行文本）被读取到`userInput`变量中，然后使用熟悉的 println()函数将其作为输出显示在控制台上。如果用户只是按下 ENTER 键，那么 readln()将返回一个空字符串，程序将在打印以下内容后正常结束：

```
You entered:
```

在 Kotlin 中从控制台读取输入时，请记住，所有输入最初都会被处理为文本，导致数据类型为 String。如果需要其他数据类型，必须进行类型转换，前提是类型兼容。使用提示语（例如“请输入您的名字”或“请输入一个整数”）向用户说明预期的输入类型也是有帮助的。

尽管有清晰的提示，您仍然不应自动假设输入将是有效的。用户可能输入无法成功类型转换为所需格式的错误字符。为了防止程序因潜在的错误而崩溃，接收用户输入时必须实施错误处理机制。这个额外的步骤能确保程序的健壮性，并带来更流畅的用户体验。以下是一个完整的从控制台读取整数的容错方法示例：

```
fun main() {
    while (true) {
        print("Enter an integer: ")
        val num = readln()

        // Validate using a try...catch block.
        try {
            val intValue = num.toInt()
            println("You entered: $intValue")
 break // Stop the loop on success.
        } catch (e: NumberFormatException) {
            println("Invalid input. Try again.")
        }
    }
}
```

我们首先创建一个 while 循环，直到提供有效的输入为止。接下来，我们将用户输入的内容作为字符串读取，并将其赋值给名为 num 的变量。我们在 try...catch 结构中检查输入的有效性，以优雅地处理错误。该结构由两个代码块组成：一个 try 块，包含你希望运行的代码；一个 catch 块，包含在 try 块出错时的备用代码路径或回退选项。catch 块防止程序因错误而突然崩溃。这个机制有助于在调试过程中排查问题，并提升商业应用中的整体用户体验。

在这种情况下，try 块尝试使用 toInt() 将存储在变量 num 中的用户输入转换为整数。如果转换成功，则会打印包含整数值的消息。

然而，如果转换失败并抛出 NumberFormatException 异常，catch 块将被激活，打印错误信息，然后开始下一次循环。注意 catch 关键字后面的 (e: NumberFormatException)，它指定了 catch 块设计用来处理的具体异常类型。

#### 简单的文件操作

Kotlin 提供了简单有效的方式来读取和写入文件，这在你需要检索之前保存的数据或保存当前程序运行中的数据时非常有用。为了实现这一功能，Kotlin 依赖于 Java 标准库。例如，下面是如何使用 Java 的 File 和 Scanner 类读取文件中的数据：

```
import java.io.File
import java.util.Scanner

fun main() {
    // Replace the path below with the path to your file.
    val inputFile = "inputfile.txt"

    try {
      ❶ val file = File(inputFile)
      ❷ val sc = Scanner(file)
        while (sc.hasNextLine()) {
            val line = sc.nextLine()
            println(line)
        }
    } catch (e: Exception) {
        println("An error occurred: ${e.message}")
    }
}
```

示例展示了如何逐行读取文本文件。在导入了 File 和 Scanner 类之后，我们将包含输入文件完整路径的字符串赋值给变量 inputFile。然后，利用该变量创建一个名为 file ❶ 的 File 对象，该对象用于创建一个名为 sc ❷ 的 Scanner 对象，我们可以通过它访问文件的内容。接着，在 while 循环中，我们使用 Scanner 对象的 nextLine() 方法逐行读取文件内容，并将结果打印到控制台。循环会持续进行，直到读取到文件末尾，此时 Scanner 对象的 hasNextLine() 方法返回 false。我们将所有这些代码放入 try 块中，并使用相应的 catch 块来处理访问文件时可能出现的任何错误——例如，如果文件名或文件路径错误。 (e: Exception) 表示 catch 块可以处理任何类型的异常，这与早期专门处理 NumberFormatException 类型异常的 catch 块不同。在这种情况下，catch 块打印与异常相关的默认错误信息，信息可以通过 e.message 获取。

我的测试文件 *inputfile.txt* 中包含了一首打油诗，程序将其逐行输出到控制台：

```
There once was a man named Bob
Who loved to eat corn on the cob
He ate so much corn
That he grew a horn
And now he is known as Corn-Bob
```

要从文件中读取和写入，不能使用 Scanner 类，因为它不支持写输出。相反，可以使用 File 类的 appendText()方法。这里有一个简单的例子：

```
import java.io.File

fun main() {
    // Replace the file locations as needed.
  ❶ val inputFile = File("inputfile.txt")
  ❷ val outputFile = File("outputfile.txt")

    // Read all lines from the input file.
  ❸ val lines = inputFile.readLines()

    // Write all lines to the output file.
  ❹ for (line in lines) {
        outputFile.appendText("$line\n")
    }
    println("Copied input_file.txt to output_file.txt")
}
```

这段 Kotlin 代码从输入文件（*inputfile.txt*）中读取所有行，并将它们写入输出文件（*outputfile.txt*）。输入文件用一个 File 对象表示❶，输出文件用另一个 File 对象表示❷。我们使用 File 类的 readLines()方法从输入文件中读取所有行，并将它们作为字符串列表返回❸。 （在 Kotlin 中，*list*是一个项目的集合；在本例中，它是一个字符串集合，每行文件一个。我们将在第二章详细讨论列表。）我们将这个字符串列表存储在 lines 变量中。然后，我们使用 for 循环遍历 lines 列表，循环变量 line 代表一次循环中的一行❹。对于每一行，我们使用 appendText()方法将该行添加到输出文件中。我们还在每行的末尾添加一个换行符（\n），以确保它被写入到输出文件的自己的行中。我们通过在控制台打印消息来结束代码，指示输入文件已复制到输出文件中。

请注意，在此示例中我们没有使用 try...catch 块，因为目标是快速展示如何向文件写入数据。在实际应用程序中，可能需要将文件操作包装在 try...catch 块中，以处理可能的异常或错误，具体取决于您的特定需求。

你可以使用许多其他技术来在 Java 和 Kotlin 中读取和写入文件。有关其他方法的信息，请参阅官方的 Kotlin 文档。

项目 1：构建基于控制台的计算器

现在我们已经探讨了 Kotlin 的一些基本特性，让我们将这些知识应用到一个真实的项目中。我们将开发一个交互式的基于控制台的计算器应用程序。该应用程序将接受一对有效的数字作为输入，要求读者选择算术操作（加法、减法、乘法或除法），然后在控制台中显示该操作的结果。我们还将编程应用程序在需要时显示有用的错误消息。

在任何编码项目开始时，开始创建应用程序结构的心理地图至关重要。这涉及识别必要的变量和数据结构，以及确定程序应包含的基本功能。一旦确定了这些组件，我们就可以继续生成需要实现的关键组件列表，然后进入实际编码阶段。

对于更复杂的项目，创建一个流程图来可视化应用程序逻辑或开发详细的伪代码以提供编码整个项目的逐步说明也可能会有益。然而，考虑到计算器项目的相对简单性，我们将从列出其关键组件开始：

1.  输入收集：我们将收集用户输入的两个数字，并确保输入有效。

2.  操作选择：用户将选择加法、减法、乘法或除法。

3.  计算：将选定的运算应用于输入的数字。

4.  结果显示：计算结果将通过控制台呈现给用户。

5.  错误信息：在第 1 至第 3 步中，我们将显示有帮助的错误信息，针对无效输入，如数字输入中的非数字字符或无法识别的数学运算。

我们将使用这五个关键组件来指导开发过程，开始编写我们的第一个迷你项目。

#### 代码

我们将从上到下讨论代码，从 main()函数开始，它通过一系列辅助函数协调程序的操作。这种方法使我们能够将代码与我们概述的关键组件对齐。

```
import kotlin.system.exitProcess

fun main() {
    println("***  Console Calculator  ***")

    // step 1: input collection
    println("\nEnter two numbers:\n")
    val number1 = readDoubleInput("Number 1: ")
    val number2 = readDoubleInput("Number 2: ")

    // step 2: operation selection
    showChoices()
    val operation = getArithmeticOperation()

 // step 3: calculation
    val result = performCalculation(number1, number2, operation)

    // step 4: result display
    println("\nResult:\n" +
            "$number1 $operation $number2 = $result")
}
```

我们首先从 Kotlin 标准库中导入 exitProcess()函数。如果用户提供了无效输入或代码遇到了无效的操作类型（例如，除以零），我们将使用这个方法退出程序。

main()函数本身分为四个明确的步骤，每个步骤与项目的一个关键功能相关。在第一个步骤中，我们要求用户提供两个数字，并将其存储在 number1 和 number2 变量中。为了管理和验证输入，我们使用 readDoubleInput()函数，如下所示：

```
fun readDoubleInput(prompt: String): Double {
    print(prompt)
    val num = readln()

    // Check input validity.
    try {
        return num.toDouble()
    } catch (e: Exception) {
        println("Error reading input: ${e.message}")
        exitProcess(1) // Exit with error code 1.
    }
}
```

该函数接受一个字符串参数，作为控制台中用户输入的提示。如果用户提供有效输入，则返回一个数字值（Double 类型）。该函数使用 print()而非 println()显示提示信息，以便用户的回答出现在同一行。然后，它使用 readln()读取用户输入，并在 try...catch 块内处理字符串输入。当字符串成功转换为 Double 类型的数字时，返回该值。否则，程序进入 catch 块，打印错误信息，并以错误代码 1 退出程序。

> 注意

*使用* exitProcess() *函数时，可以使用任何整数作为错误代码。然而，首先根据应用程序可能生成的不同类型错误来决定一个错误代码方案非常重要。这样可以帮助您快速定位错误源。在更复杂的项目中，建议创建和维护错误代码的日志或 wiki。*

在 main()函数接收到两个有效的数字值（number1 和 number2）后，我们进入第 2 步，选择数学运算。为此，我们首先调用 showChoices()函数，向用户提供一系列算术运算选项。这个函数只是由多个 println()调用组成：

```
fun showChoices() {
    println("\nOperation Options:")
    println("1\. Addition (+)")
    println("2\. Subtraction (-)")
    println("3\. Multiplication (*)")
    println("4\. Division (/)")
}
```

接下来，我们使用 getArithmeticOperation()函数从用户那里获取有效的运算符。结果被赋值给 main()中的字符串变量 operation。以下是 getArithmeticOperation()函数的样子：

```
fun getArithmeticOperation(): String {
    print("\nEnter an arithmetic operation (+, -, *, /): ")
    val operation = readln()

    if(!"+-*/".contains(operation, true)){
        println("\nInvalid operation. Exiting.")
        exitProcess(2) // Exit with error code 2.
    }
    return operation
}
```

在这个函数中，用户被提示选择四个有效算术运算符之一。此选择通过 readln()方法捕获。随后，我们使用 if 语句验证用户输入是否有效。具体来说，如果字符串"+-*/"不包含用户输入的内容，则打印错误消息，表示提供了无效的运算符。程序然后以错误代码 2 终止。

回到 main()中，我们现在可以进入第 3 步，调用 performCalculation()函数来执行选定的算术运算并返回结果。以下是该函数的声明：

```
fun performCalculation(number1: Double, number2: Double,
                       operation: String): Double {
    return when (operation) {
        "+" -> number1 + number2
        "-" -> number1 - number2
        "*" -> number1 * number2
        "/" -> if (number2 != 0.0) number1 / number2
               else {
                   println("\nDivision by zero is not allowed. Exiting.")
                   exitProcess(3)
               }
      ❶ else -> {
            println("\nUnexpected error encountered. Exiting.")
            exitProcess(4)
        }
    }
}
```

该函数以两个输入数字和包含所需运算符的字符串作为参数，并返回一个 Double 类型的数字作为计算结果。它使用 when 语句，根据 operation 的值执行所需的计算。在这一阶段，数字和运算符类型都已经被验证。然而，还有一个潜在的错误源：除以零。我们通过在 when 语句中的“/”分支使用 if...else 块来处理这一点，如果 number2 为 0.0，则打印错误消息并退出程序。

请注意，我们还为整体的 when 语句❶添加了一个 else 子句，尽管此时不应再有其他错误（因此有“遇到意外错误”消息）。添加这个子句作为回退机制是一个好习惯，以防出现意外问题或编译器错误导致不可预测的错误。

进行完计算后，我们的 main()函数进入第 4 步，并使用字符串模板显示结果。回顾 main()函数，可以注意到我们使用自定义函数来封装程序中的各个任务，这使得 main()函数本身保持简洁且易于阅读。通过这种方式，函数帮助我们保持应用程序的良好结构。

#### 结果

这是一个程序运行的示例，用于乘法运算两个数字，37 和 9。用户输入以**粗体**显示。

```
***  Console Calculator  ***

Enter two numbers:

Number 1: **37**
Number 2: **9**

Operation Options:
1\. Addition (+)
2\. Subtraction (-)
3\. Multiplication (*)
4\. Division (/)

Enter an arithmetic operation (+, -, *, /): *****

Result:
37.0 * 9.0 = 333.0
```

请注意，尽管输入的是整数，但在进行乘法计算之前，它们会被转换为 Double 类型。也就是说，37 变成了 37.0，9 变成了 9.0，如输出结果中的“结果”部分所示。可以尝试使用无效的数字或运算符，观察程序的行为。我们可以从错误中学到很多！

### 总结

在本章中，我们介绍了 Kotlin 语言的一系列基础元素。你学习了如何使用注释来增强代码的可读性，如何使用变量来存储和管理数据，以及如何通过运算符来操作这些数据。你探索了条件语句和循环等流程控制结构，来决定程序的行为，并且通过函数有效地封装和重用代码。通过 lambda 表达式，你看到了即时编写和使用函数的方式，并初步了解了函数式编程风格。你还练习了接收输入和提供输出，涵盖了控制台和文件交互的操作。最后，通过一个实现控制台计算器的项目，你获得了将这些元素结合起来的实践经验。

### 资源

Kotlin. “Kotlin 文档。”（官方 Kotlin 文档。）访问日期：2024 年 6 月 15 日。 *[`kotlinlang.org/docs/home.xhtml`](https://kotlinlang.org/docs/home.xhtml)*。

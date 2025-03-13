

## 第二章：2 数组、集合和类



![](img/icon.jpg)

在本章中，我们将继续探索 Kotlin 语言的基础，学习如何以不同的方式存储和操作数据。我们将超越第一章 中的简单数据类型，探索可以在单个单元中存储多个值的数据结构。我们将从数组开始，然后继续学习列表、集合和映射等集合类型，它们提供了更多的功能和灵活性来处理数据。接着，我们将学习如何通过类创建自定义容器。我们将研究不同种类的类，包括常规类、数据类、抽象类和枚举类。

类是面向对象编程风格的基础，它允许我们通过定义具有特定属性和行为的数据类型来建模和操作数据。在讨论类的同时，我们还将解密其他面向对象的概念，如封装、继承、多态和接口。章节的最后，我们将把所涵盖的主题综合成一个项目，创建一个基础的任务管理应用程序，帮助你跟踪和组织日常任务。

### 数组

Kotlin 的 *数组* 是一块连续内存中的元素集合。数组中元素的数量在创建时就确定，因此无法更改，这意味着一旦数组创建后，你不能再添加额外的元素。然而，数组元素的值是可变的，因此可以根据需要进行修改。数组可以包含任何类型的元素，包括用户自定义的类型，只要同一个数组中的所有元素类型相同或来自共同的父类型（超类型）。

每个数组元素都有一个索引，可以单独访问它。默认情况下，数组的第一个元素的索引为 0，第二个元素的索引为 1，依此类推。因此，数组最后一个元素的索引始终比数组的大小少 1。例如，如果我们创建一个大小为 10（即包含 10 个元素）的数组，最后一个元素的索引将是 9。要访问数组元素，只需在数组名称后用方括号括起来索引即可。

在这里，我们创建了两个不同的数组，一个包含整数，另一个包含字符串值，并打印第一个数组的最后一个元素和第二个数组的第一个元素：

```
val arrInt = arrayOf(10, 20, 30, 40)
println(arrInt[3]) // output: 40
val arrString = arrayOf("one", "two", "three", "four", "five")
println(arrString[0]) // output: one
```

我们使用 arrayOf() 函数创建每个数组，并将数组元素的初始值作为参数传入。注意，我们不需要显式指定数据类型（Int 或 String）；编译器可以根据提供的值推断数组的类型。

在 Kotlin 中，只要它们都派生自相同的超类型，我们可以创建一个包含不同子类型元素的数组。例如，Any 是 Kotlin 中的一个超类型，包含所有其他数据类型，如 Int、String 和 Boolean。因此，如果我们创建一个类型为 Any 的数组，就可以自由混合这些数据类型，如下所示：

```
val myArray: Array<Any> = arrayOf(1, "bye", false)
```

我们使用 Array<Any> 类型声明来表示 myArray 可以包含任何数据类型的元素。实际上，它包含了一个整数（1）、一个字符串（"bye"）和一个布尔值（false）。由于所有这些类型都派生自共同的超类型 Any，因此它们可以存储在同一个数组中。我们本可以跳过在这种情况下声明数组类型为 Array<Any>，因为 Kotlin 足够智能，可以自行推断出来。然而，如果你要创建一个包含用户自定义类型元素的数组，明确声明类型可能是个好主意，这样可以提醒自己正在处理的是非标准类型的元素。例如，如果你有一个自定义的 Person 类并且想创建一个该类对象的数组，你可以按如下方式声明类型：

```
val people: Array<Person> = arrayOf(...)
```

这表示 people 数组中的所有元素都将是 Person 对象。

#### 原始数组

Kotlin 提供了针对某些数据类型的专用数组类型，包括 Byte、Short、Int、Long、Char、Float、Double 和 Boolean。例如，我们可以使用 IntArray 来表示整数，DoubleArray 来表示浮动点数值，CharArray 来表示单个字符。原始数组比非原始数组更加节省内存，因此在对性能要求较高的操作中，它们是一个不错的选择。创建原始数组的语法与常规数组类似，但每种类型的原始数组都有一个与 arrayOf() 等效的专用函数：

```
val intArray = intArrayOf(1, 2, 3, 4, 5)
val doubleArray = doubleArrayOf(1.0, 2.0, 3.0, 4.0, 5.0)
val charArray = charArrayOf('a', 'b', 'c', 'd', 'e')
val booleanArray = booleanArrayOf(true, false, true, false)
```

在 Kotlin 中，String 类型没有原始数组，因为 String 是引用类型，而不是原始类型，并且在 Java 虚拟机（JVM）中与原始类型在运行时的处理方式不同。因此，创建一个特殊的原始字符串数组并不会像 intArray 或 booleanArray 那样提供显著的内存或性能优势。

#### 数组构造器

创建数组的另一种方式是使用 Array 构造器。正如我们将在本章稍后深入讨论的那样，当我们研究类时，*构造器* 是用来创建特定类对象的函数——在这种情况下，是 Array 类。在 Kotlin 中，你可以使用 Array 构造器来创建一个给定大小的数组，并通过 lambda 表达式或函数设置其元素的值。一旦数组元素被初始化，你就可以在之后访问它们并根据需要更新它们的值。使用 lambda 表达式或函数来初始化一个大数组，比将值硬编码为 arrayOf() 函数的参数或从输入文件中读取要更高效。

Array 构造函数接受两个参数：数组的大小和一个基于元素索引返回初始值的函数。例如：

```
val num = Array(4, {i -> i * 2})
```

在这里，我们调用 Array 构造函数创建一个大小为 4 的数组，并使用 lambda 表达式初始化其元素。lambda 表达式接受每个元素的索引（i），并将其值乘以 2。结果是一个包含整数值 0、2、4 和 6 的数组。

#### 数组操作

Kotlin 中的数组提供了多种方法，帮助你访问和操作它们的元素。表 2-1 总结了用于数组操作的常用方法。

表 2-1：常用的数组方法

| 操作 | 描述 | 示例 |
| --- | --- | --- |
| 访问 | 通过索引检索元素。 | val element = array[index] |
| 更新 | 在特定索引处修改元素。 | array[index] = newValue |
| 大小 | 获取数组中元素的数量。 | val size = array.size |
| 迭代 | 遍历数组中的每个元素。 | for (element in array) {/* ... */} |
| 查找 | 检查数组中是否包含某个元素（返回 true 或 false）。 | val found = array.contains(element) |
| 切片 | 提取数组的一部分。 | val subArray = array.slice(startIndex..endIndex) |
| 排序 | 将元素按升序或降序排列。 | array.sort() 或 array.sortDescending() |
| 筛选 | 创建一个包含符合条件的元素的新数组。 | val filteredArray = array.filter {/* condition */} |
| 映射/转换 | 对每个元素应用一个函数，并创建一个包含结果的新数组。 | val mappedArray = array.map {/* transformation */} |
| 合并 | 将元素结合成一个带分隔符的字符串。 | val joinedString = array .joinToString(", ") |

注意，当我们对数据容器（如数组）应用诸如 filter 和 map 之类的方法时，如果方法名称后面跟有 lambda 表达式，我们无需像通常调用函数时那样在方法名称后加上括号。我鼓励你通过创建和操作不同类型的数组来尝试这些操作。

#### 多维数组

*多维数组*是一个其元素本身为数组的数组。嵌套数组在科学和数值计算中广泛使用。例如，二维数组可以表示图像中的像素网格或地图上的位置坐标。同样，三维数组可以用来跟踪空间中物体的位置和运动，如三维游戏或用于实际物体（如卫星）的追踪。

在 Kotlin 中，你可以使用内置的数组创建函数来创建多维数组。以下是使用 Array 构造函数创建二维数组的方法：

```
val numRow = 3
val numCol = 4
// Create a (3x4) array.
val twoDimArray = Array(numRow) {Array(numCol) {0}}
// Access and modify an element using its indices.
twoDimArray[2][3] = 99
```

在此示例中，我们使用 Array 构造函数创建一个具有 3 行 4 列的二维数组，并将其所有 12 个元素初始化为 0。然后我们将最后一个元素的值（行索引为 2，列索引为 3）替换为一个新值（99）。请注意，我们为两个索引使用了不同的方括号。创建和操作三维数组遵循相同的模式：

```
// Create a 3D array.
val threeDimArray = Array(2) {Array(3) {Array(4) {""}}}
// Access and modify an element using its indices.
threeDimArray[1][2][3] = "Hello, world!"
```

在这个示例中，我们首先创建一个尺寸为 2×3×4 的数组，并将其元素初始化为空字符串。如之前所示，我们使用维度索引访问并修改数组中的最后一个元素。

我们还可以使用 arrayOf() 函数的嵌套调用（或等效的原始数组函数）来创建多维数组。下面是创建一个二维整数数组的示例：

```
val arr2D = arrayOf(
    intArrayOf(0, 1, 1),
    intArrayOf(2, 0, 2),
    intArrayOf(3, 3, 0)
)
println(arr2D[2][2])  // output: 0
```

我们使用 arrayOf() 创建一个名为 arr2D 的数组数组。arr2D 的每个元素是使用 intArrayOf() 创建的整数数组。例如，arr2D 的第一个元素是一个包含整数 0、1 和 1 的数组。打印 arr2D 的最后一个元素，即 arr2D[2][2]，将输出 0。

### 集合

Kotlin *集合*是可以容纳相同类型或具有共同超类（例如，Any）不同子类型的数据或对象的容器。当声明为可变时，集合的大小可以根据需要调整。这与数组不同，数组在初始化后无法更改其大小。Kotlin 提供了多种类型的集合，例如列表、集合和映射，每种类型都有独特的属性和使用场景。

#### 列表

在 Kotlin 中，*列表*是一个有序的元素集合，可以是只读的也可以是可变的。只读列表是一个不可修改的元素集合，一旦创建后就不能修改。你只能在只读列表上执行如 size、contains、indexOf 和 subList 等读取操作。另一方面，可变列表是一个有序的元素集合，支持添加和删除元素或更改特定元素的值。

##### 只读

使用 listOf() 函数可以创建一个只读列表：

```
val list = listOf(1, 2, 3, 2)
```

请注意，这个列表包含了值 2 两次。重复值的潜力是列表与集合之间的一个关键特征，集合是 Kotlin 中的另一种集合类型。使用 listOf() 创建的列表只能包含一种类型的数据，该类型将根据列表元素推断出来。

列表的元素可以像访问数组元素一样访问：使用从 0 开始的索引系统。列表还提供了 first() 和 last() 方法，可以方便地直接访问第一个和最后一个元素，无需使用索引。以下是一个示例：

```
val names = listOf("Mary", "Sam", "Olivia", "Mike", "Ian")
println(names[1])       // output: Sam
println(names.first())  // output: Mary
println(names.last())   // output: Ian
```

由于列表像数组一样是零索引的，name[1] 返回数组中的第二个元素。同时，names.first() 和 names.last() 分别返回第一个和最后一个数组元素。

##### 可变

如果你希望有修改列表的灵活性，可以使用 mutableListOf() 来创建一个 *可变列表*。这样，你就可以更改列表的内容和大小，如下所示：

```
val mutableList = mutableListOf(1, 2, 3)
mutableList.add(4)       // Add an element.
mutableList.removeAt(1)  // Remove an element.
mutableList[0] = 5       // Modify an element.
println(mutableList)
```

在创建了一个包含三个元素的列表后，我们使用 add() 方法将第四个元素添加到列表末尾，使用 removeAt() 方法删除索引为 1 的元素；之后的元素会滑动填补这个空缺。我们还为列表的第一个元素（索引 0）设置了一个新值。当你运行这段代码时，输出应如下所示：

```
[5, 3, 4]
```

向可变列表末尾添加元素的另一种方式是使用 += 运算符，同样，你也可以使用 -= 运算符删除某个元素的第一个实例。你还可以使用 removeAll() 方法删除符合特定条件的所有元素。这里是另一个示例：

```
val fruits = mutableListOf("apple", "banana", "berry", "cherry")
// Add an element using the += operator.
fruits += "plum"
// Remove all elements that start with the letter "b".
fruits.removeAll {it.startsWith("b")}
```

我们创建了一个水果的可变列表，并使用 += 添加了一个额外的元素。然后，我们调用 removeAll()，提供一个 lambda 表达式来检查列表中的每个元素是否以 b 开头。记住，如果 lambda 只有一个参数，可以使用 it 作为该参数。在这种情况下，it 代表列表中的每个元素。

在处理可变列表时，一个特别有用的方法是 clear()，它会删除列表中的所有内容：

```
mutableList.clear()
```

这个方法允许我们反复使用一个可变列表，而不是创建新的列表，这样可以避免占用额外的内存资源。

通常，我们首先创建一个空的可变列表，然后根据需要将元素添加进去。在这种情况下，调用 mutableListOf() 函数时必须包含列表的类型声明，如下所示：

```
❶ val list = mutableListOf<Any>()
list.add("hello")
list.add(2)
list.add(33.33)
println(list.joinToString(", "))
```

我们在创建列表 ❶ 时使用<Any>，表示它可以包含此超类型的任何子类型，包括 String、Int 和 Double。当你运行这段代码时，输出应如下所示：

```
hello, 2, 33.33
```

注意我们使用了 joinToString() 方法，将列表元素合并为一个字符串并打印出来，每个元素之间用逗号分隔。

#### 集合

*集合* 是一个唯一元素的集合，这意味着每个元素只能出现一次。集合没有定义的顺序，因此如果两个集合包含相同的元素（顺序可以不同），它们被认为是相等的。集合有只读和可变两种类型，分别通过 setOf() 或 mutableSetOf() 函数创建。下面是每种类型的示例：

```
val readonlySet = setOf(1, 2, 3, 4, 5)
val mutableSet = mutableSetOf("apple", "banana", "cherry")
```

在 Kotlin 中为集合赋值时，编译器会自动忽略任何重复的元素。请考虑以下代码片段：

```
val mySet = setOf(1, 3, 3, 4, 5, 5, 6)
println(mySet)
```

当你运行这段代码时，输出应如下所示：

```
[1, 3, 4, 5, 6]
```

在创建 mySet 时，重复的值（3 和 5）已经被过滤掉。通过这种方式，集合确保每个元素只出现一次，这使得集合非常适合用于维护唯一的数据集合。

每个集合都有一个 size 属性，报告其元素的数量。集合还具有标准方法，如 add()、remove() 和 contains()。此外，您可以使用 union()、intersect() 和 subtract() 方法根据两个集合的内容创建一个新的集合，如下所示：

```
val set1 = setOf(1, 2, 3)
val set2 = setOf(3, 4, 5)
// set operations
val unionSet = set1.union(set2)
val intersectionSet = set1.intersect(set2)
val differenceSet = set1.subtract(set2)
```

我们在一个集合上调用方法，将第二个集合作为参数传入。在这个示例中，unionSet 包含 {1, 2, 3, 4, 5}，这是两个输入集合中所有唯一的元素；intersectionSet 包含 {3}，这是两个输入集合中唯一的共同元素；而 differenceSet 包含 {1, 2}，这是 set1 中不在 set2 中的元素。

#### 映射

*映射* 是一组键值对，其中每个键是与值关联的标签。如果你接触过 Python 中的字典或 Java 中的哈希映射，概念类似。映射中的键必须是唯一的。与列表和集合一样，您可以使用 mapOf() 或 mutableMapOf() 函数来创建映射，如下所示：

```
val ages = mapOf("Alice" to 30, "Bob" to 25, "Charlie" to 35)
val vertices = mutableMapOf("circle" to 0, "triangle" to 3,
    "rectangle" to 4, "pentagon" to 5)
```

我们使用 ages 将人名映射到他们的年龄，并使用 vertices 将不同的形状映射到它们的顶点数。在创建每个映射时，注意我们如何使用 to 来将每个键（如 "Alice"）与一个值（如 30）配对。键值对之间用逗号分隔。

映射的常见属性和方法包括 size，返回键值对的数量；get()，返回与键关联的值；remove()，删除键及其值；put()，添加新的键值对；以及 containsKey()，检查是否存在某个键。以下是基于前一个代码片段中创建的映射的一些示例：

```
val bobAge = ages.get("Bob") // returns the associated value: 25
vertices.put("hexagon", 6)   // adds a new key-value pair
vertices.remove("circle")    // removes the circle-0 pair
val testForCircle = vertices.containsKey("circle") // returns false
println(bobAge)
println(vertices)
println(testForCircle)
```

我们通过 get() 从 ages 映射中检索值，通过 put() 向 vertices 中添加新的键值对。然后，我们使用 remove() 从 vertices 中删除 "circle" 项，意味着 vertices.containsKey("circle") 应返回 false。此代码片段应产生以下输出：

```
25
{triangle=3, rectangle=4, pentagon=5, hexagon=6}
false
```

注意，当我们调用 put() 方法时，并没有使用创建映射时所用的相同键值对语法。相反，我们将键和值作为单独的参数传入，且由逗号分隔。

我们仅仅触及了 Kotlin 各种集合及其属性和方法的表面。欲了解更多内容，建议查阅官方 Kotlin 文档：[`kotlinlang.org/docs/home.xhtml`](https://kotlinlang.org/docs/home.xhtml)。

### 类介绍

在 Kotlin 中，*类* 是创建自定义对象的模板。它指定了该类所有对象应具有的属性（变量）和方法（函数）。当您在代码中使用类来创建一个对象时，您是在创建该类的 *实例*。这个过程被称为 *实例化*。类是面向对象编程风格的核心构建块。虽然对象是现实世界实体或概念的模型，但您也可以将用于创建它们的类视为自定义容器，将数据和功能封装成一个单一的单元。

类通过提供抽象层简化了复杂系统的构建。当我们将对象分类为类时，可以将它们的共同特征和行为抽象成一个单一的单位。例如，考虑一个表示任意人的 Person 类。它具有像 name 和 age 这样的属性，以及像 speak() 和 walk() 这样的方法。这个类的实例（代表具体的人）会为属性填入自己的值，并可以访问共享的方法。

类进一步帮助我们以模块化的方式建模复杂系统，使用 *子类*。例如，Person 类可以有像 Teacher、Student 和 Athlete 这样的子类。每个子类继承了 Person 超类的通用属性和方法，同时添加了特定于子类的新特征。例如，Teacher 可能有一个 isTenured 属性，而 Student 可能有一个 gradeLevel 属性。

要在 Kotlin 中创建类，你使用 class 关键字声明它，后跟类名及其体，类体用大括号括起来。根据约定，类名应该以大写字母开头。下面是一个简单的类声明示例：

```
class Person {
    var name: String = ""
    var age: Int = 0
}
```

在这里，我们定义了一个名为 Person 的类，它有两个属性：name 和 age。这些属性就像类体中的常规变量一样声明，并分别赋予初始值 ""（空字符串）和 0。声明了 Person 类后，我们现在可以创建类的一个单独实例并改变它的属性，如下所示：

```
val person1 = Person()
person1.name = "John"
person1.age = 25
```

在这里，我们创建一个新的 Person 对象并将其存储在 person1 变量中。我们通过调用 Person() 构造函数来实现这一点，它返回一个新的 Person 类对象（你将在下一节找到更多关于构造函数的内容）。然后，我们为对象的 name 和 age 属性赋值，使用点符号来访问这些属性。然而，为什么要仅限于一个 Person 对象呢？类的魅力在于，我们可以用它们创建任意多个该类的不同对象。让我们再创建一个 Person 对象：

```
val person2 = Person()
person2.name = "Irina"
person2.age = 21
```

这次我们将对象存储在 person2 变量中，并为它的 name 和 age 属性赋予独特的值，这些值与 person1 的值不同。

#### 构造函数

在上一个示例中，你看到如何在类体内直接初始化类属性，但更常见的是通过 *构造函数* 初始化类属性。构造函数是一个特殊的函数，当创建类的新对象时，它会被自动调用。在 Kotlin 中，你可以使用主构造函数或次构造函数来初始化属性，我们将在本节中讨论这两者。

##### 主构造函数

*主构造函数* 在类头部定义，在类名后面是一个括号。主构造函数使用以下语法列出了类属性的名称和数据类型：

```
class MyClass(val `property1`: `Type1`, val `property2`: `Type2`) {
// class body
}
```

在这种语法中，类属性以名称：类型的形式列出，类似于声明函数参数。所有属性名必须以 `val` 或 `var` 开头。通过这种方式声明类属性后，我们可以在创建类的对象时为属性提供具体的值，就像向函数传递参数值一样。

除了声明每个属性的名称和类型，我们还可以在类头中为属性提供默认值，作为主构造函数的一部分。为了说明这一点，让我们重新定义 Person 类，添加带有主构造函数的类头。然后我们将创建该类的几个实例，并通过构造函数初始化它们的属性：

```
class Person(val name: String = "", val age: Int = -99) {
    override fun toString(): String {
        return "Person(name=$name, age=$age)"
    }
}

fun main() {
    val person1 = Person("John", 25)
    val person2 = Person("Irina", 21)
    println(person1)
    println(person2)
}
```

这段代码定义了一个名为 Person 的类，其中包含两个属性，`name` 和 `age`，这些属性在类头中指定，类头也充当主构造函数。我们为 `name` 提供了默认值 `""`（空字符串），为 `age` 提供了默认值 `-99`。该类还重写了（重新定义了）`toString()` 方法；稍后我们会详细讨论这一点。

在 `main()` 函数中，我们创建了两个 Person 类的对象，并将名称和年龄属性的值作为参数传递给构造函数。这样，我们就不需要像在原始实现中那样编写单独的语句来设置这些属性的值。接着，我们将这两个 Person 对象打印到控制台。当你运行这段代码时，输出应如下所示：

```
Person(name=John, age=25)
Person(name=Irina, age=21)
```

当你将一个对象传递给`println()`时，Kotlin 会自动调用该对象的 `toString()` 方法，显示对象的某种字符串表示形式。所有类都自带此方法的默认实现，该实现继承自通用的 Any 类，但默认实现仅显示类名和对象的哈希码（一个唯一的整数标识符），这些信息既不具备很强的可读性，也不太具有信息量。通过重写 Person 类的 `toString()` 方法并提供自定义定义，我们可以以更有意义的方式展示对象的属性。我们将在本章稍后了解如何重写从父类继承的方法。

##### 次构造函数

Kotlin 类也可以有一个或多个 *次构造函数*，其中包含在创建新对象时应调用的附加参数或逻辑。次构造函数不是类头的一部分，而是定义在类体内，使用 `constructor` 关键字。如果主构造函数也存在，次构造函数必须始终委托给它（即调用它），无论是直接还是通过其他次构造函数间接调用，使用 `this` 关键字。

一个类可以只有主构造函数、同时拥有主构造函数和副构造函数，或者只有副构造函数。虽然副构造函数不是强制性的，但在某些情况下，它们非常有用。例如，当我们需要初始化过多的类属性时，在副构造函数中初始化这些属性可能更为方便。这个机制还允许你为主构造函数中未初始化的属性设置默认值。此外，副构造函数允许你用不同的属性组合来创建类的实例。这就像函数重载，多个具有相同名称但参数不同的函数。

以下示例展示了如何创建和使用副构造函数。在此过程中，它演示了初始化类属性的三种方式：在类体内、使用主构造函数和使用副构造函数。

```
class Car(val make: String, val model: String, val year: Int) {
    // property initialization inside class body
  ❶ var color: String = "Unknown"

    // 1st secondary constructor (no args)
    constructor() : this("Unknown", "Unknown", 0)

    // 2nd secondary constructor (1 arg)
  ❷ constructor(make: String) : this(make, "Unknown", 0)

    // 3rd secondary constructor (2 args)
    constructor(make: String, model: String) : this(make, model, 0)

    override fun toString(): String =
        "Make: ${make}, Model: ${model}, Year: ${year}, Color: ${color}"
}

fun main() {
    val c1 = Car()
    val c2 = Car("Nissan")
    val c3 = Car("Toyota", "Prius")
    val c4 = Car("Ford", "Mustang", 2024)

    c1.color = "Blue"
    c2.color = "Red"
    c3.color = "Black"
    c4.color = "Yellow"

    println(c1)
    println(c2)
    println(c3)
    println(c4)
}
```

在这个例子中，Car 类有一个带有三个参数的主构造函数：make（制造商）、model（型号）和 year（年份）。它还有三个副构造函数，分别带有零个、一个和两个参数。这些副构造函数使用 this 关键字（在冒号后）调用主构造函数，并传递接收到的参数值，同时为缺失的参数填充默认值。例如，第二个副构造函数❷接受 make 属性的值，同时为 model 和 year 属性提供默认值 "Unknown" 和 0。请注意，Car 类还具有一个 color 属性，它在类体中❶被初始化为 "Unknown"，与任何构造函数分开。由于该属性是用 var 声明的，因此在创建 Car 对象后，可以将其设置为不同的值。

在 main() 函数中，我们使用不同的构造函数创建了四个 Car 对象。Kotlin 根据提供的参数数量来确定调用哪个构造函数。例如，c1 将使用第一个副构造函数创建，因为没有提供参数，而 c4 将使用主构造函数创建，因为提供了所有三个参数。然后我们为每个对象设置 color 属性，并使用类的 toString() 方法输出每个对象的详细信息，我们又重写了这个方法。代码应生成以下输出：

```
Make: Unknown, Model: Unknown, Year: 0, Color: Blue
Make: Nissan, Model: Unknown, Year: 0, Color: Red
Make: Toyota, Model: Prius, Year: 0, Color: Black
Make: Ford, Model: Mustang, Year: 2024, Color: Yellow
```

请注意，当没有提供参数时，对象的所有属性都有默认值，而当提供了三个参数时，对象的所有属性都是自定义值。

#### init 块

在 Kotlin 中，你可以在类中使用 init 块，在对象构造期间运行代码段。init 块在创建类的对象时会自动执行。如果你有多个 init 块，它们会按照在类中出现的顺序执行。

这是一个如何使用 init 块在类内初始化属性的例子：

```
class Person (var name: String, var age: Int) {
    // additional property
    var isMinor: Boolean = false

    // init block for custom initialization
    init {
        if (age < 18) isMinor = true
    }
}
```

我们给 Person 类添加了一个初始化块，当 Person 对象的 age 属性小于 18 时，将 isMinor 属性从 false 更改为 true。每当创建 Person 对象时，该块都会执行，按需调整 isMinor 的值。

初始化块和次构造函数都可以用于在创建对象时初始化类的属性或运行其他逻辑。当我们需要在初始化某些属性后运行额外的代码时，优先使用初始化块而不是次构造函数。（在前面的示例中，我们在使用初始化块初始化 isMinor 属性后更改了它的值。）初始化块可以使用主构造函数参数，并在主构造函数执行之后立即执行，但在执行任何次构造函数之前。

另一方面，次构造函数在你需要提供不同属性组合的类实例化方式时更为有用。不过，这两种机制有许多相似之处；在编程时，你通常有多种方式来完成一个任务。

#### 方法

*方法*是与类关联的函数，可以通过该类的对象调用，以执行特定操作。类的方法作为类体的一部分声明。为了说明这一点，我们向 Person 类添加一个 sayHello() 方法：

```
class Person (var name: String = "Unknown", var age = -99) {
    fun sayHello() {
        println("Hello, my name is $name, " +
                "and I am $age years old.")
    }
}
```

在类体内，我们声明了一个 sayHello() 方法，该方法使用字符串模板打印一个包含人名和年龄属性的问候语。注意，声明方法的语法与声明普通函数相同，都使用 fun 关键字，并且方法体用大括号括起来。

要使用此方法，创建一个 Person 对象，并通过点符号调用该方法，如下所示：

```
val person = Person("John", 25)
person.sayHello()
```

这将输出：

```
Hello, my name is John, and I am 25 years old.
```

你可以向 Person 类添加更多的方法，以基于对象的属性执行其他操作或计算。方法也可以像常规函数一样接受参数并返回值。

#### 封装

*封装*是面向对象编程的一个基本原则，它帮助你控制对对象内部状态的访问。这种控制是通过*访问修饰符*实现的，访问修饰符是指定属性或方法的可见性或可访问性的关键字。访问修饰符允许你隐藏（*封装*）类的实现细节，并通过减少意外修改的风险来保持类对象的完整性。在 Kotlin 中，最重要的两种访问修饰符是 public 和 private。

除非另有声明，类的所有属性和方法默认都被认为是*公共*的。这意味着它们可以在代码的任何地方访问。与此相对，*私有*属性和方法只能在类声明内部访问。例如，如果你将 Person 类的 age 属性指定为私有，那么你可以在 Person 类方法的声明中引用它，但不能在类声明外的代码中使用它，比如在 main()函数中更新 Person 对象的年龄值。这可以防止年龄属性被以非预期的方式修改。

下面是如何在 Person 类中利用封装和私有访问修饰符的示例：

```
class Person(private var name: String, private var age: Int) {
    fun introduce() {
        println("Hi, I'm $name, and I'm $age years old.")
    }

    fun haveBirthday() {
        age++
    }
}

fun main() {
    val person = Person("Alice", 30)

    // Access and modify properties using public methods.
    person.introduce()
    person.haveBirthday()
    person.introduce()

    // Trying to access private properties directly
    // will result in a compilation error.
  ❶ // println(person.name)
    // person.age++
}
```

在 Person 类的头文件中，我们使用私有访问修饰符将 name 和 age 属性指定为私有。这样，属性只能在类内部访问和修改。我们还给类定义了两个方法，introduce()和 haveBirthday()，这两个方法默认是公共的。这些方法提供了对私有属性的受控访问，其中 introduce()显示 name 和 age 的值，而 haveBirthday()则增加 age 的值。实际上，这限制了 Person 对象的 age 属性如何更新；它每次只能增加一年，而不能从 30 岁跳到 40 岁。

在 main()函数中，我们创建了一个 Person 对象，传递了姓名和年龄的初始值（仍然可以通过构造函数设置私有属性的值）。然后我们调用了公共的 introduce()和 haveBirthday()方法，再次调用 introduce()，产生了如下输出：

```
Hi, I'm Alice, and I'm 30 years old.
Hi, I'm Alice, and I'm 31 years old.
```

通过这种方式，我们能够通过对象的公共方法间接访问和修改其私有属性。然而，我们无法直接访问或修改私有属性，正如在注释掉的代码行❶中尝试的那样。如果你尝试去掉这些注释执行这些语句，你会遇到编译错误，因为这些属性是私有的。

Kotlin 还有两个额外的访问修饰符，protected 和 internal。*Protected*属性和方法与私有属性和方法类似，唯一的区别是它们可以在类的子类中访问，同时也可以在类内部访问（稍后将详细讲解子类）。*Internal*属性和方法只能在同一个模块内访问。

> 注意

*一个*模块*是必须在编译过程中一起处理的一组 Kotlin 文件。通过*import*语句访问的文件或函数并不被视为模块的一部分，而是模块使用的外部依赖。*

#### this 关键字

在 Kotlin 类声明中，this 关键字是指向类的当前实例的引用。例如，如果在 Person 类的方法定义中看到 this.name，它仅指代该方法所调用的 Person 对象的 name 属性的值。我们在 Person 类的示例中没有使用 this 关键字，因为从代码中可以明确看出，像 name 和 age 这样的变量是类的属性。当我们需要区分具有相同名称的类属性和方法参数时，this 关键字就变得很重要。下面是一个需要使用 this 的 Book 类的示例：

```
class Book(var title: String, var author: String) {
    fun displayInfo() {
        println("Title: $title")
        println("Author: $author")
    }

    fun updateInfo(title: String, author: String) {
        this.title = title
        this.author = author
    }
}

fun main() {
    val book1 = Book("The Great Gatsby", "F. Scott Fitzgerald")
    // Display book information.
    book1.displayInfo()
    // Update book information.
    book1.updateInfo("To Kill a Mockingbird", "Harper Lee")

    println("\nUpdated book information:")
    book1.displayInfo()
}
```

在这个例子中，我们有一个 Book 类，它有标题和作者属性，以及两个方法。displayInfo()方法显示书籍的标题和作者，updateInfo()方法接受新的标题和作者作为参数，并用这些值更新类的属性。注意我们在 updateInfo()方法中如何使用 this 关键字来区分 this.title 和 this.author（类的标题和作者属性）与 title 和 author（方法的参数）。这样，我们可以正确地更新书籍的信息，而不会出现命名冲突。

在 main()函数中，我们实例化了一个 Book 对象，然后使用其 updateInfo()方法来更改书籍的标题和作者，并通过 displayInfo()方法在更改前后显示书籍的属性。输出应该如下所示：

```
Title: The Great Gatsby
Author: F. Scott Fitzgerald

Updated book information:
Title: To Kill a Mockingbird
Author: Harper Lee
```

尝试从 updateInfo()方法中删除 this 关键字，留下 title = title 和 author = author。代码将不再正常工作：Kotlin 会尝试将 title 和 author 解释为局部变量，但没有 val 或 var 声明，并且无法使用提供的参数初始化这些局部变量（这也不是我们想要的结果）。

虽然 this 关键字在类方法内部出现时是指向类的当前实例，但它在其他上下文中有其他含义。正如我们已经看到的，当 this 出现在二级构造函数中的冒号后面时，它用于委托给同一类的主构造函数。有关 this 关键字的其他用法，请参阅 Kotlin 官方文档。

#### 继承与多态

*继承*和*多态*是面向对象编程的相互关联的原则。继承允许一个更具专门性的子类（或*子类*）继承一个更一般的父类（或*父类*）的属性和方法；多态使得子类能够重写并扩展其父类的行为。继承和多态共同促进了灵活性和代码的可重用性，并且使得不同的子类能够以不同的方式扩展同一个继承自父类的方法。

与一些其他编程语言不同，Kotlin 中的类默认不可继承。相反，你需要显式地在父类前加上`open`关键字，使其能够被子类继承。然后，在子类声明的头部，你指定父类的名称（在其名称前加冒号）。这就建立了继承关系。

下面是一个简单的例子，展示如何创建一个除了继承父类的属性外，还拥有自己独特属性的子类：

```
open class ParentClass(val name: String, val age: Int) {
    init {
        println()
        println("Hello, I am $name, and I am $age years old.")
    }
}

class ChildClass(name: String, age: Int, val occupation: String)
    : ParentClass(name, age) {

    init {
        println("My occupation is $occupation.")
    }
}

fun main() {
    // Create instances of parent and child classes.
    val person1 = ParentClass("John", 33)
    val person2 = ChildClass("Sarah", 24, "accountant")
}
```

请注意，我们在父类之前使用了`open`关键字。这表示该类可以被子类继承。父类的主构造函数需要两个属性：`name`类型为`String`，`age`类型为`Int`。由于这些属性没有提供默认值，因此在实例化子类时，必须提供它们的值。此外，子类还引入了一个名为`occupation`的新属性，在实例化时也需要提供值。

在`main()`函数中，我们将`person1`创建为父类的实例，将`person2`创建为子类的实例。由于这两个类都有`init`块，因此当你运行这个程序时，输出应该类似于以下内容：

```
Hello, I am John, and I am 33 years old.

Hello, I am Sarah, and I am 24 years old.
My occupation is accountant.
```

如果你打算在子类中自定义或重写父类的属性或方法，你还需要在父类中使用`open`关键字标记它们。然后，在子类中，使用`override`关键字放在这些属性或方法之前。这确保了编译器识别你想要重写父类实现的意图。

下面是一个简单的在子类中重写父类方法的例子：

```
// parent class
open class Vehicle {
    open fun startEngine() {
        println("Vehicle engine started")
    }
}

// child class
class Car : Vehicle() {
    override fun startEngine() {
        println("Car engine started")
    }
}

fun main() {
    val myCar = Car()
    myCar.startEngine()
}
```

在这个例子中，我们使用了两次`open`关键字——一次用于父类（Vehicle）之前，另一次用于在父类中声明`startEngine()`方法。然后，在子类（Car）中，我们使用`override`关键字修改了这个方法。因此，当你运行这段代码时，应该会输出以下内容：

```
Car engine started
```

虽然我们已经讲解了继承和多态的基本知识，但你还有很多内容需要探索。我建议参考官方的 Kotlin 文档，了解更多的用例。

### 常用类和自定义类型

现在我们已经概述了一些类和面向对象编程的基本原则，在本节中，我们将探讨 Kotlin 中几种常用的类和自定义类型。这些包括数据类、对偶和三元组、抽象类、接口以及枚举类。如果你对类还不熟悉，或者从未使用过这些特性，建议你在深入细节之前先快速浏览一遍。表 2-2 提供了我们将要讲解的特性的名称、简短描述和用例。如果你需要回顾或澄清任何概念，可以参考此表。

表 2-2：常用类和自定义类型

| 类别 | 定义 | 用例 |
| --- | --- | --- |
| 数据类 | 主要用于存储数据的简单类。没有任何用户定义的方法。数据类通过 data 关键字标记。 | 用作建模数据的基本构建块，通过提供描述性名称与值配对。它们通常作为更复杂数据结构的构建块。 |
| Pair 和 Triple | 用于存储两个（Pair）或三个（Triple）相同或不同数据类型的简单类。 | 用于在一个实例中存储或返回两个或三个值，特别是当你不需要为这些值提供描述性名称时。 |
| 抽象类 | 不能实例化的类，且可以有必须由其子类重写的抽象成员。 | 用于定义一组相关类的共同特性。 |
| 接口 | 一组必须由继承类或类型实现的函数和属性。 | 用于强制其他类型（类、函数、自定义类型）实现方法和属性。 |
| 枚举类 | 一种特殊的类类型，表示一组常量，具有可选的属性和方法。 | 用于表示固定的值集合。 |

我们将在接下来的章节中通过详细示例来回顾这些概念。

#### 数据类

在 Kotlin 中，*数据类*是主要用于存储数据的类，而不是执行复杂的操作或逻辑。实质上，它是一个具有属性但没有自定义方法的类（虽然添加此类方法并不被禁止）。要声明一个数据类，需在类关键字前加上 data 关键字，并在主构造函数中包含至少一个参数。

基于在主构造函数中声明的属性，数据类可以自动生成多个方法，包括：

equals() 比较两个数据类实例是否相等。

toString() 返回对象的可读字符串表示。

copy() 创建数据类实例的浅拷贝。（有关浅拷贝的信息，请参见第 75 页的“复制对象”部分。）

hashCode() 生成一个哈希码，这是基于对类的一个或多个属性应用哈希算法所得到的唯一整数。此方法与 equals()一起使用，用于判断两个对象是否相等。

相比之下，Kotlin 中的普通类不会自动生成这些方法；如果需要，你必须手动实现它们。

以下是如何在 Kotlin 中创建和使用简单数据类的示例：

```
// Declare a data class.
data class Person(val name: String, val age: Int)

fun main() {
    // Create an instance.
    val person = Person("Steve", 40)
    println(person)
}
```

我们创建一个 Person 数据类，其中有 name 和 age 属性。由于这些属性是在类头中声明的，因此不需要类体。在 main()中，我们创建一个数据类的实例 person，并将其直接传递给 println()函数。当 println()遇到数据类实例时，Kotlin 会自动调用对象的 toString()方法，从而生成以下输出：

```
Person(name=Steve, age=40)
```

数据类在建模和处理数据时非常有用，通过将相关的值分组为一个单一的、定制的对象，以清晰且高效的方式进行操作。它们与映射（maps）有一些相似之处，映射使用键值对而不是类属性来关联名称和数据值。然而，尽管映射主要用于按键存储和检索值，但数据类更适合以更有意义和结构化的方式建模数据。数据类还提供了我们刚刚讨论过的那些有用的自动生成方法。

#### 对与三元组

在 Kotlin 中，*对*是一个数据类，可以存储恰好两个值，这些值可以是相同类型或不同类型。对非常适合在单一对象中存储两个相关的值，例如图表上一个点的 x 和 y 坐标，或者一个人的姓名和年龄。它们还提供了一种将键与值关联的方式。在后一种情况下，对中的第一个值是第二个值的字符串描述符。你可以使用 Pair() 构造函数创建一个对，传入两个值作为参数，或者在赋值语句中通过在两个值之间使用 to 来创建对。以下是每种方法的示例：

```
val pair1 = Pair("Alice", 20)
val pair2 = "Bob" to 25
```

*三元组*是一个类似的结构，用于在单一对象中存储三个相关的值，例如一个人的姓名、年龄和性别，或者一个像素的 RGB 颜色组件。你可以使用 Triple() 构造函数创建一个三元组，如下所示：

```
val triple1 = Triple("Alice", 20, "Female")
```

一旦一对或三元组被创建，它就是不可变的，因此其值不能被更新。这些值可以通过点表示法作为第一、第二和第三个属性访问。例如：

```
val pair = "Hello" to "World"
val triple = Triple(1, 2, 3)

println(pair.first)   // Hello
println(triple.third) // 3
```

你还可以使用解构语法（参见“解构”框）将一对或三元组的数据元素提取到单独的变量中。以下是一个示例：

```
val pair = Pair("John", 29)
val (name, age) = pair // deconstruction
println("Name: $name") // Print the value of name.
println("Age: $age")   // Print the value of age.
```

我们创建了一个名为 pair 的对，其中包含两个值：John 和 29。然后，我们使用解构语法提取这些值并将其分配给 name 和 age 变量。从那里，我们可以独立使用这些变量来打印出对对象的姓名和年龄。

#### 抽象类

在 Kotlin 中，*抽象类*是一种不能单独实例化的类。它作为其他类通过继承和多态扩展的蓝图。你可以在想要提供一个共同的基础或框架时使用抽象类——包括必须由各个子类实现和具体化的方法和属性，但它本身不能作为一个完全功能的类存在。从这个意义上讲，抽象类类似于用 open 声明的常规父类，它允许继承并支持属性和方法的重写。关键区别在于，你不能直接实例化一个抽象类。

使用`abstract`关键字声明一个抽象类。抽象类可以包含抽象属性（没有初始值，只有名称和数据类型）和抽象方法（没有实现，只有名称和返回类型）。抽象属性和方法使用`abstract`关键字声明，就像类本身一样。抽象类还可以包含具体的（非抽象的）属性和方法——完整的变量或函数声明，提供默认行为。

任何继承自抽象类的类必须实现继承的抽象属性和方法，给它们赋予具体的值和定义。如果子类没有这样做，它也必须被声明为抽象类。子类还可以选择重写抽象类的具体成员。

下面是一个示例，展示了这一切如何工作，在这个例子中我们创建了一个抽象的 Shape 类，并将其作为 Circle 和 Square 类的模型：

```
abstract class Shape {
    abstract fun area(): Double  // abstract method
    val name: String = "Shape"   // concrete property
    fun describe() {
        println("This is a $name")
    }
}

class Circle(val radius: Double): Shape() {
    override fun area(): Double {
        return Math.PI * radius * radius
    }
}

class Square(val side: Double): Shape() {
    override fun area(): Double {
        return side * side
    }
}

fun main() {
    val circle = Circle(5.0)
    val square = Square(4.0)

    circle.describe()
    println("Area of the circle: ${circle.area()}")

    square.describe()
    println("Area of the square: ${square.area()}")
}
```

我们使用`abstract`关键字将 Shape 指定为抽象类。它有一个抽象的`area()`方法，应该返回一个类型为 Double 的值，还有一个具体的`name`属性，值为"Shape"，以及一个具体的`describe()`方法，打印一条消息。然后我们将`Circle`和`Square`声明为 Shape 的非抽象子类。每个子类都赋予一个唯一的属性（Circle 的`radius`和 Square 的`side`），并继承 Shape 的`name`属性和`describe()`方法。子类还必须使用`override`关键字为继承的`area()`方法提供具体实现。通过这种方式，抽象的 Shape 类作为两种形状的共同结构，强制要求任何子类实现一个计算形状面积的方法。

在`main()`中，我们创建每个具体类的实例，并在字符串模板中调用它的`area()`方法。代码应输出以下内容：

```
This is a Shape
Area of the circle: 78.53981633974483
This is a Shape
Area of the square: 16.0
```

除了确保父类和子类之间通过共享结构保持一致性，抽象类还减少了代码重复，提升了代码可读性，并简化了代码维护。

#### 接口

*接口*是一个方法和属性的集合，形成了一组共同的行为，实施该接口的类型必须遵循这些行为。这些方法和属性是抽象的，因为我们不能直接使用它们，但在定义时我们不会使用`abstract`关键字。接口可以包含抽象方法和属性的声明，以及方法实现。然而，它们不能存储状态，意味着它们不能包含任何存储数据的字段或属性。

一个类或对象可以实现一个或多个接口。当一个类实现了一个接口时，它必须为该接口中声明的所有抽象方法和属性提供完整的定义。从这个意义上讲，接口充当了实现它的类的共同契约，列出了任何实现该接口的类必须具备的特性。

下面是一个如何在 Kotlin 中定义和使用接口的示例：

```
import kotlin.math.PI

interface Properties {
    fun area(): Double
    fun perimeter(): Double
}

class Circle(val radius: Double): Properties {
    override fun area() = PI * radius * radius
    override fun perimeter() = 2 * PI * radius
}

fun main() {
    val circle = Circle(4.0)
    val area = circle.area()
    val perimeter = circle.perimeter()

    println("Properties of the circle:")
    println(" radius = ${circle.radius}\n area = $area\n" +
            " perimeter = $perimeter")
}
```

我们使用 interface 关键字来声明 Properties 接口。它定义了两个抽象方法 area() 和 perimeter()，这两个方法都返回一个浮点值。任何实现该接口的类（如这里声明的 Circle 类）必须为这两个方法提供定义。

实现接口的语法类似于继承：类头后面跟一个冒号，然后是接口的名称。请注意，当实现接口中的函数时，我们还需要使用 override 关键字。

在 main() 函数中，我们创建了一个 Circle 类的实例，并调用了它的 area() 和 perimeter() 方法，将结果存储在局部变量 area 和 perimeter 中。然后，我们将这些值打印到控制台，输出如下：

```
Properties of the circle:
radius = 4.0
area = 50.26548245743669
perimeter = 25.132741228718345
```

Kotlin 接口还可以继承其他接口，这意味着它们可以为继承的成员提供实现，并声明新的函数和属性。然而，实现这种接口的类只需要定义缺失的实现。

#### 枚举类

*枚举*（*enumeration* 的缩写）是一种特殊的类，用于定义一组有限的常量值。枚举通常用于表示一组固定的相关值，如一周的七天、方位、状态码、扑克牌花色和季节。在 Kotlin 中，我们使用 enum class 关键字来定义一个枚举，后面跟上类名。然后是一个用逗号分隔的枚举常量列表，这些常量被大括号括起来。以下是 Kotlin 中枚举的示例：

```
// Define an enum class for days of the week.
enum class DayOfWeek {
    MONDAY, TUESDAY, WEDNESDAY, THURSDAY,
    FRIDAY, SATURDAY, SUNDAY
}

fun main() {
    // using the enum values
    val today = DayOfWeek.MONDAY

    when (today) {
        DayOfWeek.MONDAY -> println("It's a manic Monday!")
        else -> println("It's some other day.")
    }
}
```

在这个示例中，我们定义了一个名为 DayOfWeek 的枚举类，表示一周的七天。类的主体包含枚举常量值的逗号分隔列表，按照惯例，常量名使用全大写字母。在 main() 函数中，我们创建了一个变量 today，并将其赋值为枚举中的 DayOfWeek.MONDAY。枚举常量总是这样访问，使用点符号将枚举类名与特定常量名连接。接着，我们使用 when 表达式检查 today 的值，并根据不同的日期打印相应的信息。程序应该输出 It's a manic Monday!，因为今天的值设置为 DayOfWeek.MONDAY。

### 复制对象

在许多情况下，你需要复制一个对象，也就是说，你需要创建一个与原始对象具有相同或修改过的值的新实例。在 Kotlin 中，你可以创建对象的浅拷贝或深拷贝。它们的区别在于原始对象和拷贝对象是否以及如何连接。你使用哪种类型的拷贝取决于具体情况以及原始对象的结构或复杂性。

#### 浅拷贝

*浅拷贝*在 Kotlin 中涉及创建一个新的对象，它与现有对象相似。然而，复制的对象并没有完全复制原始对象中的任何嵌套对象。相反，复制的对象保留了与原始对象相同的对嵌套对象的引用。因此，对原始版本中嵌套对象的更改也会影响复制版本，反之亦然。如前所述，任何数据类内置的 copy()方法都会创建浅拷贝。

举例来说，假设我们定义了一个包含 name 属性和 hobbies 属性（后者是 MutableList<String>）的 Person 数据类。hobbies 属性被认为是嵌套的，因为字符串列表本身是 Person 对象中的一个对象。如果我们使用该类的内置 copy()方法来复制 Person 对象，那么复制将是浅拷贝。新实例将与原始实例共享相同的列表引用，因此无论我们修改原始列表还是浅拷贝的列表，数据类的两个实例都会受到影响。以下是演示此行为的代码：

```
data class Person(val name: String,
                  val hobbies: MutableList<String>)
fun main() {
    val person1 = Person("Bob", mutableListOf("Reading", "Gaming"))
  ❶ val person2 = person1.copy()

    // Print both objects.
    println(person1)
    println(person2)

    // Add a new element to the mutable list of person1.
    person1.hobbies.add("Coding")

    // Print both objects again.
    println(person1)
    println(person2)
}
```

我们按描述声明了 Person 数据类，并创建了两个该类的实例。第一个 person1 是从头开始实例化的，而 person2 是通过复制 person1 ❶创建的。为了查看浅拷贝的影响，我们打印出两个对象，向 person1 对象的 hobbies 列表中再添加一个爱好，然后再次打印两个对象。代码应该产生以下输出：

```
Person(name=Bob, hobbies=[Reading, Gaming])
Person(name=Bob, hobbies=[Reading, Gaming])
Person(name=Bob, hobbies=[Reading, Gaming, Coding])
Person(name=Bob, hobbies=[Reading, Gaming, Coding])
```

注意到尽管我们仅修改了 person1 的 hobbies 属性，person2 却以相同的方式受到影响。这是因为 person2 的 hobbies 属性并不是一个真正的克隆，它引用了与 person1 的 hobbies 属性相同的内存位置。请记住，这只适用于嵌套对象；如果我们更新了 person1 的 name 属性，这一变化只会应用于 person1，因为这个属性不是嵌套的。

浅拷贝在性能优化中可以很有用，因为它避免了大量数据的重复复制和占用额外的内存空间。但如果你需要两个 Person 类的实例彼此完全独立呢？这就是深拷贝派上用场的时候。

#### 深拷贝

*深拷贝*通过复制现有对象的所有嵌套对象以及非嵌套属性，创建一个新的、完全独立的对象。这导致两个独立且不相关的对象，因此对一个对象的更改不会影响另一个对象。在 Kotlin 中，通常需要编写一个针对特定类定制的函数来进行深拷贝。以下是一个简单的示例：

```
data class Address(var street: String, val city: String)
data class Person(val name: String, val address: Address)

fun deepCopyPerson(person: Person): Person {
  ❶ val clonedAddress = Address(person.address.street,
                                person.address.city)
    return Person(person.name, clonedAddress)
}

fun main() {
    val originalPerson = Person("Alice", Address("123 Main St", "Cityville"))
    val copiedPerson = deepCopyPerson(originalPerson)

    // Modify the original address.
    originalPerson.address.street = "456 Elm St"

    // Check if the copied address remains unchanged.
    println(originalPerson.address.street) // output: 456 Elm St
    println(copiedPerson.address.street)   // output: 123 Main St
}
```

我们声明了两个数据类：Address 和 Person。注意 Person 类有一个类型为 Address 的 address 属性，这意味着该属性是一个嵌套对象。为了实现 Person 类的深拷贝，我们声明了一个 deepCopyPerson() 函数。该函数首先通过手动提取原始 Person 对象的嵌套地址属性来创建一个新的 Address 对象❶。然后它返回一个新的 Person 对象，该对象包含原始对象的 name 属性以及深拷贝的 Address 对象。

在 main() 中，我们创建了一个 Person 对象，然后使用 deepCopyPerson() 进行拷贝。此时，我们可以修改原始 Person 对象的 address 属性，而不会对拷贝产生任何影响，因为嵌套对象在深拷贝过程中已被复制。

另一个常见的需求是深拷贝一个对象列表。这可以通过一行代码来完成，使用列表的 map() 方法对每个对象调用 copy()。具体做法如下：

```
data class Person(var name: String, var age: Int)

fun main() {
    // original mutable list
    val originalList =
        mutableListOf(Person("Alice", 30), Person("Bob", 25))

    // Deep-copy the list using map() and copy().
    val deepCopyList =
        originalList.map{it.copy()}.toMutableList()
}
```

在这个示例中，我们有一个可变的 Person 数据类对象列表，其中每个 Person 对象有两个属性：name 和 age。我们使用 map() 方法创建该列表的深拷贝，map() 方法遍历原始列表的元素，对每个元素应用一个函数，并将结果存储在一个新的列表中。在此情况下，应用的函数是 lambda 表达式 it.copy()，它复制当前的 Person 对象（这是可能的，因为 Person 类没有任何嵌套对象）。我们在 lambda 后面链式调用了 toMutableList()，因为 map() 方法返回的是一个常规的只读列表，而不是一个可变列表。

我邀请你在之前的代码中添加几行，修改原始列表中一个 Person 对象的属性，然后打印两个列表。你应该会发现，修改原始列表并不会影响复制的列表（反之亦然）。

项目 2：构建一个多功能任务管理器

让我们将本章所学的数据结构应用到一个简单的项目中：我们将创建一个基于控制台的任务管理器应用程序。该应用程序将允许用户跟踪他们的日常任务，具备以下关键功能：

+   向任务列表中添加任务

+   显示所有任务的列表

+   标记任务为完成

+   删除不需要的或已完成的任务

+   退出程序

我们的主要挑战是维护一个任务列表。由于任务可以添加和删除，因此可变列表是合适的结构。我们还必须决定每个任务的属性是什么。我们可以将这些属性封装在数据类中。此外，我们需要有效处理用户交互，提供选项并确保对无效输入进行强有力的错误处理，这些概念我们在第一章中有提到。

#### 代码

在深入了解个别组件及其如何交互之前，我们先从程序的结构组成部分开始高层次的概述。以下是我们需要的数据结构、函数和逻辑的大纲：

```
// macro view of the task manager program

data class Task(val title: String,
                val description: String,
                var status: String = "not done"
)

class TaskManager {
  ❶ val taskList = mutableListOf<Task>()
 fun addTask(task: Task) {...}
    fun listTasks() {...}
    fun markTaskAsDone(taskIndex: Int) {...}
    fun deleteTask(taskIndex: Int) {...}
}

fun printOptions() {...}
fun readIndex(taskListSize: Int): Int? {...}

fun main() {
    val taskManager = TaskManager()

    while (true) {
        printOptions()
        when (readln()) {
            "1" -> {...}
            "2" -> {...}
            "3" -> {...}
            "4" -> {...}
            "5" -> return   // breaks the while loop
            else -> println("\nInvalid choice. Please try again.")
        }
    }
}
```

项目包含五个主要代码块。首先，Task 数据类定义了每个单独任务的结构；每个任务将有一个标题、一个描述和一个默认设置为“未完成”的状态属性。接下来，TaskManager 类包含处理所有任务管理工作的函数，例如添加、列出和删除任务。注意它的 taskList 属性 ❶，这是一个可变列表，用于存储所有当前的任务。两个独立的辅助函数，printOptions()和 readIndex()，支持用户交互和输入处理。最后，main()函数负责向用户展示选项并根据用户选择引导程序流程。

我们现在将以自上而下的方式探索 main()函数及其组件。在此过程中，我们将实现之前代码列表中用{...}标记的缺失代码块。

main()函数开始时会创建一个名为 taskManager 的 TaskManager 类实例。该类又初始化了一个类型为 Task 的可变列表作为其 taskList 属性。这个列表最初为空，但它是一个可变列表，因此我们可以根据需要添加或删除元素。

接下来，我们调用一个 while 循环，反复向用户展示任务管理选项菜单并响应用户的请求。循环的条件非常简单，即为 true，这意味着除非用户选择退出程序的选项，否则它将无限重复执行（稍后会详细介绍这一机制）。循环的第一部分是调用 printOptions()函数，定义如下：

```
fun printOptions() {
    println("\nTask Manager Menu:")
    println("1\. Add Task")
 println("2\. List Tasks")
    println("3\. Mark Task as done")
    println("4\. Delete Task")
    println("5\. Exit")
    print("Enter your choice (1-5): ")
}
```

该函数简单地显示用户可以输入的五个可用命令，分别用数字 1 至 5 表示。

##### 添加任务

打印选项后，while 循环使用 when 表达式根据输入的数字触发相应的代码。再次看看这个 when 表达式，包括“1”分支的实现，用于添加任务：

```
❶ when (readln()) {
    "1" -> {
        print("\nEnter task title: ")
        val title = readln()
        print("Enter task description: ")
        val description = readln()
      ❷ val task = Task(title, description)
      ❸ taskManager.addTask(task)
    }
    "2" -> {...}
    "3" -> {...}
    "4" -> {...}
    "5" -> break   // breaks the while loop
  ❹ else -> println("\nInvalid choice. Please try again.")
}
```

when 表达式通过使用 readln()从控制台读取一行输入（字符串），表示用户的菜单选择 ❶。如果输入的值与五个选项中的任何一个都不匹配（“1”、“2”、“3”、“4”或“5”），则触发 when 表达式中的 else 块 ❹，提示用户他们的选择无效，并要求他们重新选择。

当用户选择“1”选项时，执行“1” -> 下的代码块。由于这个选择与添加任务相关，系统会提示用户提供任务标题和描述。我们使用这些输入值（如果用户仅按 ENTER 键，则为空字符串）来创建一个新的 Task 数据类实例 ❷，然后将其作为参数传递给 taskManager 对象的 addTask()方法 ❸。此方法将任务添加到 taskList 可变列表中，如下所示：

```
fun addTask(task: Task) {
    taskList.add(task)
}
```

我们调用 list 的 add()方法，将新任务插入到列表的末尾。

##### 列出任务

当用户选择“2”选项（列出任务）时，执行 when 表达式下的“2” -> 代码块。这会调用 taskManager 对象的 listTasks()方法：

```
when (readln()) {
`--snip--`
    "2" -> taskManager.listTasks()
```

让我们来看一下 listTasks() 方法，这是在 TaskManager 类中定义的第二个方法：

```
fun listTasks() {
    if (taskList.size > 0) {
        println("\nTasks:")
        for ((index, task) in taskList.withIndex()) {
          ❶ println("${index+1}. ${task.title} - " +
                    "${task.description} - ${task.status}")
        }
    } else
        println("Task list is empty.")

}
```

在 listTasks() 内部，我们首先检查 taskList 是否有任务。如果有，我们遍历任务并打印它们，显示它们的索引、标题、描述和完成状态。虽然 Kotlin 列表的索引从 0 开始，但大多数人认为列表中的第一个项目是项目 1，因此在打印时我们会在每个索引上加 1 ❶。如果任务列表为空，我们会打印一个简单的消息说明这一点。

##### 标记任务为完成

当用户选择 "3" 选项标记任务为完成时，"3" -> 下的代码块会被执行，如下所示：

```
when (readln()) {
`--snip--`
    "3" -> {
        taskManager.listTasks()
      ❶ if (taskManager.taskList.size <= 0) {
            continue
        } else {
            print("\nEnter the task number to mark as done: ")
          ❷ val taskNumber =
                readIndex(taskManager.taskList.size)
            if (taskNumber != null) {
                taskManager.markTaskAsDone(taskNumber -1)
            }
        }
    }
```

在这段代码块中，我们首先调用 listTasks() 方法显示当前任务列表。然后，如果发现 taskList 为空 ❶，程序将继续，意味着剩余的代码会被跳过，外部的 while 循环会重新启动，用户会再次看到菜单选项。否则，用户会被提示选择任务的索引，从显示的任务列表中进行选择。我们使用 readIndex() 函数 ❷ 处理用户输入，验证数据如下：

```
fun readIndex(taskListSize: Int): Int? {
    val input = readln()
  ❶ if (input.isBlank()) {
        println("Invalid input. Please enter a valid task number.")
        return null
    }

  ❷ val taskNumber = input.toIntOrNull()
    if (taskNumber != null && taskNumber >= 1 &&
                         taskNumber <= taskListSize) {
        return taskNumber
    } else {
        println("Invalid task number. Please enter a valid task number.")
        return null
    }
}
```

在这段代码中，我们首先从控制台读取一行文本。如果输入为空 ❶，我们显示一个无效输入消息，并返回 null 值。这个 null 返回值将导致没有任务被标记为完成。

如果输入不为空，我们将其转换为 IntOrNull 类型 ❷。然后我们进行进一步检查，确保该 Int 值大于或等于 1 且小于或等于 taskList 的大小（该值作为参数传递给函数）。如果满足这些条件，用户的输入值会被返回；否则，我们返回 null，这将跳过 "3" 选项代码的其余部分。

返回到 when 表达式的 "3" 分支，如果用户输入有效且不为空，我们从 TaskManager 类调用 markTaskAsDone() 方法，并传入 taskNumber - 1 作为参数（记住，在展示任务给用户之前，我们已经对每个任务的索引加了 1）。该方法在这里定义：

```
fun markTaskAsDone(taskIndex: Int) {
  ❶ if (taskIndex in taskList.indices) {
        taskList[taskIndex].status = "done"
    } else {
        println("Invalid task index. Task not found.")
    }
}
```

我们验证 taskIndex 参数是否落在 taskList 中有效索引的范围内，使用列表的内置 indices 属性访问 ❶。如果 taskIndex 在这个范围内，我们将相应任务的 status 属性设置为 "done"。此方法中的 else 块用于处理任务索引超出范围的情况，虽然它并不是严格必要的，因为 readIndex() 函数已经验证了所选索引在有效范围内。

##### 删除任务

当用户选择 "4" 选项删除任务时，when 表达式下的 "4" -> 代码块会被执行，如下所示：

```
when (readln()) {
`--snip--`
    "4" -> {
        taskManager.listTasks()
        if (taskManager.taskList.size <= 0) {
            continue
        } else {
            print("\nEnter the task number to be deleted: ")
            val taskNumber =
                readIndex(taskManager.taskList.size)
            if (taskNumber != null) {
                taskManager.deleteTask(taskNumber - 1)
            }
        }
    }
```

这个代码块与选项“3”的代码几乎相同：我们显示任务列表，如果列表为空则跳过其余代码，否则通过 readIndex()函数从用户输入任务编号。不同之处在于，对于有效且非空的输入，我们调用 TaskManager 类中的 deleteTask()方法，而不是调用 markTaskAsDone()方法。以下是 deleteTask()的定义：

```
fun deleteTask(taskIndex: Int) {
    if (taskIndex in taskList.indices) {
        taskList.removeAt(taskIndex)
    } else {
        println("Invalid task index. Task not found.")
    }
}
```

这次，如果 taskIndex 在有效范围内，我们使用 removeAt()来删除 taskList 中对应的任务。

##### 退出程序

最后一个可用的选项是“5”，用于退出程序。它触发了“5” -> 当表达式的分支，终止 while 循环并将程序流程返回到循环外部：

```
when (readln()) {
`--snip--`
    "5" -> break   // breaks the while loop
```

由于在 while 循环后 main()函数中不再有代码可执行，打断循环会导致程序正常终止。

#### 结果

尝试启动并长时间实验任务管理器程序。以下是我在尝试程序时，做出各种任意选择的示例输出：

```
Task Manager Menu:
1\. Add Task
2\. List Tasks
3\. Mark Task as done
4\. Delete Task
5\. Exit
Enter your choice (1-5): **1**

Enter task title: **Task 1**
Enter task description: **Reply to Nathan's email**

Task Manager Menu:
1\. Add Task
2\. List Tasks
3\. Mark Task as done
4\. Delete Task
5\. Exit
Enter your choice (1-5): **1**

Enter task title: **Task 2**
Enter task description: **Complete Chapter 2 by this weekend**

Task Manager Menu:
1\. Add Task
2\. List Tasks
3\. Mark Task as done
4\. Delete Task
5\. Exit
Enter your choice (1-5): **2**

Tasks:
1\. Task 1 – Reply to Nathan's email - not done
2\. Task 2 – Complete Chapter 2 by this weekend - not done
```

你看到的输出可能会有所不同，因为你的选择与我的不同。尽管它的功能有些有限，这个程序成功地集成了一些现实任务管理工具中的基本特性。我们只用了大约 110 行 Kotlin 代码，并使用了如可变列表和具有自身属性和方法的类等结构，以保持代码的组织性。

### 总结

在本章中，我们探索了数据操作和面向对象编程的基本方面。我们从数组开始，数组存储特定类型或其子类型的值。数组在大小上是固定的，但可以修改其值。与之相对，列表在内容和大小上都是不可变的，尽管可变列表在需要时提供了灵活性。列表是一种集合类型，此外还有集合和映射。

我们进入了用户定义类的世界，这些类以属性的形式存储数据，并包含用于操作这些数据的方法。我们看到封装如何在类内部保护数据，而继承和多态则实现了代码重用和模块化设计。我们还涵盖了抽象类、数据类、接口和枚举类等主题，每种都有其独特的作用和优势。例如，抽象类为一组相关类提供了一个更高层次的框架（超类），而接口则强制实现所有继承类型的一致方法和属性。

你通过示例和练习学习了这些概念，进一步巩固了理解。本章的高潮是一个实用项目，你学习并将一个基于文本的任务管理器转变为一个多功能工具（假设你完成了练习）。

本章与关于 Kotlin 基础的第一章一起，为你提供了开始进入 Kotlin 应用世界所需的基本概念和基础知识。现在，你已经为探索数学、科学、建模、算法和优化领域中各种有趣且逐步复杂的挑战做好了充分准备。不过，首先，我们将通过 JavaFX 探索数据可视化的基础知识，JavaFX 是我们将在许多后续项目中使用的工具。

### 资源

Kotlin. “Kotlin 文档。”（Kotlin 官方文档。）访问日期：2024 年 6 月 15 日。*[`kotlinlang.org/docs/home.xhtml`](https://kotlinlang.org/docs/home.xhtml)*。

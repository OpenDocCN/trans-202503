## 1 PYTHON 回顾

![](img/opener-img.png)

如果你打算开发 Dash 应用程序，可能至少已经了解一点 Python。尽管本书不会假设你是专家，但我们会复习一些在使用 Dash 时更相关的 Python 概念，包括列表、字典、面向对象编程和装饰器函数。如果你已经非常熟悉这些领域，可以直接跳到 第二章，本章将介绍我们将在本书中使用的 Python IDE——PyCharm。

### 列表

让我们快速复习一下在几乎所有 Dash 应用程序中都使用的最重要的容器数据类型：Python 列表！在 Dash 中，列表非常重要，因为它们用于定义布局，包含 Dash Bootstrap 主题，并且通常出现在回调和由 Plotly 构建的图形中。

列表容器类型存储一系列元素。列表是可变的，意味着你可以在创建后修改它们。在这里，我们创建了一个名为 lst 的列表，并打印其长度：

lst = [1, 2, 2]

print(len(lst))

我们的输出仅为：

3

我们使用方括号和逗号分隔的元素来创建列表。列表可以包含任意的 Python 对象、重复值，甚至其他列表，因此它们是 Python 中最灵活的容器类型之一。在这里，我们用三个整数元素填充了我们的列表 lst。len() 函数返回列表中的元素数量。

添加元素

向已存在的列表添加元素有三种常见方法：追加、插入和连接。

append() 方法将其参数放置在列表的末尾。以下是一个追加的示例：

lst = [1, 2, 2]

lst.append(4)

print(lst)

这将打印：

[1, 2, 2, 4]

insert() 方法将在给定的位置插入一个元素，并将所有后续元素向右移动。以下是一个插入的示例：

lst = [1, 2, 4]

lst.insert(2,2)

print(lst)

这将打印相同的结果：

[1, 2, 2, 4]

最后，连接操作：

print([1, 2, 2] + [4])

我们得到：

[1, 2, 2, 4]

对于连接操作，我们使用加号 (+) 运算符。它通过将两个现有列表拼接在一起创建一个新的列表。

所有操作都会生成相同的列表 [1, 2, 2, 4]。其中，添加操作最快，因为它不需要像插入操作那样遍历列表并将元素插入正确位置，也不需要像连接操作那样创建一个由两个子列表组成的新列表。

要向给定列表中添加多个元素，可以使用 extend() 方法：

lst = [1, 2]

lst.extend([2, 4])

print(lst)

该代码通过如下方式修改现有的列表对象 lst：

[1, 2, 2, 4]

上述代码是一个可以容纳重复值的列表示例。

删除元素

我们可以使用 lst.remove(x) 从列表中移除元素 x，如：

lst = [1, 2, 2, 4]

lst.remove(1)

print(lst)

这将给我们如下结果：

[2, 2, 4]

该方法作用于列表对象本身——不会创建新列表，而是修改原始列表。

反转列表

你可以使用 lst.reverse() 方法反转列表元素的顺序：

lst = [1, 2, 2, 4]

lst.reverse()

print(l)

这将打印：

[4, 2, 2, 1]

反转列表也会修改原始列表对象，而不是创建一个新的列表对象。

排序列表

你可以使用 lst.sort() 方法对列表元素进行排序：

lst = [2, 1, 4, 2]

lst.sort()

print(lst)

我们看到排序后的列表：

[1, 2, 2, 4]

同样，排序列表会修改原始列表对象。默认情况下，结果列表按升序排序。要按降序排序，可以传递 reverse=True，如下所示：

lst = [2, 1, 4, 2]

lst.sort(reverse=True)

print(lst)

然后我们看到结果是按逆序排列的：

[4, 2, 2, 1]

你还可以指定一个 key 函数，并将其作为参数传递给 sort()，以自定义排序行为。key 函数只是将一个列表元素转换为可以排序的元素。例如，它可以通过使用 Dash 组件的字符串标识符作为键，将一个不可排序的对象（如 Dash 组件）转换为可排序类型。通常，这些 key 函数允许你对自定义对象的列表进行排序；例如，按员工年龄对员工对象列表进行排序。以下示例对列表进行排序，但使用元素的逆（负）值作为 key：

lst = [2, 1, 4, 2]

lst.sort(key=lambda x: −x)

print(lst)

这将给我们：

[4, 2, 2, 1]

元素 4 的 key 是负值 −4，这是所有列表元素中最小的值。由于列表是按升序排序的，这就是结果排序列表的第一个值。

索引列表元素

你可以使用 list.index(x) 方法来确定指定列表元素 x 的索引，如下所示：

print([2, 2, 4].index(2))

print([2, 2, 4].index(2,1))

方法 index(x) 会查找列表中元素 x 的第一次出现，并返回其索引。

你可以通过传递第二个参数来指定起始索引，该参数设置从哪个索引开始搜索。因此，第一行打印的是值 2 的第一次出现的索引，第二行则从索引 1 开始搜索，打印值 2 第一次出现的索引。在这两种情况下，该方法都会立即找到值 2 并打印：

0

1

索引基础

这里是 Python 中索引的快速概述，通过示例来展示。假设我们有一个字符串 'universe'。这些索引实际上就是该字符串中各个字符的位置，从 0 开始：

索引             0      1      2      3      4      5      6      7

字符      u      n      i       v       e      r      s      e

第一个字符的索引是 0，第二个字符的索引是 1， i-th 字符的索引是 i−1。

### 切片

*切片* 是从给定字符串中切出子字符串的过程。我们称这个子字符串为 *切片*。切片的语法如下：

string[start:stop:step]

start 参数是我们希望开始字符串的位置，并且该位置会包含在切片中，而 stop 是我们希望字符串停止的位置，该位置会排除在切片之外。忘记 stop 索引被排除在外是一个常见的错误源，所以一定要记住这一点。step 参数告诉 Python 要包含哪些元素，因此，如果 step 为 2，它会包含每隔一个元素；如果 step 为 3，它会包含每隔三个元素。下面是一个步长为 2 的例子：

s = '----p-y-t-h-o-n----'

print(s[4:15:2])

这将给我们：

python

所有三个参数都是可选的，因此你可以跳过它们，使用默认值 start=0、stop=len(string) 和 step=1。在切片冒号前省略 start 参数表示切片从第一个位置开始，省略 stop 参数表示切片在最后一个元素处结束。省略 step 参数表示步长为 1。这里我们省略了 step 参数：

x = 'universe'

print(x[2:4])

这给我们：

iv

这里我们指定了起始位置但没有指定结束位置，并给定了步长为 2，因此我们从第三个字符开始，跳过每个字符，直到字符串的末尾：

x = 'universe'

print(x[2::2])

这给我们：

ies

如果我们不小心给出了一个超出最大序列索引的 stop 索引，Python 会假设我们是想让切片在原始字符串的末尾结束。这里是一个例子：

word = "galaxy"

print(word[4:50])

这打印出：

xy

只需记住，如果切片超出序列索引，什么意外情况也不会发生。

你还可以为所有三个参数提供负整数。start 或 stop 的负索引告诉 Python 从末尾开始计数。例如，string[–3:] 将从倒数第三个元素开始切片，而 string[–10:–5] 将从倒数第十个元素开始（包括该元素），并且在倒数第五个元素处停止（不包括该元素）。负步长意味着 Python 会从右往左切片。例如，string[::–1] 会将字符串反转，而 string[::–2] 会每隔一个字符取一个，且从最后一个字符开始，向左移动。

### 字典

*字典* 是一种用于存储键值对的有用数据结构。我们通过大括号来定义字典，如下所示：

calories = {'apple': 52, 'banana': 89, 'choco': 546}

键首先出现，后面跟着冒号，然后是值。键值对之间应该用逗号分隔。这里，'apple' 是第一个键，52 是它的值。你可以通过指定字典和括号中的键来访问字典中的单个元素。在下面的例子中，我们比较了苹果的卡路里和一块巧克力的卡路里：

print(calories['apple'] < calories['choco'])

当然，它会返回：

True

字典是一种可变数据结构，因此你可以在创建后更改它。例如，你可以添加、删除或更新现有的键值对。这里，我们向字典中添加了一个新的键值对，存储了卡布奇诺的卡路里是 74：

calories['cappu'] = 74

print(calories['banana'] < calories['cappu'])

当我们断言一杯卡布奇诺的卡路里比一根香蕉还多时，我们得到：

False

我们使用 keys() 和 values() 函数来访问字典中的所有键和值。这里我们检查字符串 'apple' 是否是字典的一个键，以及整数 52 是否是字典的一个值。事实上，这两者的结果都是 True：

print('apple' in calories.keys())

print(52 in calories.values())

要访问字典的所有键值对，我们使用 dictionary.items() 方法。在以下的 for 循环中，我们遍历 calories 字典中的每一个 (key, value) 对，并检查每个值是否大于 500 卡路里。如果是这样，它会打印出相应的键：

for key, value in calories.items():

   if value > 500:

      print(key)

我们唯一的结果是：

'choco'

这为我们提供了一种方便的方法，可以在不单独访问每个元素的情况下，遍历字典中的所有键和值。

### 列表推导式

列表推导式是一种紧凑的创建列表的方式，其基本格式是 [expression + context]。context 告诉 Python 向新列表添加哪些元素。expression 定义了在添加这些新元素之前需要对它们做什么。例如，列表推导式语句

[x for x in range(3)]

创建新的列表 [0, 1, 2]。这个例子中的 context 是 for x in range(3)，因此循环变量 x 依次取值 0、1 和 2。这个例子中的 x 表达式非常简单：它只是将当前的循环变量添加到列表中，而不进行任何修改。然而，列表推导式能够处理更复杂的表达式。

列表推导式通常用于仪表盘应用程序中；例如，它用于动态创建多个下拉菜单选项。在这里，我们创建了一个字符串列表——工作日——然后使用该列表在列表推导式中创建一个字典列表。我们将使用这些字典来为 Dash 下拉菜单创建标签和选项，菜单显示在图 1-1 中：

days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

options = [{'label': day, 'value': day} for day in days]

![](img/Figure1-1.png)

图 1-1：一个 Dash 下拉菜单

上下文是 for day in days，因此我们遍历每个工作日 'Mon', … , 'Sun'。该表达式创建了一个包含两个键值对的字典，{'label': day, 'value': day}。这是一种非常简洁的方式，来创建以下字典列表：

[{'label': 'Mon', 'value': 'Mon'}, {'label': 'Tue', 'value': 'Tue'},

{'label': 'Wed', 'value': 'Wed'}, {'label': 'Thu', 'value': 'Thu'},

{'label': 'Fri', 'value': 'Fri'}, {'label': 'Sat', 'value': 'Sat'},

{'label': 'Sun', 'value': 'Sun'}]

另一种方式是使用常规的 Python for 循环，如这三行代码所示：

options = []

for day in days:

   options.append({'label': day, 'value': day})

你创建了一个字典列表，其中标签和对应的值与相应的星期几相关联。在这里，下拉菜单将显示标签'Mon'，如果用户选择它，标签将与值'Mon'关联。

这个上下文包含了任意数量的 for 和 if 语句。我们可以在列表推导式中使用 if 语句来过滤结果；例如，我们可以仅使用工作日来创建下拉菜单选项：

options = [{'label': day, 'value': day} for day in days if day not in ['Sat', 'Sun']]

在这里，我们使用if语句将Sat和Sun排除在结果列表之外。这是一种更快速、更简洁的写法，用于在for循环中实现常规的if语句。

### 面向对象编程

在 Python 中，一切都是对象。即使是整数值也是对象。这与 C 语言等编程语言不同，在这些语言中，整数、浮动数和布尔值是原始数据类型。因此，Python 是建立在一种严谨一致的面向对象范式上的。

类与对象

面向对象的 Python 核心是类。类是创建对象的蓝图。类的描述告诉你一个对象的外观以及它能做什么，这分别被称为对象的*数据*和*功能*。数据通过*属性*定义，属性是与给定对象相关的变量。功能通过*方法*定义，方法是与给定对象相关的函数。

让我们通过哈利·波特的例子来看这些概念的实际应用。首先，我们将创建一个只有属性而没有方法的类。在这里，我们创建了一个Muggle类，并从中创建了两个Muggle对象：

class Muggle:

   def __init__(self, age, name, liking_person):

      self.age = age

      self.name = name

      self.likes = liking_person

Vernon = Muggle(52, "Vernon", None)

Petunia = Muggle(49, "Petunia", Vernon)

我们使用关键字class为Muggle对象创建一个新的蓝图。这决定了每个Muggle对象将拥有的数据以及它能做什么。在这里，我们规定每个Muggle对象应有一个年龄、一个名字和一个他们喜欢的人。

对于每个类，你必须使用方法__init__()来初始化类的数据。每个Muggle对象都会有属性age、name和likes。通过将它们作为参数传递给def语句，我们使它们在创建对象时成为必需的参数。任何类方法的第一个值是对对象本身的引用，用self表示。只要你在代码中调用初始化方法，Python 就会创建一个空对象，你可以使用self来访问它。

注意

*尽管在定义方法时，第一个参数是 self，但在调用方法时你实际上不需要指定这个参数。Python 会在内部为你处理它。*

当你从类创建对象时，初始化方法__init__会自动首先被调用，通过将类的名称作为函数调用来实例化一个新对象。调用Muggle(52, "Vernon", None)和Muggle(49, "Petunia", Vernon)会创建两个新的类对象，两个对象都定义了这三个属性，如下所示：

麻瓜

   age = 52

   name = "Vernon"

   likes = None

麻瓜

   age = 49

   name = "Petunia"

   likes = "Vernon"

你可以看到这些对象遵循相同的蓝图，但它们是Muggle的不同实例；它们具有相同的属性，但不同的“DNA”。

从现在开始，这些对象将驻留在计算机的内存中，直到程序终止时，Python 才会将它们销毁。

到目前为止，你能看到这个故事中的悲剧元素吗？Petunia 喜欢 Vernon，但 Vernon 不喜欢任何人。我们来稍微让这个故事变得轻松一些，好吗？我们将把Vernon的likes属性改为Petunia。我们可以通过对象的名称、点表示法，然后是属性名称来访问对象的不同属性，像这样：

Vernon.likes = "Petunia"

print(Vernon.likes)

这将输出：

Petunia

让我们定义一个 Wizard 类，以便我们能在这个小世界中创建一些巫师。这一次，我们将添加一些功能：

class Wizard:

   def __init__(self, age, name):

      self.age = age

      self.name = name

      self.mana = 100

   def love_me(self, victim):

      if self.mana >= 100:

         victim.likes = self.name

         self.mana = self.mana – 100

Wiz = Wizard(42, "Tom")

每个 Wizard 对象有三个属性：age、name 和 mana 等级（即巫师剩余的魔法力量）。age 和 name 属性是在创建 Wizard 对象时，根据传入的参数值来设置的。而 mana 属性则在 __init__ 方法中被硬编码为 100。例如，调用 Wizard(42, "Tom") 会将 self.age 设置为 42，self.name 设置为 "Tom"，并且 self.mana 设置为 100。

我们还添加了一个方法<sup class="SANS_TheSansMonoCd_W5Regular_11">love_me()</sup>，它对受害者施下爱情魔咒。如果巫师剩余的法力足够，他们可以通过将受害者的<sup class="SANS_TheSansMonoCd_W5Regular_11">likes</sup>属性设置为施法者的名字来迫使受害者爱上他们。然而，只有当巫师的法力大于或等于 100 时（<sup class="SANS_TheSansMonoCd_W5Regular_11">self.mana</sup> <sup class="SANS_TheSansMonoCd_W5Regular_11">>=</sup> <sup class="SANS_TheSansMonoCd_W5Regular_11">100</sup>），这才有效。成功后，受害者的<sup class="SANS_TheSansMonoCd_W5Regular_11">likes</sup>属性指向施法巫师的名字，而施法巫师的法力值减少 100。

我们创建了一个 42 岁的巫师，名叫 Tom。Tom 很孤独，想要被喜欢。让我们让 Petunia 和 Vernon 爱上他。我们使用点表示法来访问对象的方法，并传入<sup class="SANS_TheSansMonoCd_W5Regular_11">Petunia</sup>和<sup class="SANS_TheSansMonoCd_W5Regular_11">Vernon</sup>对象：

Wiz.love_me(Petunia)

Wiz.love_me(Vernon)

print(Petunia.likes=="Tom" and Vernon.likes=="Tom")

你能告诉我 Tom 是否成功让 Petunia 和 Vernon 都爱上他吗？

面向对象编程中最常见的混淆来源之一是忘记在定义方法时包含<sup class="SANS_TheSansMonoCd_W5Regular_11">self</sup>参数。另一个问题是初始化方法的定义使用了语法<sup class="SANS_TheSansMonoCd_W5Regular_11">__init__()</sup>，而你调用类创建方法时使用语法<sup class="SANS_TheSansMonoCd_W5Regular_11">ClassName()</sup>，而不是你可能预期的<sup class="SANS_TheSansMonoCd_W5Regular_11">ClassName.__init__()</sup>。这在代码中有所体现，我们并没有调用<sup class="SANS_TheSansMonoCd_W5Regular_11">Wizard.__init__(20, 'Ron')</sup>，而是简单地调用<sup class="SANS_TheSansMonoCd_W5Regular_11">Wizard(20, 'Ron')</sup>来创建一个新的<sup class="SANS_TheSansMonoCd_W5Regular_11">Wizard</sup>对象。

这只是对 Python 中面向对象编程的简要概述，但值得确保你完全理解如何在 Python 中构建类和对象。

如需进一步信息，可以查看有关面向对象编程的备忘单：[*https://<wbr>blog<wbr>.finxter<wbr>.com<wbr>/object<wbr>-oriented<wbr>-programming<wbr>-terminology<wbr>-cheat<wbr>-sheet*](https://blog.finxter.com/object-oriented-programming-terminology-cheat-sheet)。

术语

在这里，我们将快速浏览面向对象的 Python 中的一些关键定义。

**类** 创建对象的蓝图。类定义了对象的属性（数据）和功能（方法）。你可以通过点表示法访问属性和方法。

**对象** 一个根据类定义构建的、包含封装数据和相关功能的单元。对象也被称为类的*实例*。通常，一个对象被用来模拟现实世界中的事物。例如，我们可以根据类定义 Person 创建对象 Obama**。** 一个对象由任意数量的属性和方法组成，这些属性和方法被封装在一个单独的单元中。

**实例化** 创建一个类的对象的过程。

**方法** 与特定对象关联的函数。我们使用关键字 def 在类定义中定义方法。一个对象可以有任意多个方法。

**属性** 用于存储与类或实例相关联的数据的变量。

**类属性** 在类定义中静态创建的变量，并且由该类创建的所有对象共享。它们也被称为*类变量*、**静态变量**和*静态属性*。

**动态属性** 在程序执行期间动态定义的对象属性，并且在任何方法内没有定义。例如，你可以通过调用 o.my_attribute = 42，简单地将一个新属性 my_attribute 添加到任何对象 o 上**。

**实例属性** 存储属于单个对象的数据的变量。其他对象不能像类属性那样共享此变量。通常，在使用 self 变量名创建实例时，你会创建一个实例属性 x，例如 self.x = 42。这些也被称为*实例变量*。

**继承**      一种编程概念，允许你通过重用一些或所有数据和功能来创建新类作为现有类的修改版本。也就是说，类 A 可以继承类B的属性或方法，使其拥有与类B相同的数据和功能，但类A可以改变行为或添加数据和方法。例如，类Dog可以继承类 Animal 的属性number_of_legs。在这种情况下，你可以按如下方式定义继承类Dog：class Dog(Animal):，然后是类体。

如果你理解了这些术语，你就能跟随大多数关于面向对象编程的讨论。掌握面向对象是精通 Python 的重要一步。

### 装饰器函数和注解

Dash 在很大程度上依赖于 Python 中的*装饰器*或*装饰器函数*的概念，装饰器函数可以在不修改代码本身的情况下为现有代码添加功能。如果你想修改或定制现有函数的输出，而不需要改变函数的实际代码，这非常有用。例如，你可能没有访问函数定义的权限，但仍然希望改变该函数的行为。装饰器函数来帮忙了！

把装饰器函数想象成一个包装器。它接受一个原始函数，调用它，然后根据程序员的需求修改其行为。这样，你可以在函数最初定义后动态地改变函数的行为。

让我们从一个简单的例子开始。定义一个打印文本到标准输出的函数：

def print_text():

   print("Hello world!")

print_text()

输出为：

Hello world!

该函数将始终打印相同的消息。假设你想装饰这个输出，使其更有趣。一种方法是定义一个新的pretty_print()函数；这还不是装饰器函数，因为它没有改变另一个函数的行为。然而，它确实展示了如何包装另一个函数并修改其行为：

def print_text():

   print("Hello world!")

def pretty_print():

   annotate = '+'

   print(annotate * 30)

   print_text()

   print(annotate * 30)

pretty_print()

现在输出看起来是这样的：

++++++++++++++++++++++++++++++

Hello world!

++++++++++++++++++++++++++++++

外部函数pretty_print()调用内部函数print_text()，并在内部函数输出的前后添加 30 个加号（+）符号，从而装饰了结果。本质上，你是*包装*了内部函数的结果，并用额外的功能来丰富它。

装饰器函数允许你像这样将代码进行通用化。例如，你可能希望将一个任意的内部函数传入到你的pretty_print()函数中，这样你就可以将它应用于任何 Python 函数。这里我们创建了一个装饰器函数，但请注意，为了展示它是如何工作的，我们使用了较长的方式来创建这个函数。稍后我们将看看 Python 提供的更简短的方式来实现相同的功能。以下是较长的版本：

def pretty_print_decorator(f):

   annotate = '+'

   def pretty_print():

      print(annotate * 50)

      f()

      print(annotate * 50)

   return pretty_print

def print_text():

   print("Hello world!")

def print_text_2():

   print("Hello universe!")

当我们像这样使用它时：

pretty_print_decorator(print_text)()

pretty_print_decorator(print_text_2)()

我们将得到如下的输出：

++++++++++++++++++++++++++++++++++++++++++++++++++

Hello world!

++++++++++++++++++++++++++++++++++++++++++++++++++

++++++++++++++++++++++++++++++++++++++++++++++++++

Hello universe!

++++++++++++++++++++++++++++++++++++++++++++++++++

在这里，装饰器函数接收一个函数作为输入，并返回另一个函数，通过将输出包裹在+符号中来修改行为。你可以传递任何打印任何输出的函数，并创建一个类似的函数，额外将输出包裹在一系列的+符号中。

这个简单的装饰器函数接收一个函数对象并应用一些输出修改，但装饰器函数可以做各种复杂的事情，比如分析输出、应用一些额外的逻辑或过滤掉一些不需要的消息。

这是构建装饰器函数的一种不切实际的复杂方式。因为这种模式太常见，Python 提供了一种方便的方法，可以用更少的代码实现相同的功能：你只需要在要装饰的函数前添加一行代码。这一行由@符号(@)开头，后面跟着你之前定义的装饰器函数的名称。在这里，我们定义了<sup class="SANS_TheSansMonoCd_W5Regular_11">pretty_print_decorator(f)</sup>函数，然后在定义两个打印函数时应用它：

def pretty_print_decorator(f):

   annotate = '+'

   def pretty_print():

      print(annotate * 50)

      f()

      print(annotate * 50)

   return pretty_print

@pretty_print_decorator

def print_text():

   print("Hello world!")

@pretty_print_decorator

def print_text_2():

   print("Hello universe!")

我们以这种方式调用我们定义的两个函数：

print_text()

print_text_2()

我们应该得到像这样的输出：

++++++++++++++++++++++++++++++++++++++++++++++++++

Hello world!

++++++++++++++++++++++++++++++++++++++++++++++++++

++++++++++++++++++++++++++++++++++++++++++++++++++

你好，宇宙！

++++++++++++++++++++++++++++++++++++++++++++++++++

您可以看到输出与之前完全相同。但这一次，我们不是显式地调用装饰器函数 pretty_print_factory，例如在 pretty_print_decorator(print_text) 中装饰现有函数 print_text，而是直接使用带有 @ 前缀的装饰器函数修改 print_text() 的行为。然后，每次调用装饰后的函数时，它都会自动通过装饰器函数。通过这种方式，我们可以堆叠任意复杂的函数层次结构，每一层都通过装饰另一个函数的输出添加新的复杂性。

装饰器函数是 Dash 框架的核心。Dash 提供了高级功能，您可以通过将 Dash 已定义的装饰器函数应用于任何函数（使用注解 @）来访问这些功能。Dash 将这些装饰器函数称为*回调装饰器*。在本书讨论的仪表板应用程序中，您会看到很多这样的例子。

### 摘要

这是一些与使用 Dash 创建应用程序最相关的 Python 概念的快速概述。如果您觉得这些内容难以理解，我们建议在开始构建应用程序之前查阅“Python 基础”附录。

但在我们开始创建仪表板应用程序之前，让我们先深入了解我们推荐您使用的 PyCharm 框架。如果您已经是 PyCharm 专家或者您有其他喜欢的编程环境，请随意跳转到第三章。

<hgroup>

## <samp class="SANS_Futura_Std_Bold_Condensed_B_11">3</samp> <samp class="SANS_Dogma_OT_Bold_B_11">复合数据类型</samp>

</hgroup>

![](img/opener.png)

在上一章中，我们讨论了 JavaScript 的原始数据类型，它们代表单一的数据项，比如数字或字符串。现在我们将了解 JavaScript 的*复合数据类型*，即数组和对象，它们将多个数据项组合成一个单元。复合数据类型是编程中不可或缺的一部分，因为它们使我们能够组织和处理任意大小的数据集合。你将学习如何创建和操作数组与对象，并如何将它们组合成更复杂的数据结构。

### <samp class="SANS_Futura_Std_Bold_B_11">数组</samp>

JavaScript 的*数组*是一种复合数据类型，用于存储有序的值列表。数组的元素可以是任何数据类型，它们不必全是相同的类型，尽管它们通常是。例如，一个数组可以作为待办事项清单，存储一系列描述需要完成的任务的字符串，或者它也可以存储一个数字集合，表示从特定位置定期测量的温度读数。

数组非常适合这些结构，因为它们将相关的值集合在一起，并且随着值的增加或删除，它们具有增长和缩小的灵活性。如果你有固定数量的待办事项——比如四个——你可能会使用单独的变量来存储它们，但使用数组可以让你存储一个无限、可变化的项目数，并保持它们的固定顺序。此外，一旦将元素聚集在一个数组中，你就可以编写代码，高效地依次操作数组中的每个项目，正如你将在第四章中看到的那样。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">创建与索引</samp>

要创建一个数组，将其元素用逗号分隔，并放在一对方括号内：

```
**let primes = [2, 3, 5, 7, 11, 13, 17, 19];**
**primes;**
`(8) [2, 3, 5, 7, 11, 13, 17, 19]` 
```

这个数组包含了前八个素数，并存储在 primes 变量中。当你输入 primes;时，Chrome 控制台应该会打印出数组的长度（8），后面跟着它的元素。

数组中的每个元素都有一个与之关联的索引号。像字符串一样，数组是零索引的，因此第一个元素位于索引 0，第二个元素位于索引 1，依此类推。要访问数组中的单个元素，可以在数组名称后加上其索引号并用方括号括起来。例如，这里我们访问了 primes 数组的第一个元素：

```
**primes[0];**
2 
```

因为数组是零索引的，所以数组最后一个元素的索引比数组的长度少 1。因此，我们八个元素的 primes 数组的最后一个元素位于索引 7：

```
**primes[7];**
19 
```

如果你不知道数组的长度，并且想要获取它的最后一个元素，可以先使用点符号访问其 length 属性，并查看数组的长度，就像我们在第二章中操作字符串一样：

```
**primes.length;**
8
**primes[7];**
19 
```

或者，为了在一个语句中做到这一点，你可以简单地从长度中减去 1 来获取最后一个索引处的元素，像这样：

```
**primes[primes.length - 1];**
19 
```

如果你使用了超出数组范围的索引，JavaScript 将返回 undefined：

```
**primes[10];**
undefined 
```

要替换数组中的一个元素，可以使用索引语法为元素赋予一个新值：

```
**primes[2] = 1;**
**primes;**
`(8) [2, 3, 1, 7, 11, 13, 17, 19]` 
```

这里我们在质数数组的第三个位置（索引 2）添加了一个 1，替换了之前在该索引位置的值。控制台输出确认 1 是数组的新第三个元素。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">数组的数组</samp>

数组可以包含其他数组。这些*多维数组*通常用于表示二维点阵或表格。为了说明这一点，让我们制作一个简单的井字游戏。我们将创建一个数组（我们将其称为*外部*数组），其中包含三个元素，每个元素都是另一个数组（我们将这些称为*内部*数组），代表井字棋盘的每一行。每个内部数组将包含三个空字符串，表示该行中的方格：

```
**let ticTacToe = [**
 **["", "", ""],**
 **["", "", ""],**
 **["", "", ""]**
**];** 
```

为了使代码更易读，我将每个内部数组放在了新的一行。通常，当你按下 ENTER（通常是为了开始新的一行）时，JavaScript 控制台会运行你刚刚输入的代码行，但在这种情况下，它足够聪明，能够意识到第一行没有完成，因为没有关闭的方括号来匹配开括号。它会将直到最后一个闭括号和分号的所有内容解释为一个单一语句，即使你包含了额外的括号和回车符。

> <samp class="SANS_Dogma_OT_Bold_B_21">注意</samp>

*Chrome 控制台自动为内部数组应用缩进，以表明它们嵌套在外部数组中。Chrome 和 VS Code 默认为每一层缩进使用四个空格，但这只是个人偏好的问题。在本书中，我将使用两个空格进行缩进，因为这在现代 JavaScript 代码中更为常见，也因为它能帮助一些较长的代码更好地适应页面。*

我本可以将这个数组写在一行中，如此显示，但这样更难看出它的二维结构：

```
**let ticTacToeOneLine = [["", "", ""], ["", "", ""], ["", "", ""]];**
```

现在让我们看看当我们请求控制台输出 ticTacToe 变量的值时会发生什么：

```
**ticTacToe;**
`(3) [Array(3), Array(3), Array(3)]` 
```

在这种情况下，外部数组的长度显示为（3），表示它是一个包含三个元素的数组。数组的每个元素是 Array(3)，这意味着每个内部数组是另一个包含三个元素的数组。

为了展开视图并查看内部数组中的内容，点击左侧的箭头：

```
`(3) [Array(3), Array(3), Array(3)]`
  0: (3) ['', '', '']
  1: (3) ['', '', '']
  2: (3) ['', '', '']
   length: 3
  [[Prototype]]: Array(0) 
```

前三行显示了索引为 0、1 和 2 的内部数组的值。在这些之后，显示了外部数组的长度属性，值为 3。最后的属性[[Prototype]]，是数组内置方法的来源（更多内容请参见第六章）。

我们已经创建了井字棋棋盘，但它是空的。让我们在右上角设置一个 X。第一个内部数组代表的是上排，我们可以通过 ticTacToe[0]来访问它。右上角是这一行的第三个元素，或者说是内部数组的索引 2。由于 ticTacToe[0]返回的是一个数组，我们只需在后面加上[2]来访问我们想要的元素：ticTacToe[0][2]。知道这一点后，我们可以按如下方式将这个元素设置为"X"：

```
**ticTacToe[0][2] = "X";**
```

现在，让我们再次查看 ticTacToe 的值，点击箭头展开外部数组：

```
**ticTacToe;**
(3) [Array(3), Array(3), Array(3)]
  0: (3) ['', '', 'X']
  1: (3) ['', '', '']
  2: (3) ['', '', '']
   length: 3
  [[Prototype]]: Array(0) 
```

井字棋的右上角现在包含一个 X。

接下来，让我们在左下角设置一个 O。底行是外部数组的索引 2，这一行最左边的方格是内部数组的索引 0，所以我们输入如下内容：

```
**ticTacToe[2][0] = "O";**
**ticTacToe;**
(3) [Array(3), Array(3), Array(3)]
  0: (3) ['', '', 'X']
  1: (3) ['', '', '']
  2: (3) ['O', '', '']
   length: 3
  [[Prototype]]: Array(0) 
```

现在，板子的左下角有一个 O。

总结一下，如果你想访问嵌套数组中的元素，可以使用一组方括号来选择外部数组中的元素（这会返回其中一个内部数组），然后再用第二组方括号选择内部数组中的元素。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">数组方法</samp>

JavaScript 有几个用于处理数组的有用方法。在本节中，我们将看一些重要的方法。这些方法中的一些会修改目标数组，这被称为*变异*。变异的示例包括添加或删除数组元素，或改变元素的顺序。其他方法则创建并返回一个新的数组，同时保持原始数组不变，这在你还需要原始数组用于其他目的时非常有用。

需要注意的是，你使用的方法是否会改变数组。例如，假设你有一个包含按顺序列出月份的数组，但你程序的某一部分需要按字母顺序排列这些月份。你需要确保将月份按字母顺序排列时，不会无意中改变原始的按顺序排列的数组，否则程序的其他部分可能会误认为四月是第一个月。另一方面，如果你有一个表示待办事项的数组，当添加或删除任务时，你可能希望更新原始数组，而不是创建一个新的数组。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">向数组添加元素</samp>

push 方法通过将提供的元素添加到数组的末尾来改变数组。push 方法的返回值是数组的新长度。举个例子，让我们用 push 来构建一个编程语言的数组：

```
**let languages = [];**
**languages.push("Python");**
1
**languages.push("Haskell");**
2
**languages.push("JavaScript");**
3
**languages.push("Rust");**
4
**languages;**
`(4) ['Python', 'Haskell', 'JavaScript', 'Rust']` 
```

首先，我们创建一个名为 languages 的新数组，并用[]（一个空数组）初始化它。第一次调用 push 方法时，我们传入值"Python"。该方法返回 1，表示数组中现在有一个元素。我们再做三次相同的操作，最后通过输入 languages;来查看 languages 的值。这将返回我们按顺序添加到数组中的四个编程语言。

若要将元素添加到数组的开头而不是末尾，请使用 `unshift` 方法，如下所示：

```
**languages.unshift("Erlang");**
5
**languages.unshift("C");**
6
**languages.unshift("Fortran");**
7
**languages;**
`(7) ['Fortran', 'C', 'Erlang', 'Python', 'Haskell', 'JavaScript', 'Rust']` 
```

这里我们向 languages 数组的开头添加了三个语言。因为每个元素都被添加到数组的开头，它们最终的顺序与添加时的顺序相反。像 `push` 一样，调用 `unshift` 会返回数组的新长度。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">从数组中移除元素</samp>

要通过移除数组的最后一个元素来改变数组，请使用 `pop` 方法。这里我们在 languages 数组上调用 `pop` 方法，删除它的最后一个元素：

```
**languages.pop();**
'Rust'
**languages;**
`(6) ['Fortran', 'C', 'Erlang', 'Python', 'Haskell', 'JavaScript']` 
```

该方法返回被移除元素的值，在此例中为“Rust”。当我们检查数组时，它只包含六个元素。

因为 `pop` 方法返回被移除的数组元素，所以如果你在移除元素时想要对其进行操作，它特别有用。例如，这里我们从 languages 数组中删除另一个元素，并在消息中使用它：

```
**let bestLanguage = languages.pop();**
**let message = `My favorite language is ${bestLanguage}.`;**
**message;**
'My favorite language is JavaScript.'
**languages;**
`(5) ['Fortran', 'C', 'Erlang', 'Python', 'Haskell']` 
```

这次我们调用 `languages.pop()` 时，将方法的返回值存储在 bestLanguage 变量中，并使用模板字面量将其嵌入到字符串中。当我们打印结果消息时，它包含了 *JavaScript* 这个单词。这个元素是从数组中移除的，现在数组只剩下五个语言。

若要移除数组中的*第一个*元素，而不是最后一个元素，请使用 `shift` 方法。像 `pop` 一样，`shift` 方法返回被移除的元素：

```
**let worstLanguage = languages.shift();**
**message = `My least favorite language is ${worstLanguage}.`;**
**message;**
'My least favorite language is Fortran.'
**languages;**
`(4) ['C', 'Erlang', 'Python', 'Haskell']` 
```

与之前的例子一样，我们将调用 `shift` 的结果保存到一个变量中，这次叫做 worstLanguage，并将其用于模板字面量中。该变量包含字符串“Fortran”，而 languages 数组剩下四个元素。

到目前为止我们查看过的四种方法，`pop`、`unshift`、`push` 和 `shift`，通常用于实现更专业的数据结构，如队列。*队列*是一种数据结构，类似于排队的人群，新项被添加到队列的末尾，而项则从队列的开头被移除和处理。这在你需要按照到达顺序处理数据时非常有用。例如，想象一个问答应用，很多用户可以提问。你可以使用一个数组来存储问题列表，`push` 方法将每个新问题添加到数组的末尾。当回答者准备好回答问题时，他们可以使用 `shift` 方法获取数组中的第一个元素并将其移除。这样可以确保数组中只有未回答的问题，并且它们会按照收到的顺序进行回答。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">合并数组</samp>

`concat` 方法（*连接*的缩写）将两个数组合并在一起。例如，这里我们从两个数组 `fish` 和 `mammals` 开始，并将它们合并成一个新数组，然后将其保存到 `animals` 变量中：

```
**let fish = ["Salmon", "Cod", "Trout"];**
**let mammals = ["Sheep", "Cat", "Tiger"];**
**let animals = fish.concat(mammals);**
**animals;**
`(6) ['Salmon', 'Cod', 'Trout', 'Sheep', 'Cat', 'Tiger']` 
```

当你在一个数组上调用 concat 时，会创建一个新数组，其中包含第一个数组（你调用 concat 的数组）中的所有元素，接着是第二个数组（作为参数传递给 concat 的数组）中的所有元素。原始数组保持不变，因为与我们迄今为止看到的其他方法不同，concat 并不是一个改变原数组的方法。这在这里非常有用，因为我们不希望我们的鱼类数组突然包含哺乳动物的元素！

要将三个或更多数组合并，传递多个数组作为 concat 的参数，如这个例子所示：

```
**let originals = ["Hope", "Empire", "Jedi"];**
**let prequels = ["Phantom", "Clones", "Sith"];**
**let sequels = ["Awakens", "Last", "Rise"];**
**let starWars = prequels.concat(originals, sequels);**
**starWars;**
`(9) ['Phantom', 'Clones', 'Sith', 'Hope', 'Empire', 'Jedi', 'Awakens', 'Last', 'Rise']` 
```

在这里，我们创建了三个单独的数组：originals、prequels 和 sequels，代表三套*星球大战*电影。然后，我们使用 concat 将它们合并成一个包含九个元素的 starWars 数组。注意，合并后的数组中的元素按传递数组作为参数的顺序出现。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">查找数组中元素的索引</samp>

要找出数组中某个特定元素的位置，可以使用 indexOf 方法。该方法返回指定元素第一次出现的索引。如果元素在数组中没有找到，indexOf 返回 -1：

```
**let sizes = ["Small", "Medium", "Large"];**
**sizes.indexOf("Medium");**
1
**sizes.indexOf("Huge");**
-1 
```

在这个例子中，我们要检查 "Medium" 在 sizes 数组中的位置，并且得到了答案 1。然后，因为 "Huge" 不在数组中，我们得到了答案 -1。

如果数组包含多个指定值的实例，indexOf 只会返回第一个匹配元素的索引。例如，这里有一个包含阿根廷国旗颜色的数组：

```
**let flagOfArgentina = ["Blue", "White", "Blue"];**
**flagOfArgentina.indexOf("Blue");**
0 
```

即使 "Blue" 在数组中出现了两次，indexOf 只会返回第一次出现的索引。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">将数组转换为字符串</samp>

join 方法将一个数组转换成一个单一的字符串，将所有元素连接在一起，如下所示：

```
**let beatles = ["John", "Paul", "George", "Ringo"];**
**beatles.join();**
'John,Paul,George,Ringo' 
```

注意，beatles 数组中的独立字符串如何合并成一个字符串。默认情况下，join 会在每个元素之间放置一个逗号来形成返回的字符串。要更改这一点，你可以将你自己的分隔符作为参数传递给 join。例如，如果你希望元素之间没有任何内容，可以传递一个空字符串作为参数：

```
**beatles.join("");**
'JohnPaulGeorgeRingo' 
```

你可以传递任何有效的字符串作为分隔符。在下一个例子中，我们传递一个空格、一个与号和一个换行符转义字符，将每个元素放在自己的行上。正如你在第二章中学到的那样，我们必须使用 console.log 才能在 Chrome 中正确显示换行符：

```
**console.log(beatles.join("&\n"));**
John&
Paul&
George&
Ringo 
```

请记住，分隔符只出现在数组元素*之间*，而不是每个元素后面。这就是为什么在 Ringo 后面没有额外的与号和换行符。

如果你对包含非字符串值的数组使用 join，这些值会被转换为字符串，正如这个例子所示：

```
**[100, true, false, "hi"].join(" - ");**
'100 - true - false - hi' 
```

与之前的连接方法一样，结果是一个由分隔符（在本例中为 " - "）连接起来的长字符串。不同之处在于，非字符串值（例如数字 100 和布尔值 true 和 false）在连接之前必须自动转换为字符串。这个例子还展示了如何可以直接在数组字面量上调用数组方法，而无需先将数组保存到变量中。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">其他有用的数组方法</samp>

以下是一些你可能想尝试的其他有用的数组方法：

arr.includes(elem)    根据给定的 elem 是否在 arr 数组中，返回 true 或 false。

arr.reverse()    反转数组中元素的顺序。这是一个变异方法，因此会修改原始数组。

arr.sort()    对数组元素进行排序，修改原数组。如果元素是字符串，它们会按字母顺序排序。否则，排序会像将元素转换为字符串后进行排序一样。

arr.slice(start, end)    通过从原数组中提取从索引 start 开始到索引 end 之前的元素来创建一个新数组。此方法等同于上一章介绍的字符串的 slice 方法。如果调用 slice() 时不带任何参数，则会将整个数组复制到一个新数组中。如果你需要使用像 sort 这样的变异方法，但又不想修改原数组，这个方法会很有用。

arr.splice(index, count)    从数组中删除从索引 index 开始的 count 个元素。

### <samp class="SANS_Futura_Std_Bold_B_11">对象</samp>

*对象*是 JavaScript 中的另一种复合数据类型。它们与数组类似，都是用来存储一组值，但不同之处在于，对象使用称为 *键* 的字符串来访问值，而不是数字索引。每个键都与一个特定的值关联，形成一个 *键值对*。

数组通常用于存储相同数据类型的有序元素列表，而对象通常用于存储关于单一实体的多个信息。这些信息通常并非全部是相同的数据类型。例如，表示一个人的对象可能包含该人的姓名（字符串）、年龄（数字）、是否已婚（布尔值）等信息。对象比数组更适合用于这种情况，因为每个信息片段都有一个有意义的名称——它的键——而不是一个通用的索引号。如果这些值 35 和 true 存储在表示人的数组中，且其索引分别为 1 和 2，那么它们的含义就不如存储在表示人的对象中，分别作为 "age" 和 "married" 键的值那样清晰。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">创建对象</samp>

创建对象的一种方式是使用*对象字面量*，它由一对大括号（{ 和 }）组成，括起来的是一系列键值对，键值对之间用逗号分隔。每个键值对必须在键和值之间有一个冒号。例如，下面是一个名为 casablanca 的对象字面量，包含一些关于那部电影的信息：

```
**let casablanca = {**
 **"title": "Casablanca",**
 **"released": 1942,**
 **"director": "Michael Curtiz"**
**};**
**casablanca;**
`{title: 'Casablanca', released: 1942, director: 'Michael Curtiz'}` 
```

这里我们创建了一个包含三个键的对象："title"、"released" 和 "director"。每个键都关联有一个值。我将每个键值对写在单独的行上，以便更容易阅读对象字面量，但这并不是严格必要的。正如你在后面的示例中会看到的，键值对也可以写在同一行。

所有对象的键都是字符串，但如果你的键是有效的标识符，通常做法是省略引号。*有效标识符*是指任何可以作为 JavaScript 变量名使用的一系列字符。标识符可以由字母、数字和字符 _ 和 $ 组成，但不能以数字开头。它也不能包含其他符号，如 *、( 或 #，也不能包含空白字符，如空格和换行符。这些字符 *在*对象键中是允许的，但前提是键必须用引号括起来。例如：

```
**let obj = { key1: 1, key_2: 2, "key 3": 3, "key#4": 4 };**
**obj;**
`{key1: 1, key_2: 2, key 3: 3, key#4: 4}` 
```

这里 key1 和 key_2 是有效的标识符，因此不需要加引号。然而，key 3 包含空格，key#4 包含井号，因此它们是无效的标识符。它们必须用引号括起来，才能作为对象的键使用。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">访问对象值</samp>

要获取与某个键关联的值，可以使用方括号括起来的字符串键来调用对象名：

```
**obj["key 3"];**
3
**casablanca["title"];**
'Casablanca' 
```

这就像访问数组元素的语法一样，只不过不使用数字索引，而是使用字符串键。

对于有效的标识符，可以使用点表示法代替方括号，键名跟在点后面：

```
**obj.key_2;**
2 
```

这对于无效标识符的键不起作用。例如，你不能写 obj.key 3，因为在 JavaScript 中，这看起来像是 obj.key 后面跟着一个空格和数字字面量 3。

注意，这种点表示法看起来就像我们用于访问字符串的 length 属性（在第二章中）和数组（在本章前面）的语法。那是因为它们是一样的！属性实际上就是键值对的另一种说法。在后台，JavaScript 将字符串视为对象，数组也是一种特殊的对象。当我们写出类似 [1, 2, 3].length 这样的代码时，我们说我们正在访问数组的 length 属性，但我们也可以说我们正在获取与数组 length 键关联的值。同样，当我们写出类似 casablanca.title 的代码时，我们通常说我们正在访问对象的 title 属性，而不是与 title 键关联的值。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">设置对象值</samp>

要向对象中添加一个新的键值对，使用与查找值时相同的括号或点表示法。例如，这里我们设置了一个空字典对象，然后添加了两个定义：

```
**let dictionary = {};**
**dictionary.mouse = "A small rodent";**
**dictionary["computer mouse"] = "A pointing device for computers";**
**dictionary;**
`{mouse: 'A small rodent', computer mouse: 'A pointing device for computers'}` 
```

我们首先使用一对空大括号创建一个新的空对象。然后，我们设置两个新的键，“mouse”和“computer mouse”，并为每个键设置一个定义作为值。像之前一样，我们可以使用点表示法来访问有效的标识符 mouse，但对于“computer mouse”，由于它包含空格，我们需要使用括号表示法。

更改与已存在的键相关联的值遵循相同的语法：

```
**dictionary.mouse =** **"A furry rodent";**
**dictionary;**
`{mouse: 'A furry rodent', computer mouse: 'A pointing device for computers'}` 
```

输出确认鼠标的定义已经更新。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">与对象一起工作</samp>

JavaScript 有很多用于处理对象的方法；我们将在这里讨论其中一些最常见的方法。与数组不同，数组的方法是直接在你想操作的数组上调用的，而对象的方法是作为静态方法调用的，方法格式是 `Object.methodName()`，并在括号内传入你想操作的对象作为参数。这里，Object 是一个*构造函数*，是一种用于创建对象的函数类型，而*静态方法*是直接在构造函数上定义的方法，而不是在某个特定对象上定义的方法。我们将在第六章中更详细地讨论构造函数。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">获取对象的键</samp>

要获取对象的所有键的数组，使用静态方法 `Object.keys`。例如，这里是如何获取我猫的名字：

```
**let cats = { "Kiki": "black and white", "Mei": "tabby", "Moona": "gray" };**
**Object.keys(cats);**
`(3) ['Kiki', 'Mei', 'Moona']` 
```

cats 对象有三个键值对，其中每个键代表一只猫的名字，每个值代表该猫的颜色。`Object.keys` 返回的只是键，作为一个字符串数组。

`Object.keys` 在像这种情况下很有用，当你只需要从对象中获取其键的名称时。例如，你可能有一个对象来跟踪你欠朋友多少钱，其中键是朋友的名字，值是欠款金额。使用 `Object.keys`，你可以列出你正在跟踪的朋友的名字，从而大致了解你欠钱的人。

你可能会想，为什么 keys 是一个静态方法——也就是说，为什么我们需要通过 `Object.keys(cats)` 来调用它，而不是用 `cats.keys()`。为了理解这是为什么，考虑这个钢琴对象：

```
**let piano = {**
 **make: "Steinway",**
 **color: "black",**
 **keys: 88**
**};** 
```

该对象有一个名为"keys"的属性，表示钢琴上的按键数量。如果像 keys 这样的函数可以直接在钢琴对象本身上调用，属性名和方法名会发生冲突，这是不被允许的。JavaScript 除了 keys 之外，还有许多内建的对象方法，记住所有这些方法的名称以确保它们不会与对象的属性名冲突是非常繁琐的。为了解决这个问题，语言设计者将这些对象方法设置为静态方法。它们被附加到整体的 Object 构造器上，而不是附加到像猫（cat）或钢琴（piano）这样的单个对象上，因此不会发生命名冲突。

> <samp class="SANS_Dogma_OT_Bold_B_21">注意</samp>

*数组没有这个问题。方法名必须是有效的标识符，这意味着它们不能以数字开头。因此，数组方法不可能与数组的数字索引发生冲突。*

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">获取对象的键和值</samp>

要获取对象的键*和*值，可以使用 Object.entries。这个静态方法返回一个包含二元素数组的数组，每个内层数组的第一个元素是键，第二个元素是值。下面是它的工作原理：

```
**let chromosomes = {**
 **koala: 16,**
 **snail: 24,**
 **giraffe: 30,**
 **cat: 38**
**};**
**Object.entries(chromosomes);**
`(4) [Array(2), Array(2), Array(2), Array(2)]` 
```

我们创建了一个包含四个键值对的对象，展示了各种动物的染色体数量。Object.entries(chromosomes)返回一个包含四个元素的数组，每个元素都是一个包含两个元素的数组。点击箭头以展开外部数组并查看完整内容：

```
`(4) [Array(2), Array(2), Array(2), Array(2)]`
  0: (2) ['koala', 16]
  1: (2) ['snail', 24]
  2: (2) ['giraffe', 30]
  3: (2) ['cat', 38]
   length: 4
  [[Prototype]]: Array(0) 
```

这表示每个内层数组包含原始对象的一个键作为第一个元素，关联的值作为第二个元素。

使用 Object.entries 将一个对象转换成数组，可以更方便地遍历对象的所有键值对，并对每个键值对依次进行处理。我们将在第四章中看到如何使用循环来实现这一点。

<samp class="SANS_Futura_Std_Bold_Condensed_B_11">合并对象</samp>

Object.assign 方法允许你将多个对象合并成一个。例如，假设你有两个对象，一个给出一本书的物理属性，另一个描述书的内容：

```
**let physical = { pages: 208, binding: "Hardcover" };**
**let contents = { genre: "Fiction", subgenre: "Mystery" };** 
```

使用 Object.assign，你可以将这些独立的对象合并成一个整体的书籍对象：

```
**let book = {};**
**Object.assign(book, physical, contents);**
**book;**
`{pages: 208, binding: 'Hardcover', genre: 'Fiction', subgenre: 'Mystery'}` 
```

Object.assign 的第一个参数是*目标*，即将从其他对象中复制的键赋值给的对象。在这个例子中，我们使用一个名为 book 的空对象作为目标。其余的参数是*源对象*，即其键值对将被复制到目标对象中的对象。你可以在初始目标参数之后传入任意多个源对象——我们这里只传入了两个。该方法会修改并返回目标对象，复制来自源对象的键值对。源对象本身不会受到影响。

你不一定需要创建一个新的空对象作为 Object.assign 的目标，但是如果不这么做，你将会修改其中一个源对象。例如，我们可以去掉之前调用中的第一个参数 book，仍然得到一个具有相同四个键值对的对象：

```
**Object.assign(physical, contents);**
**physical;**
`{pages: 208, binding: 'Hardcover', genre: 'Fiction', subgenre: 'Mystery'}` 
```

这里的问题是，physical 现在是目标对象，因此它会被修改，获得来自 contents 的所有键值对。通常情况下，这不是我们想要的，因为原本的单独对象在应用程序的其他部分通常仍然很重要。基于这个原因，常见做法是将一个空对象作为 Object.assign 的第一个参数。

### <samp class="SANS_Futura_Std_Bold_B_11">嵌套对象和数组</samp>

和数组一样，我们可以将对象嵌套在其他对象中。我们还可以将对象嵌套在数组中，或者将数组嵌套在对象中，从而创建更复杂的数据结构。例如，你可能想创建一个表示“人”的对象，这个对象包含一个 children 属性，属性值是一个数组，数组中的每个元素都是一个表示该人孩子的对象。我们可以通过两种方式来构建这些嵌套结构：一种是创建一个包含嵌套对象或数组字面量的对象或数组字面量，另一种是先创建内部元素，保存到变量中，然后使用这些变量来构建复合结构。我们将在这里探讨这两种技巧。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">使用字面量进行嵌套</samp>

首先，我们来使用字面量构建一个嵌套结构。我们将创建一个表示不同书籍三部曲的对象数组：

```
**let trilogies = [**
❶ **{**
 **title: "His Dark Materials",**
 **author: "Philip Pullman",**
 **books: ["Northern Lights", "The Subtle Knife", "The Amber Spyglass"]**
 **},**
❷ **{**
 **title: "Broken Earth",**
 **author: "N. K. Jemisin",**
 **books: ["The Fifth Season", "The Obelisk Gate", "The Stone Sky"]**
 **}**
**];** 
```

变量 trilogies 包含一个包含两个元素的数组，❶和❷，每个元素都是一个包含特定三部曲信息的对象。注意，每个对象都有相同的键，因为我们希望存储关于每个三部曲的相同信息。其中一个键是 books，它本身包含一个数组，表示该三部曲中的书籍标题。因此，我们得到了一个嵌套在数组中的对象，又嵌套在数组中。

从这些内部数组中访问元素需要结合数组索引和对象点表示法：

```
**trilogies[1].books[0];**
'The Fifth Season' 
```

在这里，trilogies[1]表示我们想要外部数组中的第二个对象，.books 表示我们想要该对象的 books 键的值（即一个数组），而[0]表示我们想要该数组中的第一个元素。将它们结合起来，我们就得到了外部数组中第二个三部曲的第一本书。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">使用变量进行嵌套</samp>

另一种创建嵌套结构的技巧是先创建包含内部元素的对象，将这些对象赋值给变量，然后使用这些变量构建外部结构。例如，假设我们想创建一个模拟我们口袋里零钱变化的数据结构。我们创建四个对象，分别表示便士、五分镍币、十分镍币和四分之一硬币，并将每个对象赋值给各自的变量：

```
**let penny = { name: "Penny", value: 1, weight: 2.5 };**
**let nickel = { name: "Nickel", value: 5, weight: 5 };**
**let dime = { name: "Dime", value: 10, weight: 2.268 };**
**let quarter = { name: "Quarter", value: 25, weight: 5.67 };** 
```

接下来，我们使用这些变量创建一个数组，表示我们口袋中特定组合的硬币。例如：

```
**let change** **= [quarter, quarter, dime, penny, penny, penny];**
```

注意到某些硬币对象在数组中出现多次。这是先将内部对象赋值给变量再创建外部数组的一个优点：对象可以在数组中重复，而不需要每次手动写出对象字面量。

再次访问内部对象的值时，需要结合数组索引和对象点符号：

```
**change[0].value;**
25 
```

这里，change[0]给我们返回 change 数组的第一个元素（一枚硬币对象），而.value 给我们它的 value 键。

从对象变量构建数组的一个有趣结果是，重复的元素共享一个共同的身份。例如，change[3]和 change[4]引用的是同一枚 penny 对象。如果美国政府决定更新一枚 penny 的重量，我们只需要更新该 penny 对象的 weight 属性，这个更新就会反映到 change 数组中所有的 penny 元素上：

```
**penny.weight = 2.49;**
**change[3].weight;**
2.49
**change[4].weight;**
2.49
**change[5].weight;**
2.49 
```

在这里，我们将 penny 的 weight 属性从 2.5 修改为 2.49。然后，我们检查数组中每个 penny 的重量，确认更新已经反映到每一个硬币上。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">在控制台中探索嵌套对象</samp>

Chrome 控制台让我们轻松地探索嵌套对象，就像我们之前在本章中使用嵌套的 ticTacToe 数组那样。为了说明这一点，我们将创建一个深度嵌套的对象并尝试查看其中内容：

```
**let nested = {**
 **name: "Outer",**
 **content: {**
 **name: "Middle",**
 **content: {**
 **name: "Inner",**
 **content: "Whoa…"**
 **}**
 **}**
**};** 
```

我们的嵌套对象包含三层对象，每一层都有 name 和 content 属性。外层和中间层的 content 值是另一个对象。要获取最内层对象的 content 属性值，需要一连串的点符号：

```
**nested.content.content.content;**
'Whoa…' 
```

这相当于请求最外层对象的内容属性的内容属性的内容属性。

现在尝试查看嵌套对象的整体值：

```
**nested;**
`{name: 'Outer', content: {…}}` 
```

控制台只会显示外部对象内容属性的简略版本，内容显示为{…}，表示这里有一个对象，但没有足够的空间来展示它。点击箭头以展开外部对象的视图。现在，下一个嵌套对象（名称：“Middle”）也以简略形式显示。点击箭头再展开此对象，然后再点击一次展开名为：“Inner”的对象。现在你应该能在控制台中看到整个对象的内容：

```
`{name: 'Outer', content: {…}}`
  content:
content:
content: "Whoa…"
name: "Inner"
  [[Prototype]]: Object
name: "Middle"
[[Prototype]]: Object
name: "Outer"
  [[Prototype]]: Object 
```

[[Prototype]]属性指向 Object 构造函数，我们之前已经使用过它来调用像 Object.keys 和 Object.assign 这样的对象方法。我们将在第六章中详细讨论原型。

这样使用控制台查看复杂对象是一个非常有用的调试工具。你经常会处理来自不同 JavaScript 库的对象，或者包含你从服务器获取的数据的对象，而你不一定知道这些数据的“形状”——例如对象包含哪些属性、它们有多少层嵌套等等。通过控制台，你可以交互式地探索对象并查看它们的内容。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">使用 JSON.stringify 打印嵌套对象</samp>

查看嵌套对象的另一种方式是将其转换为 JSON 字符串。*JSON*，即 *JavaScript 对象表示法*，是一种基于 JavaScript 对象和数组字面量的文本数据格式，在 web 及其他领域被广泛使用来存储和交换信息。JSON.stringify 方法将一个 JavaScript 对象转换为 JSON 字符串。我们以嵌套对象作为例子：

```
**JSON.stringify(nested);**
'{"name":"Outer","content":{"name":"Middle","content":{"name":"Inner","content":"Whoa…"}}}' 
```

结果是一个字符串（它被单引号括起来），包含了嵌套对象的 JSON 表示。实质上，它等同于我们用来创建嵌套对象的原始对象字面量。像 JavaScript 一样，JSON 使用大括号括起来对象，使用冒号分隔键和值，使用逗号分隔不同的键值对。这个表示中唯一缺失的是我们用来澄清对象字面量嵌套结构的原始换行符和缩进。为了重新创建这些换行符和缩进，我们可以传递 JSON.stringify 另一个参数，表示每个新的嵌套对象的缩进空格数：

```
**nestedJSON = JSON.stringify(nested, null, 2);**
**console.log(nestedJSON);**
{
  "name": "Outer",
  "content": {
"name": "Middle",
"content": {
  "name": "Inner",
"content": "Whoa…"
}
  }
} 
```

JSON.stringify 的第二个参数让你定义一个替换函数，可以通过替换键值对来修改输出，但在这里我们不需要这样做，所以传递 null。将 2 作为第三个参数传递会修改 JSON.stringify 的行为，在每个属性后、在大括号和方括号后添加换行符，并为每个额外的嵌套级别增加两个额外的缩进空格。如果我们直接在控制台中查看结果，我们会看到许多 \n 转义字符表示所有的换行符。相反，我们将结果存储在一个变量中并传递给 console.log，这样就能给我们一个格式良好的对象嵌套层次视图。

以这种方式调用 JSON.stringify 有助于快速获取对象的可视化表示，而无需在控制台中反复点击箭头来展开每个嵌套级别。该方法同样适用于非嵌套对象，但在这种情况下，控制台中对象的常规视图通常就足够了。

### <samp class="SANS_Futura_Std_Bold_B_11">总结</samp>

本章介绍了 JavaScript 的复合数据类型，它们允许你将多个值组合成一个单一的单位。通过这种方式组织数据，你可以更高效地处理无限量的信息。你了解了数组，它是由数字索引标识的有序值集合，通常所有值的数据类型相同；你还了解了对象，它是由键值对组成的集合，其中每个键是一个字符串，而值通常是不同的数据类型。你已经了解了数组如何用于存储类似值的列表，例如素数列表或编程语言列表。同时，对象对于收集单个实体的多个信息也非常有用，比如一本书或一部电影的相关信息。

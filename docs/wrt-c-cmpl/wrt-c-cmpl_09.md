![](img/pg142.jpg)

<samp class="SANS_Futura_Std_Book_Oblique_I_11">描述</samp>

<hgroup>

## <samp class="SANS_Futura_Std_Bold_Condensed_B_11">8</samp> <samp class="SANS_Dogma_OT_Bold_B_11">循环</samp>

</hgroup>

![](img/opener-img.jpg)

在本章中，你将添加所有与循环相关的内容。这包括 <samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">do</samp> 循环，另外还有 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句，用来跳过循环的某些部分。这些是本书中你将实现的最后几个语句。一旦你完成本章的内容，并且实现了所有额外的加分特性，你的编译器就能处理*每*一种 C 语句。

但你首先有工作要做！你将更新词法分析器和语法分析器，以支持所有五个新语句。然后，你将增加一个新的语义分析步骤，我们称之为*循环标注*。这个新步骤，如本章开头的图表中加粗的部分所示，将注释 AST，将每个 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句与包含它的循环关联起来。最后，你将把每个新语句翻译成一系列 TACKY 指令。你可以使用已经定义的 TACKY 指令来实现所有新语句，因此在 TACKY 生成之后你不会再更改任何阶段。

本章中新引入的语句会带来一些边界情况和错误，我们需要处理这些情况。在我们开始讲解词法分析器之前，我们将简要讨论每个语句。

### <samp class="SANS_Futura_Std_Bold_B_11">循环及如何跳出它们</samp>

让我们首先看看三种循环语句，然后考虑 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句。Listing 8-1 展示了一个 <samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp> 循环的示例。

```
while ( ❶ a > 0)
    a = a / 2;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">Listing 8-1: 一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">while</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环</samp>

首先，我们评估语句的*控制表达式* ❶。如果它是 0（即假），循环结束，我们进入下一个语句。如果它是非零的，我们执行 <samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp> 循环体，然后返回控制表达式，清空并重复执行。

一个 <samp class="SANS_TheSansMonoCd_W5Regular_11">do</samp> 循环，像在 Listing 8-2 中的那个，几乎是完全相同的。

```
do
    a = a + 1;
while (a < 100);
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-2：一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">do</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环</samp>

唯一的区别是我们先执行循环体，*然后*检查控制表达式。这意味着循环体至少会执行一次。像<samp class="SANS_TheSansMonoCd_W5Regular_11">if</samp>语句体一样，循环体是一个单一的语句，可以是包含声明的复合语句。你在循环体内声明的任何变量，在控制表达式中将无法访问。例如，列表 8-3 是无效的。

```
do {
    int a = a + 1;
} while (a < 100);
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-3：一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">do</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环，其中控制表达式使用了一个超出作用域的变量</samp>

当<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>循环出现时，事情开始变得更加复杂。它们有两种不同的形式。在第一种形式中，如列表 8-4 所示，循环头由三个表达式组成。

```
int a;
for ( ❶ a = 0; ❷ a < 5; ❸ a = a + 1)
    b = b * 2;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-4：一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">for</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环，其中初始语句是一个表达式</samp>

初始表达式❶在第一次循环迭代之前评估一次。然后，在每次迭代时，我们：

1.  评估控制表达式❷。如果它为假，循环终止。否则，我们…

1.  执行语句体。

1.  评估最终表达式❸。

你可以省略循环头中的任何或所有表达式。如果省略初始表达式或最终表达式，当该语句通常会被评估时，什么也不会发生。如果省略控制表达式，循环将表现得好像其控制表达式始终为真（即非零）。这意味着它永远不会终止，除非它包含一个可以跳出循环体的<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">goto</samp>或<samp class="SANS_TheSansMonoCd_W5Regular_11">return</samp>语句。

列表 8-5 展示了第二种类型的<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>循环，其中初始语句是一个声明，而不是表达式。

```
for (int a = 0; a < 5; a = a + 1)
    b = b * 2;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-5：一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">for</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环，其中初始语句是一个声明</samp>

<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>循环头引入了一个新的作用域，因此你可以像列表 8-6 那样编写代码。

```
int a = 5;
for (int a = 0; a < 5; a = a + 1)
    b = b + a;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-6：在</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">for</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环前和循环头部声明两个同名变量</samp>

在这个清单中，头部声明的变量<samp class="SANS_TheSansMonoCd_W5Regular_11">a</samp>隐藏了上一行声明的变量<samp class="SANS_TheSansMonoCd_W5Regular_11">a</samp>。由于复合语句总是引入一个新的作用域，包括当它作为循环体出现时，清单 8-7 也是有效的。

```
❶ int a = 5;
for ( ❷ int a = 0; a < 5; a = a + 1) {
  ❸ int a = 1;
    b = b + a;
}
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-7：在</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">for</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环前，循环头部和循环体中声明三个同名变量</samp>

在清单 8-7 中，有三个不同的变量名为<samp class="SANS_TheSansMonoCd_W5Regular_11">a</samp>：一个在循环开始前声明 ❶，一个在循环头部声明 ❷，另一个在循环体内声明 ❸。

尽管在<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>循环头部的表达式是可选的，但循环体是必须的。（这对于<samp class="SANS_TheSansMonoCd_W5Regular_11">do</samp>和<samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp>循环也是如此。）然而，循环体可以是一个空语句，就像在清单 8-8 中一样。

```
while ((a = a + 1) < 10)
    ;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-8：将空语句用作循环体</samp>

这里单独的<samp class="SANS_TheSansMonoCd_W5Regular_11">;</samp>是一个空语句。尽管这个语句什么也不做，但我们需要包含它，以便解析器能够识别循环的结束位置。正如我们在第五章中实现它们时所看到的，空语句并不是一个特定于循环的构造；你可以在任何可以使用其他类型语句的地方使用它们。实际上，它们主要出现在循环体内，因为它们很少在其他地方有用。

现在让我们讨论一下<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp>和<samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp>语句。两者只能出现在循环内部。（实际上，这并不完全正确；<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp>语句也可以出现在<samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp>语句内部，你可以将它作为本章的附加功能来实现。）<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp>语句，像清单 8-9 中的语句一样，跳转到循环结束后的位置。

```
while (1) {
    a = a - 1;
    if (a < 0)
        break;
}
return a;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-9：一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句</samp>

当我们遇到这个 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句时，我们将跳转到 <samp class="SANS_TheSansMonoCd_W5Regular_11">return</samp> 语句，位于 <samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp> 循环之后。

<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句仅终止最内层的循环。例如，参考 列表 8-10 中的代码片段。

```
while (b > 0) {
    do {
        a = a - 1;
        if (a < 0)
            break;
    } while (1);
    b = b * a;
}
return b;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-10：使用</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句跳出两个嵌套循环中的内层循环</samp>

当我们到达这个列表中的 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句时，我们将跳出内层循环，但不会跳出外层循环，因此我们会跳转到 <samp class="SANS_TheSansMonoCd_W5Regular_11">b</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">=</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">b * a;</samp>。在本章中，我将把包含 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句的最内层循环称为它的 *封闭循环*。（如果称之为“最小封闭循环”会更符合 C 标准中的术语，但这有点冗长。）

<samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句跳转到封闭循环体内最后一条语句之后的位置。参考 列表 8-11 中的例子。

```
while (a > 0) {
    a = a * b;
    if (b > 0)
        continue;
    b = b + 1;
    return b;
❶}
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-11：A</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">continue</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句</samp>

当我们到达 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句时，我们将跳过所有后续的语句，直接跳转到循环体的末尾 ❶。从那里，<samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp> 循环照常执行，意味着它将跳转回控制表达式。像 列表 8-12 中的那种 <samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp> 循环中的 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句也起到相同的作用。

```
for (int i = 0; i < 5; ❶ i = i + 1) {
    a = a * i;
    if (b > 0)
        continue;
    b = b + 1;
❷}
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-12：A</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">continue</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句在</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">for</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环内部</samp>

在这个列表中，我们仍然从 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句跳转到循环体的末尾 ❷。然后，我们按常规跳转到最终表达式 ❶。

如果在循环外出现了一个 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句，就像在清单 8-13 中一样，编译应该失败。

```
int main(void) {
    break;
}
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-13：无效的</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句</samp>

然而，如果这些语句之一嵌套在循环内部深层次的地方，像清单 8-14 中的 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句那样，也是完全合法的。

```
while (1) {
    if (a > 4) {
        b = b * 2;
        return a + b;
    } else {
        int c = a ? b : 5;
        {
            int d = c;
            break;
        }
    }
    return 0;
}
return 1;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-14：一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句出现在循环内多层嵌套的情况</samp>

这个 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句跳转到 <samp class="SANS_TheSansMonoCd_W5Regular_11">return 1;</samp>，因为那是循环结束后的下一点。

在一个循环中有多个 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句是合法的，就像在清单 8-15 中一样。

```
for (int i = 0; i < 10; i = i + 1) {
    if (i % 2 == 0)
        continue;
    if (x > y)
        continue;
    break;
}
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-15：多个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">和</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">continue</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句在循环内部</samp>

现在我们已经涵盖了你需要了解的关于本章将要添加的语句的关键内容，我们可以开始实现它们了。第一步，像往常一样，是更新词法分析器（lexer）。

### <samp class="SANS_Futura_Std_Bold_B_11">词法分析器</samp>

本章中你将添加五个关键字：

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">do</samp>

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">while</samp>

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">for</samp>

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">break</samp>

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">continue</samp>

你不需要其他新的标记（tokens）。

### <samp class="SANS_Futura_Std_Bold_B_11">解析器</samp>

接下来，我们将更新抽象语法树（AST）。我们将添加五个新语句：

```
statement = Return(exp)
          | Expression(exp)
          | If(exp condition, statement then, statement? else)
| Compound(block)
 **| Break**
 **| Continue**
 **| While(exp condition, statement body)**
 **| DoWhile(statement body, exp condition)**
 **| For(for_init init, exp? condition, exp? post, statement body)**
          | Null
```

`<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp>` 和 `<samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp>` 语句是最简单的。`<samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp>` 和 `<samp class="SANS_TheSansMonoCd_W5Regular_11">do</samp>` 语句也相对简单；它们都有一个主体和一个控制表达式。`<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>` 语句是最复杂的：它包括一个初始子句、一个可选的控制表达式、一个可选的最终表达式和一个主体。初始子句可以是声明、表达式或没有任何内容，因此我们需要一个新的 AST 节点来描述它：

```
for_init = InitDecl(declaration) | InitExp(exp?)
```

将所有内容整合在一起，我们得到了最新的 AST 定义，如 示例 8-16 所示。

```
program = Program(function_definition)
function_definition = Function(identifier name, block body)
block_item = S(statement) | D(declaration)
block = Block(block_item*)
declaration = Declaration(identifier name, exp? init)
**for_init = InitDecl(declaration) | InitExp(exp?)**
statement = Return(exp)
          | Expression(exp)
          | If(exp condition, statement then, statement? else)
| Compound(block)
 **| Break**
 **| Continue**
 **| While(exp condition, statement body)**
 **| DoWhile(statement body, exp condition)**
 **| For(for_init init, exp? condition, exp? post, statement body)**
          | Null
exp = Constant(int)
| Var(identifier)
    | Unary(unary_operator, exp)
    | Binary(binary_operator, exp, exp)
| Assignment(exp, exp)
| Conditional(exp condition, exp, exp)
unary_operator = Complement | Negate | Not
binary_operator = Add | Subtract | Multiply | Divide | Remainder | And | Or
                | Equal | NotEqual | LessThan|LessOrEqual
                | GreaterThan | GreaterOrEqual
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">示例 8-16：包含循环的抽象语法树和</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">和</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">continue</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句</samp>

本章更新 AST 涉及一个复杂的问题。循环标注阶段会为程序中的每个 `<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp>`、`<samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp>` 和循环语句加上标签（我们将使用这些标签将每个 `<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp>` 和 `<samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp>` 语句与其包含的循环关联起来）。这意味着你需要一种方法将这些标签附加到 AST 中的新语句上。这里有几种不同的选择。一种方法是在每个新构造函数中包含一个 `<samp class="SANS_TheSansMonoCd_W5Regular_11">label</samp>` 参数，像这样：

```
statement = `--snip--`
          | Break(**identifier label**)
          | Continue(**identifier label**)
          | While(exp condition, statement body, **identifier label**)
          | DoWhile(statement body, exp condition, **identifier label**)
          | For(for_init init, exp? condition, exp? post, statement body, **identifier label**)
```

如果你选择这种方法，你可能需要在解析过程中使用虚拟标签，然后在循环标注阶段将它们替换为真实标签。另一种方法是定义两个 AST 数据结构：一个在循环标注前使用，没有注释，另一个在循环标注后使用，带有注释。正确的方法取决于你使用的编译语言（以及你的个人偏好）。

更新 AST 后，我们将对语法进行相应的修改，如 示例 8-17 所示。

```
<program> ::= <function>
<function> ::= "int" <identifier> "(" "void" ")" <block>
<block> ::= "{" {<block-item>} "}"
<block-item> ::= <statement> | <declaration>
<declaration> ::= "int" <identifier> ["=" <exp>] ";"
**<for-init> ::= <declaration> | [<exp>] ";"**
<statement> ::= "return" <exp> ";"
              | <exp> ";"
| "if" "(" <exp> ")" <statement> ["else" <statement>]
              | <block>
              **| "break" ";"**
 **| "continue" ";"**
 **| "while" "(" <exp> ")" <statement>**
 **| "do" <statement> "while" "(" <exp> ")" ";"**
 **| "for" "(" <for-init> [<exp>] ";" [<exp>] ")" <statement>**
              | ";"
<exp> ::= <factor> | <exp> <binop> <exp> | <exp> "?" <exp> ":" <exp>
<factor> ::= <int> | <identifier> | <unop> <factor> | "(" <exp> ")"
<unop> ::= "-" | "~" | "!"
<binop> ::= "-" | "+" | "*" | "/" | "%" | "&&" | "||"
          | "==" | "!=" | "<" | "<=" | ">" | ">=" | "="
<identifier> ::= ? An identifier token ?
<int> ::= ? A constant token ?
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">示例 8-17：包含循环的语法和</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">和</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">continue</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句</samp>

我建议编写一个辅助函数来解析可选的表达式。你可以使用这个辅助函数来解析`for`循环头部中的两个可选表达式，以及表达式语句和空语句。这个辅助函数应该让你指定哪个标记表示可选表达式的结束；语法中的大多数可选表达式后面跟着一个分号，但`for`循环头部的第三个子句后面跟着一个右括号。

### <samp class="SANS_Futura_Std_Bold_B_11">语义分析</samp>

目前编译器的语义分析阶段执行一个任务：解析变量名。在本章中，它将承担一个全新的任务：循环标记。循环标记步骤将每个`break`和`continue`语句与其所在的循环关联起来。更具体地说，这个步骤为每个循环语句分配一个唯一的 ID，并为每个`break`和`continue`语句添加其所在循环的 ID。如果在循环外发现`break`或`continue`语句，将抛出错误。在 TACKY 生成过程中，我们将使用这些注释信息，将每个`break`和`continue`语句转换为相对于其所在循环的跳转。

我们将在两次遍历中分别解析变量名和标记循环，每次遍历整个程序。让我们首先扩展变量解析步骤，以处理本章的新语句；然后实现循环标记步骤。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">扩展变量解析</samp>

你需要扩展<samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_statement</samp>，以遍历本章中添加的五个新语句。你将像处理`if`语句一样处理`while`和`do`循环，递归地处理每个子语句和子表达式。解析`break`和`continue`语句要简单得多；因为它们没有子语句或子表达式，你不需要做任何额外处理。

解析一个<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>循环稍微复杂一些，因为循环头部引入了一个新的变量作用域。清单 8-18 演示了如何在<samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_statement</samp>中处理<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>循环。

```
resolve_statement(statement, variable_map):
    match statement with
  | `--snip--`
    | For(init, condition, post, body) ->
        new_variable_map = copy_variable_map(variable_map)
        init = resolve_for_init(init, new_variable_map)
        condition = resolve_optional_exp(condition, new_variable_map)
        post = resolve_optional_exp(post, new_variable_map)
        body = resolve_statement(body, new_variable_map)
        return For(init, condition, post, body)
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-18：解析一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">for</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环</samp>

我们首先创建一个新的变量映射副本，就像在复合语句的开始时一样。复制映射可以确保在循环头部声明的变量不会在循环外部可见，并且如果它隐藏了外部作用域的变量，也不会触发编译器错误。

接下来，我们使用<samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_for_init</samp>处理初始子句，稍后我们将查看这个函数。然后，我们使用新的变量映射遍历<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>循环的控制表达式、终止表达式和主体。我不会提供<samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_optional_exp</samp>的伪代码，它处理可选的控制表达式和终止表达式；如果表达式存在，它会调用<samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_exp</samp>，如果不存在，则不执行任何操作。

清单 8-19 显示了<samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_for_init</samp>的伪代码。

```
resolve_for_init(init, variable_map):
    match init with
    | InitExp(e) -> return InitExp(resolve_optional_exp(e, variable_map))
    | InitDecl(d) -> return InitDecl(resolve_declaration(d, variable_map))
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-19：解析一个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">for</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环的初始子句</samp>

我们在初始子句中解析一个表达式或声明的方式与在程序其他地方解析它时完全相同。如果该子句是一个声明，调用<samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_declaration</samp>将把新声明的变量添加到变量映射中，使其在整个循环中可见。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">循环标记</samp>

在解析变量后，我们将再次遍历程序，给每个循环、<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句标注上 ID。每当我们遇到循环语句时，我们将为其生成一个唯一的 ID。然后，在遍历循环体时，我们将这个 ID 附加到遇到的任何 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句上。让我们来看几个例子。在接下来的三个列表中，标记 ❶ 和 ❷ 表示附加到抽象语法树（AST）的 ID。尽管循环标注阶段是给 AST 添加注解，而不是源文件，但为了可读性，这些列表以源代码的形式呈现。

列表 8-20 演示了我们如何标注包含两个连续循环的代码片段。

```
❶ while (1) {
    a = a - 1;
    if (a < 0)
      ❶ break;
}

❷ for (int b = 0; b < 100; b = b + 1) {
    if (b % 2 == 0)
      ❷ continue;
    a = a * b;
}
return a;
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-20: 标注</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">和</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">continue</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句及其包含的循环</samp>

本列表中的两个循环各自获得一个 ID。我们将 <samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp> 循环标注为 ID ❶，将 <samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp> 循环标注为 ID ❷。每个 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句都会被标注上其所包含循环的 ID，因此我们将 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句标注为 ID ❶，将 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句标注为 ID ❷。

如果多个 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句位于同一个包含循环中，它们都会被标注为相同的 ID，正如 列表 8-21 所示。

```
❶ for (int i = 0; i < 10; i = i + 1) {
    if (i % 2 == 0)
      ❶ continue;
    if (x > y)
      ❶ continue;
  ❶ break;
}
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-21: 标注同一循环中的多个</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">break</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">和</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">continue</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">语句</samp>

由于标注为 ❶ 的 <samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp> 循环是两个 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句和 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句的包含循环，我们将这三条语句都标注为 ID ❶。

如果 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句出现在嵌套循环内，我们会用其包含的最内层循环的 ID 为其注解。列表 8-22 演示了如何注解嵌套循环。

```
❶ while (a > 0) {
  ❷ for (int i = 0; i < 10; i = i + 1) {
        if (i % 2 == 0)
          ❷ continue;
        a = a / 2;
    }
    if (a == b)
      ❶ break;
}
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-22：注解嵌套循环</samp>

外部的 <samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp> 循环和内部的 <samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp> 循环分别被标注为 ❶ 和 ❷。由于 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句出现在内部循环中，我们用 ID ❷ 为其注解。<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句出现在外部循环中，因此我们用 ID ❶ 为其注解。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">实现循环标注</samp>

为了实现这个编译器阶段，我们在遍历 AST 时将当前的循环 ID 作为参数传递，就像我们在变量解析阶段将变量映射传递给 <samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_statement</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">resolve_exp</samp> 等函数一样。当我们不在循环内时，当前的 ID 为 <samp class="SANS_TheSansMonoCd_W5Regular_11">null</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">None</samp>，或者根据你的实现语言，表示缺失值的其他方式。当遇到循环语句时，我们会生成一个新的 ID，并用它注解该语句。然后，在遍历循环体时，我们将其作为当前 ID 传递。当遇到 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句时，我们用传递给我们的 ID 为其注解。列表 8-23 中的伪代码演示了如何用循环 ID 注解语句。

```
label_statement(statement, current_label):
    match statement with
    | Break ->
        if current_label is null:
            fail("break statement outside of loop")
        return ❶ annotate(Break, current_label)
    | Continue ->
        if current_label is null:
            fail("continue statement outside of loop")
        return ❷ annotate(Continue, current_label)
    | While(condition, body) ->
        new_label = ❸ make_label()
        labeled_body = label_statement(body, new_label)
        labeled_statement = While(condition, labeled_body)
        return ❹ annotate(labeled_statement, new_label)
    | `--snip--`
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">列表 8-23：循环注解算法</samp>

<samp class="SANS_TheSansMonoCd_W5Regular_11">make_label</samp>辅助函数❸生成唯一的循环 ID；你可以在此使用与生成 TACKY 中唯一标签相同的辅助函数。<samp class="SANS_TheSansMonoCd_W5Regular_11">annotate</samp>辅助函数接受一个<samp class="SANS_TheSansMonoCd_W5Regular_11">statement</samp> AST 节点和一个标签，并返回一个带有该标签的 AST 节点副本。在这里，我们用它来注解<samp class="SANS_TheSansMonoCd_W5Regular_11">Break</samp> ❶、<samp class="SANS_TheSansMonoCd_W5Regular_11">Continue</samp> ❷和<samp class="SANS_TheSansMonoCd_W5Regular_11">While</samp> ❹语句。我没有提供<samp class="SANS_TheSansMonoCd_W5Regular_11">annotate</samp>的定义，因为它将依赖于你在 AST 中如何表示循环注解。我还省略了处理<samp class="SANS_TheSansMonoCd_W5Regular_11">DoWhile</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">For</samp>以及我们在早期章节中添加的所有语句的伪代码。你可以像处理<samp class="SANS_TheSansMonoCd_W5Regular_11">While</samp>语句一样处理<samp class="SANS_TheSansMonoCd_W5Regular_11">DoWhile</samp>和<samp class="SANS_TheSansMonoCd_W5Regular_11">For</samp>语句。要处理任何其他类型的语句，请递归地调用<samp class="SANS_TheSansMonoCd_W5Regular_11">label_statement</samp>，并传递相同的<samp class="SANS_TheSansMonoCd_W5Regular_11">current_label</samp>值给每个子语句。

一旦你更新了循环标签的传递过程，就可以测试整个语义分析阶段了。

### <samp class="SANS_Futura_Std_Bold_B_11">TACKY 生成</samp>

接下来，我们将把每个新语句转换为 TACKY。在本章中，我们不会改变 TACKY IR，因为我们可以使用现有的 TACKY 指令来实现这些语句。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">break 和 continue 语句</samp>

一个<samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp>语句会无条件跳转到程序中的某个点，因此我们使用单一的<samp class="SANS_TheSansMonoCd_W5Regular_11">Jump</samp>指令来实现它。<samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp>语句也是如此。唯一的问题是跳转到哪里。我们在上一节添加的循环注解可以帮助我们回答这个问题。

每当我们将一个循环语句转换为 TACKY 时，我们会在循环体的指令后面生成一个<samp class="SANS_TheSansMonoCd_W5Regular_11">Label</samp>。任何该循环中的<samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp>语句都可以实现为跳转到该标签，我将其称为*continue 标签*。我们将生成另一个<samp class="SANS_TheSansMonoCd_W5Regular_11">Label</samp>作为整个循环的最后一条指令；我将其称为*break 标签*。

我们将根据在循环注释过程中添加的 ID 来导出这些标签。例如，如果一个循环被标记为 <samp class="SANS_TheSansMonoCd_W5Regular_11">loop0</samp>，则其 break 和 continue 标签可能是 <samp class="SANS_TheSansMonoCd_W5Regular_11">break_loop0</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue_loop0</samp>。使用此命名方案，我们将把带有 ID <samp class="SANS_TheSansMonoCd_W5Regular_11">loop0</samp> 注释的 <samp class="SANS_TheSansMonoCd_W5Regular_11">Break</samp> AST 节点转换为以下 TACKY 指令：

```
Jump("break_loop0")
```

我们将使用相同的注释将一个 <samp class="SANS_TheSansMonoCd_W5Regular_11">Continue</samp> 节点转换为：

```
Jump("continue_loop0")
```

你不需要使用这个特定的命名方案（尽管你的命名方案必须保证这些标签不会与 TACKY 程序中的其他标签冲突）。重要的是，你可以在将 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句转换为 TACKY 时，导出与转换其封闭循环时相同的标签，因为该语句及其封闭循环都使用相同的 ID 注释。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">do 循环</samp>

我们可以通过三步执行语句 <samp class="SANS_TheSansMonoCd_W5Regular_11">do</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><body></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">while (</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><condition></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">);</samp>。首先，我们执行循环体。然后，评估条件并将结果与零进行比较。最后，如果结果不为零，我们跳回到循环的开始。清单 8-24 演示了如何在 TACKY 中实现这些步骤。

```
Label(start)
`<instructions for body>`
`<instructions for condition>`
v = `<result of condition>`
JumpIfNotZero(v, start)
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-24：do 循环的 TACKY 指令</samp>

我们还需要 break 和 continue 标签。continue 标签位于循环体和条件之间，而 break 标签位于最后，在 <samp class="SANS_TheSansMonoCd_W5Regular_11">JumpIfNotZero</samp> 之后。添加这两个标签可以得到完整的 TACKY for <samp class="SANS_TheSansMonoCd_W5Regular_11">do</samp> 循环，如清单 8-25 所示。

```
Label(start)
`<instructions for body>`
**Label(continue_label)**
`<instructions for condition>`
v = `<result of condition>`
JumpIfNotZero(v, start)
**Label(break_label)**
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-25：带有 break 和 continue 标签的 do 循环的 TACKY 指令</samp>

现在，循环体中的任何 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句将跳转到 continue 标签，而任何 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句将跳转到 break 标签。只有在循环体中出现 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句时，这些标签才是必要的——否则它们不会被使用——但为了简化，我们总是会生成这些标签。这样，我们就不需要判断循环中是否包含 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">while 循环</samp>

我们将像处理 <samp class="SANS_TheSansMonoCd_W5Regular_11">do</samp> 循环一样处理 <samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp> 循环，但在这种情况下，我们将在循环体之前执行条件判断，然后使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">JumpIfZero</samp> 来退出循环（如果条件为假）。我们可以将语句 <samp class="SANS_TheSansMonoCd_W5Regular_11">while (</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><condition></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><body></samp> 转换为 清单 8-26 中的 TACKY。

```
Label(start)
`<instructions for condition>`
v = `<result of condition>`
JumpIfZero(v, end)
`<instructions for body>`
❶ Jump(start)
Label(end)
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">清单 8-26: while 循环的 TACKY 指令</samp>

现在，让我们来决定将 break 和 continue 标签放在哪里。这次我们不需要额外的 <samp class="SANS_TheSansMonoCd_W5Regular_11">Label</samp> 指令；我们可以重用 清单 8-26 中已经存在的 <samp class="SANS_TheSansMonoCd_W5Regular_11">Label</samp> 指令。我们将把 break 标签放在本清单末尾的 <samp class="SANS_TheSansMonoCd_W5Regular_11">Label</samp> 指令中。它将作为 <samp class="SANS_TheSansMonoCd_W5Regular_11">JumpIfZero</samp> 指令和任何循环体中的 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句的目标。

同样，我们将在本清单开头的 <samp class="SANS_TheSansMonoCd_W5Regular_11">Label</samp> 指令中放置 continue 标签。这与将 continue 标签放在循环体末尾之后 ❶ 的效果相同，因为循环体之后的指令是一个无条件跳转，它会立即将我们带回循环的开始。让 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句直接跳转到循环开始处，可以让它们绕过那个 <samp class="SANS_TheSansMonoCd_W5Regular_11">Jump</samp> 指令，从而提高一些效率。

Listing 8-27 显示了在我们将<samp class="SANS_TheSansMonoCd_W5Regular_11">while</samp>循环转换为 TACKY 时，应该使用 break 和 continue 标签的位置。

```
Label(**continue_label**)
`<instructions for condition>`
v = `<result of condition>`
JumpIfZero(v, **break_label**)
`<instructions for body>`
Jump(**continue_label**)
Label(**break_label**)
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">Listing 8-27: 带有 break 和 continue 标签的 TACKY 指令，用于</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">while</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环</samp>

这个 TACKY 与 Listing 8-26 完全相同，只是它使用了<samp class="SANS_TheSansMonoCd_W5Regular_11">continue_</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">label</samp>和<samp class="SANS_TheSansMonoCd_W5Regular_11">break_label</samp>，而不是<samp class="SANS_TheSansMonoCd_W5Regular_11">start</samp>和<samp class="SANS_TheSansMonoCd_W5Regular_11">end</samp>。

#### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">for 循环</samp>

我们的最终任务是将<samp class="SANS_TheSansMonoCd_W5Regular_11">for</samp>循环转换为 TACKY。我们将把语句<samp class="SANS_TheSansMonoCd_W5Regular_11">for (</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><init></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">;</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><condition></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">;</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><post></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><body></samp> 转换为 Listing 8-28 中的 TACKY，这包括了 break 和 continue 标签。

```
`<instructions for init>`
Label(start)
`<instructions for condition>`
v = `<result of condition>`
JumpIfZero(v, break_label)
`<instructions for body>`
Label(continue_label)
`<instructions for post>`
Jump(start)
Label(break_label)
```

<samp class="SANS_Futura_Std_Book_Oblique_I_11">Listing 8-28: 带有 break 和 continue 标签的 TACKY 指令，用于</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">for</samp> <samp class="SANS_Futura_Std_Book_Oblique_I_11">循环</samp>

首先，我们执行<code><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><init></samp></code>。然后，我们执行控制表达式<code><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><condition></samp></code>，并检查结果是否为零。如果是，我们跳转到<code><samp class="SANS_TheSansMonoCd_W5Regular_11">Label(break _label)</samp></code>，跳过执行循环体和最终表达式。否则，我们执行循环体，接着是最终表达式<code><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><post></samp></code>，然后跳转回<code><samp class="SANS_TheSansMonoCd_W5Regular_11">Label(start)</samp></code>并开始下一轮循环。我们不会再次执行<code><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><init></samp></code>，因为<code><samp class="SANS_TheSansMonoCd_W5Regular_11">Label(start)</samp></code>在<code><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><init></samp></code>之后。请注意，continue 标签出现在循环体的末尾，紧接在<code><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><post></samp></code>之前，而 break 标签则出现在循环的最末尾，起到双重作用：既是<code><samp class="SANS_TheSansMonoCd_W5Regular_11">JumpIfZero</samp></code>指令的目标，也是任何<code><samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp></code>语句的目标。

接下来，让我们分析如何处理循环头中的三个子句。第一个子句可以是一个表达式、一个声明，或者什么都没有。如果它是声明或表达式，我们将像处理<code>for</code>循环外的声明或表达式一样处理它。如果没有这个子句，我们将不生成任何指令。

第二个子句是控制表达式。如果这个表达式存在，我们将像处理<code>while</code>和<code>do</code>循环中的控制表达式一样，转换它为 TACKY。如果缺失，C 标准规定这个表达式会被“替换为一个非零常量”（第 6.8.5.3 节，第 2 段）。我们可以直接在条件跳转中使用一个非零常量：

```
JumpIfZero(Const(1), break_label)
```

但这个指令实际上什么也不做；<samp class="SANS_TheSansMonoCd_W5Regular_11">Const(1)</samp>永远不可能等于零，因此我们永远不会跳转。相反，我们将完全省略<code>JumpIfZero</code>指令，因为这种方式更高效，能实现相同的行为。

最后，我们需要处理第三个子句，<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><post></samp>。如果存在，我们将转换它为 TACKY；如果缺失，我们将不生成任何指令。### <samp class="SANS_Futura_Std_Bold_B_11">额外加分：switch 语句</samp>

在这一章中，你有机会实现 <samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">case</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">default</samp> 语句。为了支持这些语句，你将需要对语义分析阶段进行重大修改。首先，你需要更改循环注解阶段，因为 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句可以跳出 <samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp> 语句以及循环。你不能在 <samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp> 语句中使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句，因此这个阶段需要将 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句与 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 语句区分开来。

你将需要额外的分析，可能是在一个单独的编译器阶段，来收集出现在每个 <samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp> 语句中的所有情况。为了生成一个 <samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp> 语句的 TACKY，你需要得到该语句中所有情况的列表。然而，这些信息在 AST（抽象语法树）中并不立即可用。一个 <samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp> 语句中的情况可能嵌套了多层，或者 <samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp> 语句的主体根本没有包含任何情况。你需要以更易用的形式将这些信息附加到 AST 上。

使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">--switch</samp> 标志来启用对 <samp class="SANS_TheSansMonoCd_W5Regular_11">switch</samp> 语句的测试：

```
$ **./test_compiler** `**/path/to/your_compiler**` **--chapter 8 --switch**
```

或者，像往常一样，使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">--extra-credit</samp> 标志来启用所有额外的学分测试。

### <samp class="SANS_Futura_Std_Bold_B_11">总结</samp>

在本章中，你实现了最后一组控制流语句。你为三种不同的循环语句添加了支持，并增加了对 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句的支持。你实现了一个新的语义分析阶段，将 <samp class="SANS_TheSansMonoCd_W5Regular_11">break</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">continue</samp> 语句与它们所包含的循环关联，并且你学会了如何将这些复杂的结构转换为一系列 TACKY 指令。

虽然我们已经完成了控制流的*语句*，但在下一章中，你将为一种新的控制流*表达式*添加支持：函数调用。你将学习关于调用约定的知识，这些约定决定了在汇编语言中函数调用的工作原理，并编写一个简单的类型检查器。最棒的是，你将通过编译“Hello, World!”来结束这一章。

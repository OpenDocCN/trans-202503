<hgroup>

## <samp class="SANS_Futura_Std_Bold_Condensed_B_11">B</samp> <samp class="SANS_Dogma_OT_Bold_B_11">汇编生成与代码输出表格</samp>

</hgroup>

![](img/opener-img.jpg)

在每一章中，关于将 TACKY 转换为汇编语言或代码生成的部分，我都包含了总结这些过程的表格。从第四章开始，这些表格仅展示了该章节中所做的更改，而非整个过程。附录中展示了总结这些过程的完整表格，位于第一部分、第二部分和第三部分的末尾。

## <samp class="SANS_Futura_Std_Bold_B_11">第一部分</samp>

本节中的第一组表格说明了编译器应该如何将每个 TACKY 构造转换为汇编语言，位于第一部分的末尾。第二组表格说明了编译器应该如何输出每个汇编构造，位于第一部分的末尾。

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">将 TACKY 转换为汇编语言</samp>

表 B-1 到 B-5 展示了将 TACKY 转换为汇编语言的完整过程，位于第一部分的末尾。

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-1:</samp> <samp class="SANS_Futura_Std_Book_11">将顶级 TACKY 构造转换为汇编语言</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 顶级构造</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编顶级构造</samp> |
| --- | --- |

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Program(top_level_defs)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Program(top_level_defs)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Function(name, global, params,
         instructions)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Function(name, global,
         [Mov(Reg(DI), param1),
          Mov(Reg(SI), param2),</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy next four parameters from registers>,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Stack(16), param7),
          Mov(Stack(24), param8),</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">
          <copy remaining parameters from stack></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">]</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><samp class="SANS_TheSansMonoCd_W5Regular_11">+
         instructions)</samp></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticVariable(name, global, init)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticVariable(name, global, init)</samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-2:</samp> <samp class="SANS_Futura_Std_Book_11">将 TACKY 指令转换为汇编语言</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 指令</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编指令</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Return(val)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(val, Reg(AX)) Ret</samp> |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Unary(非运算, src, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(Imm(0), src) Mov(Imm(0), dst)

SetCC(E, dst)</samp> |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Unary(一元运算符, src, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(src, dst) Unary(一元运算符, dst)</samp> |
| --- | --- |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(除法, src1, src2, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(src1, Reg(AX)) Cdq

Idiv(src2)

Mov(Reg(AX), dst)</samp> |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(余数, src1, src2, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(src1, Reg(AX)) Cdq

Idiv(src2)

Mov(Reg(DX), dst)</samp> |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(算术运算符, src1, src2, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(src1, dst) Binary(算术运算符, src2, dst)</samp> |
| --- | --- |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(关系操作符, src1, src2, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(src2, src1) Mov(Imm(0), dst)

SetCC(关系操作符, dst)</samp> |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Jump(目标)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Jmp(目标)</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">JumpIfZero(条件, 目标)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(Imm(0), 条件) JmpCC(E, 目标)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">JumpIfNotZero(条件, 目标)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(Imm(0), 条件) JmpCC(NE, 目标)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Copy(src, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(src, dst)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Label(标识符)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Label(标识符)</samp> |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">FunCall(函数名, 参数, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><修复堆栈对齐> <设置参数></samp>

<samp class="SANS_TheSansMonoCd_W5Regular_11">Call(函数名)</samp>

<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><deallocate 参数/填充></samp>

<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Reg(AX), dst)</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-3:</samp> <samp class="SANS_Futura_Std_Book_11">将 TACKY 算术运算符转换为汇编</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 运算符</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编运算符</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Complement</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Not</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Negate</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Neg</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Add</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Add</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Subtract</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Sub</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Multiply</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Mult</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-4:</samp> <samp class="SANS_Futura_Std_Book_11">将 TACKY 比较转换为汇编</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 比较</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编条件码</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Equal</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">E</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">NotEqual</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">NE</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LessThan</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">L</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LessOrEqual</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">LE</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">GreaterThan</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">G</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">GreaterOrEqual</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">GE</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-5:</samp> <samp class="SANS_Futura_Std_Book_11">将 TACKY 操作数转换为汇编语言</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 操作数</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作数</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Constant(int)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Imm(int)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Var(identifier)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Pseudo(identifier)</samp> |

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">代码生成</samp>

表 B-6 到 B-10 展示了 第一部分结束时的完整代码生成过程。

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-6:</samp> <samp class="SANS_Futura_Std_Book_11">格式化顶层汇编结构</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编语言顶层结构</samp> |  | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- | --- |

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Program(top_levels)</samp>
```

|

```
<samp class="SANS_Futura_Std_Book_11">Print out each top-level construct. On Linux, add at end of file:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.section .note.GNU-stack,"",@progbits</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Function(name, global, instructions)</samp>
```

|

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.text</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:
    pushq    %rbp
    movq     %rsp, %rbp</samp> 
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><instructions></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticVariable(name, global, init)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">初始化为零</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.bss</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment-directive>
<name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:
    .zero 4</samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">初始化为非零值</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.data</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment-directive>
<name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:
    .long</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><init></samp></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">全局指令</samp> |
| --- |

```
<samp class="SANS_Futura_Std_Book_11">If</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">global</samp> <samp class="SANS_Futura_Std_Book_11">is true:</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">.globl</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><identifier></samp>
<samp class="SANS_Futura_Std_Book_11">Otherwise, omit this directive.</samp></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">对齐指令</samp> | <samp class="SANS_Futura_Std_Book_11">仅限 Linux</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.align 4</samp> |
| --- | --- | --- |
|  | <samp class="SANS_Futura_Std_Book_11">macOS 或 Linux</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.balign 4</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-7:</samp> <samp class="SANS_Futura_Std_Book_11">格式化汇编指令</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编指令</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- |

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(src, dst)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movl   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Ret</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movq    %rbp, %rsp
popq    %rbp
ret</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Unary(unary_operator, operand)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><unary_operator>     <operand></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(binary_operator, src, dst)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><binary_operator>    <src>, <dst></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Idiv(operand)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">idivl  </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cdq</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cdq</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">AllocateStack(int)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">subq    $</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, %rsp</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">DeallocateStack(int)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">addq    $</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, %rsp</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Push(operand)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">pushq  </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Call(label)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">call   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
<samp class="SANS_Futura_Std_Book_11">or</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">call   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">@PLT</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(operand, operand)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cmpl   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Jmp(label)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">jmp     .L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">JmpCC(cond_code, label)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">j</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><cond_code>     </samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">.L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">SetCC(cond_code, operand)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">set</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><cond_code>    <operand></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Label(label)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-8:</samp> <samp class="SANS_Futura_Std_Book_11">汇编运算符的指令名称</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编运算符</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令名称</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Neg</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">negl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Not</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">notl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Add</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">addl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Sub</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">subl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Mult</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">imull</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-9：</samp> <samp class="SANS_Futura_Std_Book_11">条件码的指令后缀</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">条件码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令后缀</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">E</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">e</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">NE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ne</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">L</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">l</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">le</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">G</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">g</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">GE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ge</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-10：</samp> <samp class="SANS_Futura_Std_Book_11">汇编操作数格式</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作数</samp> |  | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(AX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rax</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%eax</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%al</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(DX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rdx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%edx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%dl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(CX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rcx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%ecx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%cl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(DI)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rdi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%edi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%dil</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(SI)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rsi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%esi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%sil</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R8)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R9)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R10)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R11)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Stack(int)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">(%rbp)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">立即数（int）</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">$</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">数据（标识符）</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><标识符></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">（%rip）</samp> |

## <samp class="SANS_Futura_Std_Bold_B_11">第二部分</samp>

本节的第一组表格展示了编译器如何将每个 TACKY 构造转换为汇编语言，在第二部分结束时。第二组表格展示了编译器如何生成每个汇编构造，同样在第二部分结束时。

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">将 TACKY 转换为汇编</samp>

表 B-11 至 B-16 展示了从 TACKY 到汇编的完整转换，见第二部分结束。

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-11：</samp> <samp class="SANS_Futura_Std_Book_11">将顶层 TACKY 构造转换为汇编</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 顶层构造</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编顶层构造</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">程序（顶层定义）</samp> |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Program(top_level_defs</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><all StaticConstant constructs for
       floating-point constants></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Function(name,
         global,
         params,
         instructions)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">寄存器中的返回值或无返回值</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Function(name, global, 
  [</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy Reg(DI) into first int param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy Reg(SI) into second int param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy next four int params/eightbytes from registers></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
    Mov(Double,
        Reg(XMM0),</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">       <first double param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),</samp>
```

|

|  |  |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Double,
        Reg(XMM1),</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">       <second double param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy next six double params/eightbytes from registers></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy Memory(BP, 16) into first stack param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy Memory(BP, 24) into second stack param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy remaining params/eightbytes from stack></samp><samp class="SANS_Futura_Std_Book_11">]</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">+
  instructions)</samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">栈上的返回值</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Function(name, global,
    [Mov(Quadword,
        Reg(DI),
        Memory(BP, -8)),</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy Reg(SI) into first int param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy Reg(DX) into second int param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy next three int params/eightbytes from registers></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
    Mov(Double,
        Reg(XMM0),</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">       <first double param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),
    Mov(Double,
        Reg(XMM1),</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">       <second double param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy next six double params/eightbytes from registers></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy Memory(BP, 16) into first stack param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy Memory(BP, 24) into second stack param/eightbyte></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">   <copy remaining params/eightbytes from stack></samp><samp class="SANS_Futura_Std_Book_11">]</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_11">+
  instructions)</samp></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticVariable(name, global, t,
               init_list)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticVariable(name, global,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment of t></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
               init_list)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticConstant(name, t, init)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticConstant(name,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment of t></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, init)</samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-12：</samp> <samp class="SANS_Futura_Std_Book_11">将 TACKY 指令转换为汇编</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 指令</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编指令</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">返回（val）</samp> | <samp class="SANS_Futura_Std_Book_11">栈上的返回值</samp> |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Quadword, Memory(BP, -8), Reg(AX))
Mov(Quadword,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <first eightbyte of return value></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     Memory(AX, 0))
 Mov(Quadword,</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <second eightbyte of return value></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     Memory(AX, 8))</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy rest of return value></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">Ret</samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">寄存器中的返回值</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><move integer parts of return value into RAX, RDX>
<move double parts of return value into XMM0, XMM1></samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">Ret</samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">无返回值</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Ret</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">一元运算符（Not，src，dst）</samp> | <samp class="SANS_Futura_Std_Book_11">整数</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Imm(0), src)
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Imm(0), dst)
SetCC(E, dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">double</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Xor, Double, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Cmp(Double, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Imm(0), dst)
SetCC(E, dst)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Unary(Negate, src, dst)</samp>
<samp class="SANS_Futura_Std_Book_11">(</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">double</samp> <samp class="SANS_Futura_Std_Book_11">negation)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Double, src, dst)
Binary(Xor, Double, Data(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><negative-zero></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 0), dst)</samp>
<samp class="SANS_Futura_Std_Book_11">And add a top-level constant:</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticConstant(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><negative-zero></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 16,
                DoubleInit(-0.0))</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">一元运算符（unary_operator，src，dst）</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src, dst)
Unary(unary_operator,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, dst)</samp></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Divide, src1,
       src2, dst)</samp>
<samp class="SANS_Futura_Std_Book_11">(integer division)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">有符号</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src1, Reg(AX))
Cdq(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)
Idiv(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src2)
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Reg(AX), dst)</samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">无符号</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src1, Reg(AX))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Imm(0), Reg(DX))
Div(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src2)
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Reg(AX), dst)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Remainder, src1,
       src2, dst)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">有符号</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src1, Reg(AX))
Cdq(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">) 
div(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src2)
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Reg(DX), dst)</samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">无符号</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src1, Reg(AX))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Imm(0), Reg(DX))
Div(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src2)
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Reg(DX), dst)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(arithmetic_operator, src1,
       src2, dst)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src1, dst)
Binary(arithmetic_operator,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src2, dst)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(relational_operator, src1,
      src2, dst)</samp>
```

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src1 type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src2, src1)
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Imm(0), dst)
SetCC(relational_operator, dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">跳转（目标）</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Jmp(target)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">JumpIfZero(condition,
           target)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">整数</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><condition type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Imm(0), condition)
JmpCC(E, target)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">double</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Xor, Double, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Cmp(Double, condition, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
JmpCC(E, target)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">JumpIfNotZero(condition,
              target)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">整数</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><condition type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Imm(0), condition)
JmpCC(NE, target)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">double</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Xor, Double, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Cmp(Double, condition, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
JmpCC(NE, target)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Copy(src, dst)</samp> | <samp class="SANS_Futura_Std_Book_11">标量</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src, dst)</samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">结构</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     PseudoMem(src, 0),
     PseudoMem(dst, 0))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><next chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     PseudoMem(src,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),
     PseudoMem(dst,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy remaining chunks></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Load(ptr, dst)</samp> | <samp class="SANS_Futura_Std_Book_11">标量</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Quadword, ptr, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, Memory(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 0), dst)</samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">结构</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Quadword, ptr, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     Memory(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 0),
     PseudoMem(dst, 0))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><next chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     Memory(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),
     PseudoMem(dst,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy remaining chunks></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Store(src, ptr)</samp> | <samp class="SANS_Futura_Std_Book_11">标量</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Quadword, ptr, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src, Memory(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 0))</samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">结构</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Quadword, ptr, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     PseudoMem(src, 0),
     Memory(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 0))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><next chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     PseudoMem(src,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),
     Memory(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy remaining chunks></samp></samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">GetAddress(src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Lea(src, dst)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">AddPtr(ptr, index, scale,
        dst)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">常量索引</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Quadword, ptr, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Lea(Memory(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, index * scale), dst)</samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">变量索引和 1, 2, 4 或 8 的尺度</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Quadword, ptr, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(Quadword, index, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Lea(Indexed(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, scale), dst)</samp></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">变量索引和其他尺度</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(Quadword, ptr, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(Quadword, index, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Binary(Mult, Quadword, Imm(scale), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Lea(Indexed(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 1), dst)</samp></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">CopyToOffset(src, dst,
             offset)</samp>
```

| <samp class="SANS_TheSansMonoCd_W5Regular_11">src</samp> <samp class="SANS_Futura_Std_Book_11">是标量</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src, PseudoMem(dst, offset))</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">src</samp> <samp class="SANS_Futura_Std_Book_11">是一个结构</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     PseudoMem(src, 0),
     PseudoMem(dst, offset))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><next chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     PseudoMem(src,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),
     PseudoMem(dst, offset</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy remaining chunks></samp></samp></samp></samp>
```

|

|  ``` <samp class="SANS_TheSansMonoCd_W5Regular_11">CopyFromOffset(src,
               offset,
               dst)</samp>
```  | <samp class="SANS_TheSansMonoCd_W5Regular_11">dst</samp> <samp class="SANS_Futura_Std_Book_11">是标量</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, PseudoMem(src, offset), dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">dst</samp> <samp class="SANS_Futura_Std_Book_11">是一个结构</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     PseudoMem(src, offset),
     PseudoMem(dst, 0))
Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><next chunk type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,
     PseudoMem(src, offset</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">),
     PseudoMem(dst,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><first chunk size></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><copy remaining chunks></samp></samp></samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">标签（标识符）</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Label(identifier)</samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">FunCall(fun_name, args,
         dst)</samp>
```

| <samp class="SANS_TheSansMonoCd_W5Regular_11">dst</samp> <samp class="SANS_Futura_Std_Book_11">将会存储在内存中</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Lea(dst, Reg(DI))</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><fix stack alignment></samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><move arguments to general-purpose registers, starting with RSI></samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><move arguments to XMM registers>
<push arguments onto the stack></samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">Call(fun_name)</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><deallocate arguments/padding></samp>
```

|

|  | <samp class="SANS_TheSansMonoCd_W5Regular_11">dst</samp> <samp class="SANS_Futura_Std_Book_11">将会通过寄存器返回</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><fix stack alignment>
<move arguments to general-purpose registers>
<move arguments to XMM registers>
<push arguments onto the stack></samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">Call(fun_name)</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><deallocate arguments/padding>
<move integer parts of return value from RAX, RDX into dst>
<move double parts of return value from XMM0, XMM1 into dst></samp>
```

|

|  | <samp class="SANS_TheSansMonoCd_W5Regular_11">dst</samp> <samp class="SANS_Futura_Std_Book_11">不存在</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><fix stack alignment>
<move arguments to general-purpose registers>
<move arguments to XMM registers>
<push arguments onto the stack></samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">Call(fun_name)</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><deallocate arguments/padding></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">ZeroExtend(src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">MovZeroExtend(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type>, <dst type>,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_11">src, dst)</samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">SignExtend(src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Movsx(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type>, <dst type>,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_11">src, dst)</samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Truncate(src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src, dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">IntToDouble(src, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">char</samp> <samp class="SANS_Futura_Std_Book_11">或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">signed char</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Movsx(Byte, Longword, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Cvtsi2sd(Longword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">int</samp> <samp class="SANS_Futura_Std_Book_11">或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">long</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cvtsi2sd(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src, dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">DoubleToInt(src, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">char</samp> <samp class="SANS_Futura_Std_Book_11">或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">signed char</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cvttsd2si(Longword, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(Byte, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">整数</samp> <samp class="SANS_Futura_Std_Book_11">或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">长整数</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cvttsd2si(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst type></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, src, dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">UIntToDouble(src, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">无符号字符</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">MovZeroExtend(Byte, Longword, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Cvtsi2sd(Longword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)</samp>
```

|

|  | <samp class="SANS_TheSansMonoCd_W5Regular_11">无符号整数</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">MovZeroExtend(Longword, Quadword, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Cvtsi2sd(Quadword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)</samp>
```

|

|  | <samp class="SANS_TheSansMonoCd_W5Regular_11">无符号长整数</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(Quadword, Imm(0), src)
JmpCC(L,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)
Cvtsi2sd(Quadword, src, dst)
Jmp(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)
Label(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)
Mov(Quadword, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(Quadword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Unary(Shr, Quadword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Binary(And, Quadword, Imm(1), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Binary(Or, Quadword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Cvtsi2sd(Quadword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)
Binary(Add, Double, dst, dst) Label(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">DoubleToUInt(src, dst)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">无符号字符</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cvttsd2si(Longword, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(Byte, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">无符号整数</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cvttsd2si(Quadword, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Mov(Longword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">无符号长整数</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(Double, Data(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><upper-bound></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 0), src)
JmpCC(AE,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)
Cvttsd2si(Quadword, src, dst)
Jmp(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)
Label(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)
Mov(Double, src, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Binary(Sub, Double, Data(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><upper-bound></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 0), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Cvttsd2si(Quadword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><X></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)
Mov(Quadword, Imm(9223372036854775808), Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">))
Binary(Add, Quadword, Reg(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><R></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">), dst)
Label(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp>
<samp class="SANS_Futura_Std_Book_11">And add a top-level constant:</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticConstant(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><upper-bound></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 8,
                DoubleInit(9223372036854775808.0))</samp></samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-13:</samp> <samp class="SANS_Futura_Std_Book_11">将 TACKY 算术运算符转换为汇编</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 运算符</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编运算符</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">补码</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Not</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">取反</samp> <samp class="SANS_Futura_Std_Book_11">(整数取反)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Neg</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">加法</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Add</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">减法</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Sub</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">乘法</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Mult</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">除法</samp> <samp class="SANS_Futura_Std_Book_11">(</samp><samp class="SANS_TheSansMonoCd_W5Regular_11">双精度</samp> <samp class="SANS_Futura_Std_Book_11">除法)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">DivDouble</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-14:</samp> <samp class="SANS_Futura_Std_Book_11">将 TACKY 比较操作转换为汇编</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 比较</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">汇编条件码</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">等于</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">E</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">不相等</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">NE</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">小于</samp> | <samp class="SANS_Futura_Std_Book_11">符号数</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">L</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">无符号，指针，或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">双精度</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">B</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">小于等于</samp> | <samp class="SANS_Futura_Std_Book_11">有符号</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">LE</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">无符号、指针或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">双精度</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">BE</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">大于</samp> | <samp class="SANS_Futura_Std_Book_11">有符号</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">G</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">无符号、指针或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">双精度</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">A</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">大于等于</samp> | <samp class="SANS_Futura_Std_Book_11">有符号</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">GE</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">无符号、指针或</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">双精度</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">AE</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-15：</samp> <samp class="SANS_Futura_Std_Book_11">将 TACKY 操作数转换为汇编</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">TACKY 操作数</samp> |  | <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作数</samp> |
| --- | --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">常量(ConstChar(int))</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">立即数(int)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">常量(ConstInt(int))</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">立即数(int)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">常量(ConstLong(int))</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">立即数(int)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">常量(ConstUChar(int))</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">立即数(int)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">常量(ConstUInt(int))</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">立即数(int)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">常量(ConstULong(int))</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">立即数(int)</samp> |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">常量(ConstDouble(double))</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">数据(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><ident></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 0)</samp> <samp class="SANS_Futura_Std_Book_11">并添加一个顶层常量：</samp>

<samp class="SANS_TheSansMonoCd_W5Regular_11">静态常量(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><ident></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, 8, DoubleInit(double))</samp> |

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Var(identifier)</samp> | <samp class="SANS_Futura_Std_Book_11">标量值</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">Pseudo(identifier)</samp> |
| --- | --- | --- |
|  | <samp class="SANS_Futura_Std_Book_11">聚合值</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">PseudoMem(identifier, 0)</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-16：</samp> <samp class="SANS_Futura_Std_Book_11">类型转换为汇编语言</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">源类型</samp> |  | <samp class="SANS_Futura_Std_Heavy_B_11">汇编类型</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">对齐方式</samp> |
| --- | --- | --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Char</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">SChar</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UChar</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Int</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">长整型</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UInt</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">长整型</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Long</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">四字长整型</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ULong</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">四字长整型</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Double</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">双精度</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Pointer(referenced_t)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">四字长整型</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Array(element, size)</samp> | <samp class="SANS_Futura_Std_Book_11">大小为 16 字节或更大的变量</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ByteArray(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><size of element></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">* 大小, 16)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">16</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">其他所有内容</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">字节数组（</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><size of element></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">* 大小，</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment of element></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp> | <samp class="SANS_Futura_Std_Book_11">与</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">元素</samp> <samp class="SANS_Futura_Std_Book_11">相同的对齐方式</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">结构（标签）</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">字节数组（</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><size from type table></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment from type table></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp> | <samp class="SANS_Futura_Std_Book_11">来自类型表的对齐</samp> |

### <samp class="SANS_Futura_Std_Bold_Condensed_Oblique_BI_11">代码发射</samp>

表 B-17 至 B-23 显示了在 第二部分 结束时的完整代码发射过程。

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-17:</samp> <samp class="SANS_Futura_Std_Book_11">格式化顶级汇编构造</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编顶级构造</samp> |  | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">程序（顶层构造）</samp> |

```
<samp class="SANS_Futura_Std_Book_11">Print out each top-level construct.
On Linux, add at end of file:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .section .note.GNU-stack,"",@progbits</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">函数（名称，全局，指令）</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .text</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:
     pushq    %rbp
     movq     %rsp, %rbp</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <instructions></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticVariable(name, global,
               alignment,
               init_list)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">初始化为零的整数，或任何仅用</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">ZeroInit</samp> <samp class="SANS_Futura_Std_Book_11">初始化的变量</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .bss</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <alignment-directive>
 <name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init_list></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">所有其他变量</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .data</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <alignment-directive>
 <name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init_list></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticConstant(name, alignment,
               init)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">Linux</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.section .rodata</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <alignment-directive>
 <name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init></samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS（8 字节对齐的数字常量）</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.literal8
    .balign 8</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init></samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS（16 字节对齐的数字常量）</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.literal16
    .balign 16</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .quad 0</samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS（字符串常量）</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.cstring</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">全局指令</samp> |  |
| --- | --- |

```
 <samp class="SANS_Futura_Std_Book_11">If</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">global</samp> <samp class="SANS_Futura_Std_Book_11">is true:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.globl</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><identifier></samp>
 <samp class="SANS_Futura_Std_Book_11">Otherwise, omit this directive.</samp></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">对齐指令</samp> | <samp class="SANS_Futura_Std_Book_11">仅限 Linux</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.align</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment></samp></samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS 或 Linux</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.balign</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment></samp></samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-18:</samp> <samp class="SANS_Futura_Std_Book_11">格式化静态初始化器</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">静态初始化器</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CharInit（0）</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CharInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.byte</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">IntInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">IntInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.long</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LongInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LongInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.quad</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UCharInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UCharInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.byte</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UIntInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UIntInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.long</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ULongInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ULongInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.quad</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ZeroInit(n)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><n></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DoubleInit(d)</samp> |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.double</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><d></samp>
 <samp class="SANS_Futura_Std_Book_11">or</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.quad</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><d-interpreted-as-long></samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">StringInit(s, True)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.asciz "</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><s></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">"</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">StringInit(s, False)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.ascii "</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><s></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">"</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">PointerInit(label)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.quad</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-19：</samp> <samp class="SANS_Futura_Std_Book_11">格式化汇编指令</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编指令</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(t, src, dst)</samp> |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">mov</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>   <src></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Movsx(src_t, dst_t, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movs</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src_t><dst_t>    <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">MovZeroExtend(src_t, dst_t, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movz</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src_t><dst_t>    <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Lea</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">leaq    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cvtsi2sd(t, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cvtsi2sd</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>     <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cvttsd2si(t, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cvttsd2si</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>    <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Ret</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movq     %rbp, %rsp
popq     %rbp
ret</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Unary(unary_operator, t, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><unary_operator><t>     <operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Xor, Double, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">xorpd   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src>,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst></samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Mult, Double, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">mulsd   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src>,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst></samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(binary_operator, t, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><binary_operator><t>    <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Idiv(t, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">idiv</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"></samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Div(t, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">div</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"></samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cdq(Longword)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cdq</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cdq(Quadword)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cqo</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Push(operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">pushq   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Call(label)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">call    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
<samp class="SANS_Futura_Std_Book_11">or</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">call    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">@PLT</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(Double, operand, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">comisd  </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand>, <operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(t, operand, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cmp</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>   <operand></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Jmp(label)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">jmp      .L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">JmpCC(cond_code, label)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">j</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><cond_code></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">.L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">SetCC(cond_code, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">set</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><cond_code>    <operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Label(label)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-20：</samp> <samp class="SANS_Futura_Std_Book_11">汇编操作符的指令名称</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作符</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令名称</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Neg</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">neg</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Not</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">not</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Shr</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">shr</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Add</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">add</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Sub</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">sub</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Mult</samp> <samp class="SANS_Futura_Std_Book_11">(仅限整数乘法)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">imul</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DivDouble</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">div</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">And</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">and</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Or</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">or</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Shl</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">shl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ShrTwoOp</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">shr</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-21:</samp> <samp class="SANS_Futura_Std_Book_11">汇编类型的指令后缀</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编类型</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令后缀</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Longword</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">l</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Quadword</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">q</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Double</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">sd</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-22:</samp> <samp class="SANS_Futura_Std_Book_11">条件码的指令后缀</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">条件码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令后缀</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">E</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">e</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">NE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ne</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">L</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">l</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">le</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">G</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">g</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">GE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ge</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">A</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">a</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ae</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">B</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">BE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">be</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-23:</samp> <samp class="SANS_Futura_Std_Book_11">汇编操作数格式</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作数</samp> |  | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(AX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rax</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%eax</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%al</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(DX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rdx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%edx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%dl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(CX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rcx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%ecx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%cl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(DI)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rdi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%edi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%dil</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(SI)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rsi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%esi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%sil</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R8)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R9)</samp> | <samp class="SANS_Futura_Std_Book_11">8-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R10)</samp> | <samp class="SANS_Futura_Std_Book_11">8-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R11)</samp> | <samp class="SANS_Futura_Std_Book_11">8-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1-byte</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(SP)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rsp</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(BP)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rbp</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM0)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm0</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM1)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM2)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm2</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM3)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm3</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM4)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM5)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm5</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM6)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm6</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM7)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm7</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM14)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm14</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM15)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm15</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Memory(reg, int)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><reg></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Indexed(reg1, reg2, int)</samp> |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><reg1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><reg2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Imm(int)</samp> |  |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">$</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Data(identifier, int)</samp> |  |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><identifier></samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">(%rip)</samp>
```

|

## <samp class="SANS_Futura_Std_Bold_B_11">第三部分</samp>

在第三部分中，我们不会改变从 TACKY 到汇编的转换，但我们会向汇编的 AST 添加一些新的寄存器，并相应地更新代码生成步骤。本节末尾的代码生成步骤如何呈现，取决于你是否先完成了第二部分，或者是直接从第一部分跳到第三部分。

表 B-24 到 B-28 展示了如果你跳过第二部分，在第三部分末尾的完整代码生成步骤。

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-24：</samp> <samp class="SANS_Futura_Std_Book_11">格式化顶层汇编构造</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编顶层构造</samp> |  | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Program(top_levels)</samp> |

```
<samp class="SANS_Futura_Std_Book_11">Print out each top-level construct.
On Linux, add at end of file:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .section .note.GNU-stack,"",@progbits</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Function(name, global, instructions)</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .text</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:
     pushq    %rbp
     movq     %rsp, %rbp</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <instructions></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">StaticVariable(name, global, init)</samp> | <samp class="SANS_Futura_Std_Book_11">初始化为零</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .bss</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <alignment-directive>
<name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:
     .zero 4</samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">初始化为非零值</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .data</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <alignment-directive>
 <name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:
     .long</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><init></samp></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">全局指令</samp> |
| --- |

```
 <samp class="SANS_Futura_Std_Book_11">If</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">global</samp> <samp class="SANS_Futura_Std_Book_11">is true:</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">.globl</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><identifier></samp>
 <samp class="SANS_Futura_Std_Book_11">Otherwise, omit this directive.</samp></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">对齐指令</samp> | <samp class="SANS_Futura_Std_Book_11">仅限 Linux</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.align 4</samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS 或 Linux</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.balign 4</samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-25：</samp> <samp class="SANS_Futura_Std_Book_11">格式化汇编指令</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编指令</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(src, dst)</samp> |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movl    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Ret</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movq     %rbp, %rsp
popq     %rbp
ret</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Unary(unary_operator, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><unary_operator>     <operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(binary_operator, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><binary_operator>    <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Idiv(operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">idivl   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cdq</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cdq</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">AllocateStack(int)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">subq     $</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, %rsp</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">DeallocateStack(int)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">addq     $</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">, %rsp</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Push(operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">pushq   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Pop(reg)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">popq    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><reg></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Call(label)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">call   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
<samp class="SANS_Futura_Std_Book_11">or</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">call   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">@PLT</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(operand, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cmpl   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Jmp(label)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">jmp     .L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">JmpCC(cond_code, label)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">j</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><cond_code></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">.L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">SetCC(cond_code, operand)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">set</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><cond_code>    <operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Label(label)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-26:</samp> <samp class="SANS_Futura_Std_Book_11">汇编操作符的指令名称</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作符</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令名称</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Neg</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">negl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Not</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">notl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Add</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">addl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Sub</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">subl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Mult</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">imull</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-27:</samp> <samp class="SANS_Futura_Std_Book_11">条件代码的指令后缀</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">条件代码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令后缀</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">E</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">e</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">NE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ne</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">L</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">l</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">le</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">G</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">g</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">GE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ge</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-28:</samp> <samp class="SANS_Futura_Std_Book_11">汇编操作数的格式化</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作数</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(AX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rax</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%eax</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%al</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(DX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rdx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%edx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%dl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(CX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rcx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%ecx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%cl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(BX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rbx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%ebx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%bl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(DI)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rdi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%edi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%dil</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(SI)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rsi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%esi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%sil</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R8)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R9)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R10)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R11)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R12)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r12</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r12d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r12b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R13)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r13</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r13d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r13b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R14)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r14</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r14d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r14b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R15)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r15</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r15d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r15b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Stack(int)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">(%rbp)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Imm(int)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">$</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Data(identifier)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><identifier></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">(%rip)</samp> |

表 B-29 至 B-35 显示了完成 第一部分、第二部分 和 第三部分 后的完整代码输出过程。

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-29：</samp> <samp class="SANS_Futura_Std_Book_11">格式化顶级汇编构造</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编顶级构造</samp> |  | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Program(top_levels)</samp> |

```
<samp class="SANS_Futura_Std_Book_11">Print out each top-level construct.
On Linux, add at end of file:</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">
    .section .note.GNU-stack,"",@progbits</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Function(name, global, instructions)</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.text</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:
     pushq    %rbp
     movq     %rsp, %rbp</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><instructions></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticVariable(name, global,
               alignment,
               init_list)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">初始化为零的整数，或者仅用</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">ZeroInit</samp> 初始化的任何变量 |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .bss</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <alignment-directive>
 <name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init_list></samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">所有其他变量</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><global-directive></samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">    .data</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <alignment-directive>
 <name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init_list></samp>
```

|

|

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">StaticConstant(name, alignment,
               init)</samp>
```

| <samp class="SANS_Futura_Std_Book_11">Linux</samp> |
| --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.section .rodata</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <alignment-directive>
 <name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init></samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS（8 字节对齐的数字常量）</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.literal8
    .balign 8</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init></samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS（16 字节对齐的数字常量）</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.literal16
    .balign 16</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"> 
     .quad 0</samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS（字符串常量）</samp> |
| --- | --- |

```
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.cstring</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><name></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11">    <init></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">全局指令</samp> |
| --- |

```
 <samp class="SANS_Futura_Std_Book_11">If</samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">global</samp> <samp class="SANS_Futura_Std_Book_11">is true:</samp>
 <samp class="SANS_TheSansMonoCd_W5Regular_11">.globl</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><identifier></samp>
 <samp class="SANS_Futura_Std_Book_11">Otherwise, omit this directive.</samp></samp>
```

|

| <samp class="SANS_Futura_Std_Book_11">对齐指令</samp> | <samp class="SANS_Futura_Std_Book_11">仅限 Linux</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.align</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment></samp></samp>
```

|

|  | <samp class="SANS_Futura_Std_Book_11">macOS 或 Linux</samp> |
| --- | --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.balign</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><alignment></samp></samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-30：</samp> <samp class="SANS_Futura_Std_Book_11">格式化静态初始化器</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">静态初始化器</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CharInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">CharInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.byte</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">IntInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">IntInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.long</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LongInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LongInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.quad</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UCharInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UCharInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.byte</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UIntInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">UIntInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.long</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ULongInit(0)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero 8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ULongInit(i)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.quad</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><i></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ZeroInit(n)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.zero</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><n></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DoubleInit(d)</samp> |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.double</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><d></samp>
<samp class="SANS_Futura_Std_Book_11">or</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">.quad</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><d-interpreted-as-long></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">StringInit(s, True)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.asciz "</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><s></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">"</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">StringInit(s, False)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.ascii "</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><s></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">"</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">PointerInit(label)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">.quad</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-31:</samp> <samp class="SANS_Futura_Std_Book_11">格式化汇编指令</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编指令</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Mov(t, src, dst)</samp> |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">mov</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>   <src></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_Futura_Std_Book_11"><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst></samp></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Movsx(src_t, dst_t, src, dst)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movs</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src_t><dst_t>    <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">MovZeroExtend(源类型, 目标类型, 源, 目标)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movz</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src_t><dst_t>    <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Lea</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">leaq    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cvtsi2sd(t, 源, 目标)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cvtsi2sd</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>     <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cvttsd2si(t, 源, 目标)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cvttsd2si</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>    <src>, <dst></samp> <samp class="SANS_Futura_Std_Book_11"></samp> 
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Ret</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">movq     %rbp, %rsp
popq     %rbp
ret</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Unary(一元操作符, t, 操数)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><unary_operator><t>     <operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Xor, Double, 源, 目标)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">xorpd   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(Mult, Double, 源, 目标)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">mulsd   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Binary(二元操作符, t, 源, 目标)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><binary_operator><t>    <src>, <dst></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Idiv(t, 操数)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">idiv</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>  <operand></samp> 
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Div(t, 操数)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">div</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t>   <operand></samp> 
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cdq(长字)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cdq</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cdq(四字)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cqo</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Push(操作数)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">pushq   </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Pop(寄存器)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">popq    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><reg></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Call(标签)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">call    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
<samp class="SANS_Futura_Std_Book_11">or</samp>
<samp class="SANS_TheSansMonoCd_W5Regular_11">call    </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">@PLT</samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(Double, 操数, 操数)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">comisd  </samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand>, <operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Cmp(t, 操数, 操数)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">cmp</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><t></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"></samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Jmp(标签)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">jmp      .L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">JmpCC(条件码, 标签)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">j</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><cond_code></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">.L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">SetCC(条件码, 操数)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">set</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><cond_code></samp> <samp class="SANS_TheSansMonoCd_W5Regular_11"></samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><operand></samp>
```

|

| <samp class="SANS_TheSansMonoCd_W5Regular_11">Label(标签)</samp> |
| --- |

```
<samp class="SANS_TheSansMonoCd_W5Regular_11">.L</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><label></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">:</samp>
```

|

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-32：</samp> <samp class="SANS_Futura_Std_Book_11">汇编操作符的指令名称</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作符</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令名称</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Neg</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">neg</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Not</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">not</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Shr</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">shr</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Add</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">add</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Sub</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">sub</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Mult</samp> <samp class="SANS_Futura_Std_Book_11">(仅限整数乘法)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">imul</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">DivDouble</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">div</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">与</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">and</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">或</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">or</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Shl</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">shl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">ShrTwoOp</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">shr</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-33：</samp> <samp class="SANS_Futura_Std_Book_11">汇编类型的指令后缀</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编类型</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令后缀</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">长字</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">l</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">四字</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">q</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">双精度</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">sd</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-34：</samp> <samp class="SANS_Futura_Std_Book_11">条件码的指令后缀</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">条件码</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">指令后缀</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">E</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">e</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">不等</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ne</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">L</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">l</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">LE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">le</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">G</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">g</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">GE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ge</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">A</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">a</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">AE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">ae</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">B</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">BE</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">be</samp> |

<samp class="SANS_Futura_Std_Heavy_B_11">表 B-35：</samp> <samp class="SANS_Futura_Std_Book_11">汇编操作数的格式化</samp>

| <samp class="SANS_Futura_Std_Heavy_B_11">汇编操作数</samp> | <samp class="SANS_Futura_Std_Heavy_B_11">输出</samp> |
| --- | --- |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">寄存器(AX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rax</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%eax</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%al</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">寄存器(DX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rdx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%edx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%dl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">寄存器(CX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rcx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%ecx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%cl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">寄存器(BX)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rbx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%ebx</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%bl</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">寄存器(DI)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rdi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%edi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%dil</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">寄存器(SI)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rsi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%esi</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%sil</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">寄存器(R8)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r8b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R9)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r9b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R10)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r10b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R11)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r11b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R12)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r12</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r12d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r12b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R13)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r13</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r13d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r13b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R14)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r14</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r14d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r14b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(R15)</samp> | <samp class="SANS_Futura_Std_Book_11">8 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r15</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">4 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r15d</samp> |
|  | <samp class="SANS_Futura_Std_Book_11">1 字节</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">%r15b</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(SP)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rsp</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(BP)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%rbp</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM0)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm0</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM1)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm1</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM2)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm2</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM3)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm3</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM4)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm4</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM5)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm5</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM6)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm6</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM7)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm7</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM8)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm8</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM9)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm9</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM10)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm10</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM11)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm11</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM12)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm12</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM13)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm13</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM14)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm14</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Reg(XMM15)</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">%xmm15</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Memory(reg, int)</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><reg></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">索引（reg1，reg2，int）</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_11">(</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><reg1></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><reg2></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">,</samp> <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">)</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">Imm（int）</samp> |  | <samp class="SANS_TheSansMonoCd_W5Regular_11">$</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">数据（identifier，0）</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><identifier></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">（%rip）</samp> |
| <samp class="SANS_TheSansMonoCd_W5Regular_11">数据（identifier，int）</samp> | <samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><identifier></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">+</samp><samp class="SANS_TheSansMonoCd_W5Regular_Italic_I_11"><int></samp><samp class="SANS_TheSansMonoCd_W5Regular_11">（%rip）</samp> |

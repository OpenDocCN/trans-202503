<hgroup>

## <samp class="SANS_Futura_Std_Bold_Condensed_B_11">C</samp> <samp class="SANS_Dogma_OT_Bold_B_11">常见匹配器</samp>

</hgroup>

![](img/Drop-image.jpg)

在 Jest 中，*匹配器* 让我们检查特定的条件，例如两个值是否相等，或者当前 DOM 中是否存在某个 HTML 元素。Jest 自带一组内置匹配器。此外，来自测试库的 *JEST-DOM* 包提供了专门用于 DOM 的匹配器。

### <samp class="SANS_Futura_Std_Bold_B_11">内置匹配器</samp>

本节介绍了最常见的 Jest 内置匹配器。你可以在官方 JEST 文档中找到完整的匹配器列表，网址是 [*https://<wbr>jestjs<wbr>.io<wbr>/docs<wbr>/expect*](https://jestjs.io/docs/expect)。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toBe  </samp>这是最简单且迄今为止最常见的匹配器。它是一个简单的相等性检查，用来判断两个值是否完全相同。它的行为类似于严格相等运算符（<samp class="SANS_TheSansMonoCd_W5Regular_11">===</samp>），因为它考虑了类型差异。然而，与严格相等运算符不同的是，它将 <samp class="SANS_TheSansMonoCd_W5Regular_11">+0</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">-0</samp> 视为不同的。

```
test('toBe',  () => {
    expect(1 + 1).toBe(2);
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toEqual  </samp>我们使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">toEqual</samp> 执行对象和数组的深度相等性检查，比较它们的所有属性或项。该匹配器忽略了 undefined 值和项。此外，它不会检查对象的类型（例如，它们是否是同一类或父对象的实例或子类）。如果需要进行这样的检查，请考虑使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">toStrictEqual</samp> 匹配器。

```
test('toEqual', () => {
    expect([undefined, 1]).toEqual([1]);
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toStrictEqual  </samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">toStrictEqual</samp> 匹配器对对象和数组执行结构和类型比较；通过此测试要求对象必须为相同类型。此外，匹配器还考虑了 <samp class="SANS_TheSansMonoCd_W5Regular_11">undefined</samp> 值和 <samp class="SANS_TheSansMonoCd_W5Regular_11">undefined</samp> 数组项。

```
test('toStrictEqual', () => {
    expect([undefined, 1]).toStrictEqual([undefined, 1]);
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toBeCloseTo  </samp>对于浮动点数，我们使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">toBeCloseTo</samp> 而不是 <samp class="SANS_TheSansMonoCd_W5Regular_11">toBe</samp>。这是因为 JavaScript 对浮动点数的内部计算存在缺陷，而这个匹配器考虑了这些舍入误差。

```
test('toBeCloseTo', () => {
    expect(0.1 + 0.2).toBeCloseTo(0.3);
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toBeGreaterThan/toBeGreaterThanOrEqual  </samp>对于数值，我们使用这些匹配器来验证结果是否大于或等于某个值，类似于 <samp class="SANS_TheSansMonoCd_W5Regular_11">></samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">>=</samp> 运算符。

```
test('toBeGreaterThan', () => {
    expect(1 + 1).toBeGreaterThan(1);
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toBeLessThan/toBeLessThanOrEqual  </samp>这些是与数字值的 <samp class="SANS_TheSansMonoCd_W5Regular_11">GreaterThan...</samp> 匹配器相对的，类似于 <samp class="SANS_TheSansMonoCd_W5Regular_11"><</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11"><=</samp> 运算符。

```
test('toBeLessThan', () => {
    expect(1 + 1).toBeLessThan(3);
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toBeTruthy/toBeFalsy  </samp>这些匹配器检查一个值是否存在，不论其值如何。它们将六个 JavaScript 值 <samp class="SANS_TheSansMonoCd_W5Regular_11">0</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">' '</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">null</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">undefined</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">NaN</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">false</samp> 视为假值，其他一切视为真值。

```
test('toBeTruthy', () => {
    expect(1 + 1).toBeTruthy();
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toMatch  </samp>该匹配器接受字符串或正则表达式，然后检查一个值是否包含给定的字符串，或者正则表达式是否返回给定的结果。

```
test('toMatch, () => {
    expect('apples and oranges').toMatch('apples');
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toContain  </samp> <samp class="SANS_TheSansMonoCd_W5Regular_11">toContain</samp> 匹配器类似于 <samp class="SANS_TheSansMonoCd_W5Regular_11">toMatch</samp>，但它接受数组或字符串，并检查这些是否包含给定的字符串值。当在数组上使用时，匹配器验证该数组是否包含给定的字符串。

```
test('toMatch, () => {
    expect(['apples', 'oranges']).toContain('apples');
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toThrow  </samp>该匹配器验证一个函数是否抛出错误。被检查的函数需要一个包装函数，否则断言会失败。我们可以像 <samp class="SANS_TheSansMonoCd_W5Regular_11">toMatch</samp> 函数一样，传递一个字符串或正则表达式。

```
function functionThatThrows() {
    throw new Error();
}

test('toThrow', () => {
    expect(**()** **=>** **functionThatThrows()).toThrow()**;
}) 
```

### <samp class="SANS_Futura_Std_Bold_B_11">JEST-DOM 匹配器</samp>

*JEST-DOM* 包提供了与 DOM 直接交互的匹配器，允许我们轻松编写在 DOM 上运行断言的测试，例如检查元素的存在、HTML 内容、CSS 类或属性。

假设我们想要检查我们的 logo 元素是否具有类名 <samp class="SANS_TheSansMonoCd_W5Regular_11">center</samp>。我们可以使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">toHaveClass</samp> 匹配器，而不是手动检查元素的存在并使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">toMatch</samp> 检查它的类名属性，如 列表 C-1 所示。

```
<img data-testid="image"class="center full" alt="The Logo" src="logo.svg" />

test('toHaveClass', () => {
    const element = getByTestId('image');
    expect(element).toHaveClass('center');
}) 
```

列表 C-1：使用 DOM 进行测试的基本语法

首先，我们在图片元素中添加数据属性 <samp class="SANS_TheSansMonoCd_W5Regular_11">testid</samp>。然后，在测试中，我们使用这个 ID 获取元素，并将引用存储在常量中。最后，我们在元素的引用上使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">toHaveClass</samp> 匹配器，检查该元素的类名是否包含类 <samp class="SANS_TheSansMonoCd_W5Regular_11">center</samp>。

让我们来看看最常见的与 DOM 相关的匹配器。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">getByTestId  </samp>此匹配器允许我们直接访问一个 DOM 元素并存储对它的引用，然后我们可以使用自定义匹配器来对该元素进行断言。

```
<img **data-testid="image"** class="center full" alt="The Logo" src="logo.svg" />

test('toHaveClass', () => {
    const element = **getByTestId('image')**;
`--snip--`
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toBeInTheDocument  </samp>此匹配器验证一个元素是否已被添加到文档树中。该匹配器仅适用于当前属于 DOM 的元素，忽略被移除的元素。

```
<samp class="SANS_TheSansMonoCd_W5Regular_11"><img</samp> **data-testid="image"** <samp class="SANS_TheSansMonoCd_W5Regular_11">class="center full" alt="The Logo" src="logo.svg" /></samp>

test('toHaveClass', () => {
    const element = getByTestId('image');
    expect(element)**.toBeInTheDocument();**
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toContainElement  </samp>此匹配器测试我们关于元素子元素的假设，例如，它让我们验证一个元素是否是另一个元素的后代。

```
<div data-testid="parent">
    <img **data-testid="image"** class="center full" alt="The Logo" src="logo.svg" />
</div>

test('toHaveClass', () => {
    const parent = getByTestId('parent');
    const element = getByTestId('image');
    expect(parent)**.toContainElement(element);**
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toHaveAttribute  </samp>此匹配器允许我们对元素的属性进行断言，例如，图片的 <samp class="SANS_TheSansMonoCd_W5Regular_11">alt</samp> 属性，以及表单元素的 <samp class="SANS_TheSansMonoCd_W5Regular_11">checked</samp>、<samp class="SANS_TheSansMonoCd_W5Regular_11">disabled</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">error</samp> 状态。

```
<img data-testid="image" class="center full" **alt="The Logo"** src="logo.svg" />

test('toHaveClass', () => {
    const element = **getByTestId('image')**;
    expect(element).**toHaveAttribute('alt', 'The Logo')**;
}) 
```

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">toHaveClass</samp>  <code>toHaveClass</code> 匹配器是 <samp class="SANS_TheSansMonoCd_W5Regular_11">toHave Attribute</samp> 匹配器的特定变体。它允许我们明确地断言一个元素具有特定的类名，从而使我们能够编写干净的测试。

```
<img data-testid="image" **class**="**center** full" alt="The Logo" src="logo.svg" />

test('toHaveClass', () => {
    const element = **getByTestId('image')**;
    expect(element).**toHaveClass('center')**;
}) 
```

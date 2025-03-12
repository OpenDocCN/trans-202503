<hgroup>

## <samp class="SANS_Futura_Std_Bold_Condensed_B_11">A</samp> <samp class="SANS_Dogma_OT_Bold_B_11">类型脚本编译器选项</samp>

</hgroup>

![](img/Drop-image.jpg)

将这些选项中的任何一个传递给 *tsconfig.json* 文件的 <samp class="SANS_TheSansMonoCd_W5Regular_11">compilerOptions</samp> 字段，以配置 TSC 将 TypeScript 代码转译为 JavaScript 的过程。有关此过程的更多信息，请参见 第三章。

这里我们介绍了最常见的选项。您可以在官方文档中找到更多信息和完整的选项列表，链接为 [*https://<wbr>www<wbr>.typescriptlang<wbr>.org<wbr>/tsconfig*](https://www.typescriptlang.org/tsconfig)。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">allowJs  </samp>一个布尔值，指定项目是否可以导入 JavaScript 文件。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">baseUrl  </samp>一个字符串，用于定义用于解析模块路径的根目录。例如，如果将其设置为 <samp class="SANS_TheSansMonoCd_W5Regular_11">"./"</samp>，TypeScript 将从根目录解析文件导入。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">esModuleInterop  </samp>一个布尔值，指定 TypeScript 是否应无缝导入 CommonJS、AMD 或 UMD 模块，或者是否应将它们与 ES.Next 模块区分开来。通常，如果使用不支持 ES.Next 模块的第三方库，则需要此选项。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">forceConsistentCasingInFileNames  </samp>一个布尔值，指定文件导入是否区分大小写。这在一些开发者在区分大小写的文件系统上工作，而其他开发者则不区分时尤其重要，以确保文件加载行为对所有人一致。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">incremental  </samp>一个字符串，用于定义 TypeScript 编译器是否应保存上次编译的项目图，使用增量类型检查，并在连续运行时执行增量更新。这可以加速转译过程。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">isolatedModules  </samp>一个布尔值，指定 TypeScript 是否应对与第三方转译器（例如 Babel）不兼容的代码发出警告。引发这些警告的最常见原因是代码使用了不是模块的文件；例如，它们没有任何 <samp class="SANS_TheSansMonoCd_W5Regular_11">import</samp> 或 <samp class="SANS_TheSansMonoCd_W5Regular_11">export</samp> 语句。此值不会改变实际 JavaScript 的行为，它只是警告无法正确转译的代码。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">jsx  </samp> 一个字符串，指定 TypeScript 如何处理 JSX。它仅适用于 *.tsx* 文件以及 TypeScript 编译器如何输出这些文件。例如，默认值 <samp class="SANS_TheSansMonoCd_W5Regular_11">react</samp> 会使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">React .createElement</samp> 转换并输出代码，而 <samp class="SANS_TheSansMonoCd_W5Regular_11">preserver</samp> 则不会转换组件中的代码，直接输出未修改的代码。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">lib  </samp> 一个数组，通过 polyfill 添加缺失的特性。一般来说，*polyfill* 是一些代码片段，用来为目标环境不原生支持的特性和功能提供支持。当我们针对不完全兼容的系统时（如旧版本的浏览器或 Node 版本），需要模拟现代 JavaScript 特性。编译器将 <samp class="SANS_TheSansMonoCd_W5Regular_11">lib</samp> 数组中定义的 polyfill 添加到生成的代码中。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">module  </samp> 一个字符串，设置转译代码的模块语法。例如，如果将其设置为 <samp class="SANS_TheSansMonoCd_W5Regular_11">commonjs</samp>，TSC 将转译该项目，使用传统的 CommonJS 模块语法，采用 <samp class="SANS_TheSansMonoCd_W5Regular_11">require</samp> 来导入，使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">module.exports</samp> 来导出代码，而设置为 <samp class="SANS_TheSansMonoCd_W5Regular_11">ES2015</samp> 时，转译后的代码将使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">import</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">export</samp> 关键字。这与 <samp class="SANS_TheSansMonoCd_W5Regular_11">target</samp> 属性无关，后者定义了所有可用的语言特性，模块语法除外。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">moduleResolution  </samp> 一个字符串，指定模块解析策略。此策略还定义了 TSC 在编译时如何定位模块的定义文件。改变解析方式可以解决导入和导出模块时的一些边缘问题。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">noEmit  </samp> 一个布尔值，定义了 TSC 是否应该生成文件，或者仅检查项目中的类型。如果你希望像 webpack、Babel.js 或 Parcel 这样的第三方工具来转译代码，而不是 TSC，请将其设置为 <samp class="SANS_TheSansMonoCd_W5Regular_11">false</samp>。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">resolveJsonModule  </samp> 一个布尔值，指定 TypeScript 是否导入 JSON 文件。它会根据文件中的 JSON 生成类型定义，并在导入时验证类型。由于 TypeScript 默认不能导入 JSON 文件，因此我们需要手动启用 JSON 导入。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">skipLibCheck  </samp> 一个布尔值，用于定义 TypeScript 编译器是否对所有类型声明文件进行类型检查。将其设置为 <samp class="SANS_TheSansMonoCd_W5Regular_11">false</samp> 可以减少编译时间，并且是处理没有类型声明的第三方依赖项的解决办法。

<samp class="SANS_TheSansMonoCd_W7Bold_B_11">target  </samp> 一个字符串，用于指定 TypeScript 代码应该转译成的语言特性。例如，如果将其设置为 <samp class="SANS_TheSansMonoCd_W5Regular_11">es6</samp>，或等同的 <samp class="SANS_TheSansMonoCd_W5Regular_11">ES2015</samp>，TSC 将把该项目转译为与 ES2015 兼容的 JavaScript，例如使用 <samp class="SANS_TheSansMonoCd_W5Regular_11">let</samp> 和 <samp class="SANS_TheSansMonoCd_W5Regular_11">const</samp>。

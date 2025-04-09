## 5

## 精细化你的应用，加入菜单和设置

![Image](img/circle.jpg)

你已经写了一个有趣的 Android 应用，但它仍然缺少一些东西。你还没有学习如何在 Android 中构建设置或选项菜单，或者如何保存高分、游戏统计信息和其他数据。在本章中，我们将为我们的 Hi-Lo 猜数字游戏应用添加一个选项菜单，并添加存储信息的功能。

### 在 Android 中添加选项菜单

大多数应用和游戏都有用户可以通过菜单访问的选项或设置。对于 Hi-Lo 猜数字游戏，我们可能希望允许用户更改游戏的难度级别、重新开始、查看游戏统计信息或查看关于屏幕，所以我们将创建一个可以执行所有这些操作的菜单。

在 Android 中添加选项菜单的步骤有四个：

1\. 编辑应用的默认 XML 菜单文件，创建用户可以选择的选项项。

2\. 修改应用的活动文件，显示我们在上一步创建的菜单和选项。

3\. 创建一个事件处理程序，以确定用户何时选择一个选项。

4\. 编写代码以便用户选择每个选项时执行。

添加选项菜单不仅能让我们的应用看起来更专业，也能让用户对他们的游戏体验拥有更大的控制权。我的儿子们喜欢能够将猜数字游戏的范围从 1 到 10 改成 1 到 100，再到 1 到 1000，但当我们添加了显示游戏胜利次数的“游戏统计”选项时，我几乎无法把设备从他们手中拿回来——他们想不断地将数字增大！我希望你们能像他们一样觉得这些额外的功能既有趣（也许还有点上瘾）。

#### *向菜单的 XML 文件添加项*

在 Android Studio 中打开你的 Hi-Lo 猜数字游戏项目，在项目资源管理器窗格中，将左上角的视图更改为 **Android**。然后，通过展开 **app** ▸ **res** ▸ **menu**，并双击 *menu_main.xml* 打开默认菜单文件。

修改 *menu_main.xml* 文件中的 XML 代码，使其与以下内容相符：

<menu xmlns:android="http://schemas.android.com/apk/res/android">

<item

android:id="@+id/action_settings"

android:title="设置" />

<item

android:id="@+id/action_newgame"

android:title="新游戏" />

<item

android:id="@+id/action_gamestats"

android:title="游戏统计" />

<item

android:id="@+id/action_about"

android:title="关于" />

</menu>

`<menu>` 标签通过 Android XML 文档的 XML 命名空间创建一个菜单资源，该命名空间由统一资源标识符（URI） *http://schemas.android.com/apk/res/android* 标识。我们可以通过将 XML 标签与元素连接，使用 XML 存储或显示从网页到数据库的所有内容。此代码中的 `xmlns`（XML 命名空间）属性选择了主要的 Android 命名空间，以便该 XML 文件中的标签会引用 Android 应用中的通用元素。因此，`<menu>` 标签表示一个 Android 菜单，而每个 `<item>` 标签描述该菜单中的一个项或条目及其属性。这个菜单将包含四个选项：设置、新游戏、游戏统计和关于，因此我们添加了四个 `<item>` 标签。我们将这些名称分配给每个项的 `title` 属性，它决定了用户打开菜单时显示的文本。稍后我们将在代码中使用 `id` 属性来确定用户选择了哪个选项。

保存 *menu_main.xml* 文件。现在是时候在 Hi-Lo 猜数字游戏应用中显示我们的选项菜单了。

#### *显示选项菜单*

我们已经设置好了菜单，但为了显示它，我们需要在应用的 *MainActivity.java* 文件中添加一些 Java 代码。在 **app** ▸ **java** ▸ **com.*****yourdomain*****.GuessingGame** 下的项目资源管理器中打开 *MainActivity.java* 文件。

在 `MainActivity` 类的中部或底部，你应该能找到一个名为 `onCreateOptionsMenu()` 的方法。将它修改为以下代码片段。（如果你的代码中没有 `onCreateOptionsMenu()` 方法，在 `onCreate()` 的结束括号后但在 `MainActivity` 的最终结束括号前添加以下代码。）

public boolean onCreateOptionsMenu(Menu menu) {

MenuInflater inflater = getMenuInflater();

inflater.inflate(R.menu.menu_main, menu);

return true;

}

} // MainActivity.java 文件的最终结束括号

`onCreateOptionsMenu()` 方法正如其名称所示，它告诉 Android 在为我们的应用创建选项菜单时该做什么。在本例中，我们告诉 Android 我们希望扩展 *menu_main.xml* 文件，作为我们的选项菜单。*menu_main.xml* 文件尚未成为一个菜单，因此我们需要使用一个名为 `MenuInflater` 的类将其转换为菜单。我们将通过 `getMenuInflater()` 方法创建一个 `MenuInflater` 实例，命名为 `inflater`。得到 `inflater` 后，我们调用 `inflate()` 方法，并传入 XML 文件（`R.menu.menu_main`）和我们希望 XML 文件中的项填充到的菜单（`menu`）。在你将代码添加到文件时，可能需要按 ALT-ENTER（在 macOS 上是 OPTION-ENTER）来修复缺失的 `import` 语句。

做完这个更改后，保存并运行应用。Android 通过在应用的操作栏中显示三个点来告诉你有可用的选项菜单（见图 5-1，顶部）。点击这些点会显示选项菜单（见图 5-1，底部）。

![图片](img/f0112-01.jpg)

*图 5-1：选项菜单在应用的操作栏（顶部）显示为三个点。点击三个点将展开选项菜单（底部）。*

你会注意到，点击选项目前并没有任何反应，因为我们还没有添加代码来响应用户的选择。接下来，我们将添加这个代码。

#### *响应用户选择*

当用户从菜单中选择一个选项时，我们希望我们的应用执行所请求的操作。为了让应用做到这一点，我们需要添加一个事件处理方法来跟踪选择了哪个选项。我们将使用与每个项关联的`id`属性来区分不同的选择。

在*MainActivity.java*文件中，找到并修改`onOptionsItemSelected()`事件处理方法。或者，你也可以将其添加到我们在上一节中修改的`onCreateOptionsMenu()`方法下方，但要放在文件最后一行的闭括号之前。

public boolean onCreateOptionsMenu(Menu menu) {

MenuInflater inflater = getMenuInflater();

inflater.inflate(R.menu.menu_main, menu);

return true;

}

public boolean onOptionsItemSelected(MenuItem item) {

switch (item.getItemId()) {

case R.id.action_settings:

return true;

case R.id.action_newgame:

newGame();

return true;

case R.id.action_gamestats:

return true;

case R.id.action_about:

return true;

default:

return super.onOptionsItemSelected(item);

}

}

}

在这段代码中，我们使用`switch`语句来判断用户在菜单中选择了哪个选项。`switch`语句是测试多个条件的另一种方式，类似于一连串的`if-else`语句。不过，我们可以使用单一的`switch`语句，而不是通过四个`if-else`语句来测试每个可能的菜单项选择。我们将要测试的变量放在`switch`关键字后面的括号内。例如，我们正在检查用户选择的菜单项的`id`，因此我们使用`switch (item.getItemId())`。然后，在`switch`语句的括号内，我们列出我们要测试的值作为`case`语句（例如，`case R.id.action_settings`），每个`case`语句后跟一个冒号（`:`），执行该选择的代码，并跟着`break`或`return`语句。由于这个事件处理方法返回一个布尔值，所以我们在每个`case`块中使用`return`语句，而不是`break`语句。如果没有`return`语句，我们需要在每个`case`的最后使用`break`命令。

这段代码中的每个`case`语句测试的是我们在*menu_main.xml*文件中输入的项的一个`id`值，每个值的代码将在用户选择时执行。目前，我们只有`action_newgame`这个`case`的代码，它会使用`newGame()`方法开始一个新游戏。其他的`case`需要编写更多代码，所以我们会逐一定义它们。

#### *为关于页面创建一个警告对话框弹出框*

对于“关于”菜单选项，我们将弹出一个对话框，类似于你可能见过的其他应用程序中的对话框。为此，我们将使用*警告对话框*，这是一种灵活的弹出窗口，用于通知用户某些信息或提示他们做出回应。这种弹出窗口比我们在第四章（第 106 页上的编程挑战#1）中使用的 Toast 弹出窗口更具适应性，因为`AlertDialog`类允许我们通过`Builder`子类自定义对话框的属性。在这种情况下，我们将使用警告对话框来响应用户选择“关于”选项，弹出一条消息告诉他们是谁创建了他们正在玩的精彩的 Hi-Lo 猜数字游戏。

将以下代码添加到`action_about`项选择的`case`语句中：

case R.id.action_about:

➊ AlertDialog aboutDialog = new AlertDialog.Builder(MainActivity.this).create();

➋ aboutDialog.setTitle("关于猜数字游戏");

➌ aboutDialog.setMessage("(c)2018 你的名字。");

➍ aboutDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",

new DialogInterface.OnClickListener() {

public void onClick(DialogInterface dialog, int which) {

➎ dialog.dismiss();

}

});

➏ aboutDialog.show();     return true;

我们使用`AlertDialog.Builder`类 ➊ 来创建一个自定义的弹出窗口。➋ 处的代码将弹出窗口的标题设置为“关于猜数字游戏”，而 ➌ 处的代码显示一个简单的消息，包含版权信息和你的名字（当然你也可以在这里写任何你想写的文字）。`setButton()`方法 ➍ 向弹出窗口添加一个文本为`"OK"`的按钮，接下来的`onClick()`事件监听器会在用户点击`"OK"`按钮时调用`dismiss()`方法 ➎ 来关闭弹出窗口。最后，通过`show()`命令 ➏ 显示自定义的弹出窗口。

使用 ALT-ENTER（或 OPTION-ENTER）来导入`AlertDialog`类。然后保存更新后的代码并运行应用的新版本。当你点击选项菜单并选择“关于”选项时，应该会看到一个像图 5-2 那样的弹出窗口。

![图片](img/f0114-01.jpg)

*图 5-2：一个自定义的警告对话框弹出框*

Hi-Lo 猜数字游戏应用程序现在开始感觉更像是一个专业的安卓应用程序了！现在，让我们进一步完善它，让用户可以选择游戏的难度级别，并跟踪他们赢得了多少场游戏。

### 更改猜测范围

让用户选择猜测范围——比如从 1 到 10，从 1 到 100，或者从 1 到 1000——将是一个巨大的增强功能。既然你已经了解了选项菜单和警告对话框，接下来我们来规划一下如何升级游戏，让用户可以更改猜测范围设置。

首先，我们需要为范围添加一个变量，这样我们就不再使用硬编码的`100`，而是使用用户选择的范围。其次，我们需要以几种方式修改应用程序的行为。我们将更改`newGame()`方法来使用新的范围变量。我们还将使当前显示“`Enter a number between 1 and 100:`”的`TextView`根据选择的范围显示不同的提示。最后，我们需要让用户选择范围。我们将通过构建另一个自定义警告对话框来实现，提供三种范围选择：1 到 10、1 到 100 和 1 到 1,000。

#### *为范围添加一个变量*

首先，我们将用一个变量替换计算随机数时使用的硬编码值`100`。在`MainActivity`类的顶部，添加一个`range`变量并将其设置为默认值`100`：

public class MainActivity extends AppCompatActivity {

private EditText txtGuess;

private Button btnGuess;

private TextView lblOutput;

private int theNumber;

private int range = 100;

在我们添加变量的同时，我们还将为显示“`Enter a number between 1 and 100:`”的标签添加第二个`TextView`。当用户选择的范围不是 1 到 100 时，这个标签就不再正确，因此我们需要一个变量来存储要显示的适当文本。我们将创建一个名为`lblRange`的变量来实现这一点：

private int range = 100;

private TextView lblRange;

为了将 GUI 与`lblRange`变量连接起来，向代码中添加以下行：

`onCreate()`方法：

protected void onCreate(Bundle savedInstanceState) {

super.onCreate(savedInstanceState);

setContentView(R.layout.activity_main);

txtGuess = (EditText) findViewById(R.id.txtGuess);

btnGuess = (Button) findViewById(R.id.btnGuess);

lblOutput = (TextView) findViewById(R.id.lblOutput);

lblRange = (TextView) findViewById(R.id.textView2);

如果你遇到错误，请检查设计视图中提示框的`TextView`名称：打开**app** ▸ **res** ▸ **layout** ▸ ***content_main.xml***，然后点击显示“`Enter a number between 1 and 100:`”的标签。将标签的`id`属性更改为`textView2`。

配置好`range`和`lblRange`变量后，接下来我们需要修改应用程序的行为，使其使用这些变量而不是硬编码值。

#### *使用范围变量*

首先，让我们修改`newGame()`方法，使用`range`变量。我们还需要添加代码来更改提示信息，让用户知道正确的猜测范围：

public void newGame() {

theNumber = (int)(Math.random() * range + 1);

lblRange.setText("Enter a number between 1 and " + range + ".");

txtGuess.setText("" + range/2);

txtGuess.requestFocus();

txtGuess.selectAll();

}

除了使用`range`正确设置随机数外，我们还更改了`lblRange`提示，以便使用`range`变量。最后三行是一个小小的修饰——我已经自作主张在`txtGuess`文本框中输入了一个默认的起始值，即`range`的一半。因此，如果用户的猜测范围是 1 到 10，猜测文本框将显示 5 作为默认的第一次猜测；如果范围是 1,000，文本框将推荐 500 作为第一次猜测。

最后一个与范围相关的变化出现在`checkGuess()`方法中。我们添加了一个`try-catch`语句来处理无效的用户输入，在`catch`语句中，我们告诉用户输入一个有效的整数，范围为 1 到 100。现在让我们仅更改`catch`语句以反映用户选择的范围：

public void checkGuess() {

--snip--

}

} catch (Exception e) {

message = "请输入一个介于 1 和" + range + "之间的整数。";

} finally {

--snip--

}

}

现在，两个`TextView`标签将正确显示用户选择的范围。接下来是构建警告对话框，让用户选择他们游戏的难度级别。

#### *构建对话框以允许用户选择范围*

范围设置对话框应在用户选择菜单中的设置选项时，显示所有范围选项（1 到 10，1 到 100，1 到 1,000）。为了显示这些选项，我们将构建另一个自定义的警告对话框，但这个对话框会显示一个包含三个范围选项的列表视图。

首先，滚动回到你的`onOptionsItemSelected()`方法，并在`action_settings`的`case`语句内添加以下代码：

public boolean onOptionsItemSelected(MenuItem item) {

switch (item.getItemId()) {

case R.id.action_settings:

final CharSequence[] items = {"1 到 10", "1 到 100", "1 到 1000"};

AlertDialog.Builder builder = new AlertDialog.Builder(this);

builder.setTitle("选择范围：");

builder.setItems(items, null);

AlertDialog alert = builder.create();

alert.show();

return true;

这六行代码将显示一个带有三个猜测范围选项的警告对话框，但我们需要再添加一点代码来处理用户的选择。`builder.setItems()`方法将接受一个项目列表和一个事件监听器，以处理用户从列表中选择的选项。

如果用户选择第一个选项，我们需要将`range`变量的值更改为`10`，对于第二个和第三个选项，分别更改为`100`和`1000`。事件监听器的代码将放入`builder.setItems()`语句中：

case R.id.action_settings:

final CharSequence[] items = {"1 到 10", "1 到 100", "1 到 1000"};

AlertDialog.Builder builder = new AlertDialog.Builder(this);

builder.setTitle("选择范围：");

builder.setItems(items, new DialogInterface.OnClickListener() {

public void onClick(DialogInterface dialog, int item) {

switch(item) {

case 0:

range = 10;

newGame();

break;

case 1:

range = 100;

newGame();

break;

case 2:

range = 1000;

newGame();

break;

}

dialog.dismiss();

}

});

AlertDialog alert = builder.create();

alert.show();

return true;

请注意，在我们为每个选项设置新范围后，我们调用`newGame()`来生成该范围内的一个新的随机数，并将屏幕上的提示更改为反映新的范围。

保存文件并进行这些更改后，运行游戏以测试新的选项。从 1 到 10 改变范围并猜几轮，然后再回到 1 到 100，如果您敢的话，再试试 1 到 1000。

关闭应用并重新打开，您会注意到游戏在第二次运行时没有记住您首选的范围。应用也没有记住您在猜数字方面的超凡能力。如果应用能记住您的首选范围和赢得的游戏次数就好了......

### 存储用户偏好和游戏统计数据

记住用户偏好和游戏统计数据的关键是能够将*持久信息*保存到您的 Android 设备上。持久信息是指应用关闭后仍然保留在设备上的任何数据。在 Hi-Lo 猜数字游戏中，我们想要将用户的首选难度级别和他们赢得的游戏数量作为持久信息进行存储。

有三种方法可以将持久数据保存到您的 Android 设备上：存储共享偏好、保存文件和将数据保存到数据库中。*共享偏好*是一种对象类型，用于存储您的应用程序需要在下次使用时保存的相对较短的设置列表。它们被称为*共享*偏好，因为您可以在应用中的多个活动或屏幕之间共享这些设置，例如猜数字游戏中的选项菜单和主游戏屏幕。将文件保存到设备上对于需要存储大量数据的情况很有用，例如文本文件，而数据库对于像通讯录或联系人列表这样的应用是必需的。但对于猜数字游戏，我们只需要存储几个数字，因此我们将使用共享偏好。

#### *存储和检索用户首选的范围*

共享偏好以*键/值对*的形式存储，其中每个值都有一个关联的键，用于检索它。例如，您可以有一对像`"range"`和`"100"`，其中`"range"`是*键*，`"100"`是我们在该键下存储的*值*。让我们编写一个方法来将用户首选的范围存储到共享偏好中。

在您的*MainActivity.java*文件的底部，添加以下方法，它位于`onOptionsItemSelected()`方法之后，并紧接着关闭大括号之前：

default:

return super.onOptionsItemSelected(item);

}

}

public void storeRange(int newRange) {

SharedPreferences preferences =

PreferenceManager.getDefaultSharedPreferences(this);

SharedPreferences.Editor editor = preferences.edit();

editor.putInt("range", newRange);

editor.apply();

}

}

每个应用程序都已经有一个默认的共享首选项对象，你可以通过创建一个`SharedPreferences`对象来连接它。为此，访问默认对象可以通过调用`PreferenceManager`对象上的`getDefaultSharedPreferences()`来实现，`PreferenceManager`对象创建并维护共享首选项的列表。记得在使用时导入相关包，或者按 ALT-ENTER（或 OPTION-ENTER）。

要写入共享首选项，我们必须使用`Editor`对象，它允许我们编辑单独的共享首选项值。为了存储特定的键/值对，我们使用`put`方法，例如`putString`用于存储字符串值，`putInt`用于存储整数，`putFloat`用于存储浮动的十进制值，`putBoolean`用于存储真/假值，等等。每次用户选择一个新的范围时，我们将把`range`变量作为`newRange`传递给`storeRange()`方法。为了在`"range"`键下存储`newRange`，我们使用 editor.putInt("range", newRange);将用户的新范围值（10、100 或 1000）存储在共享首选项的键名`"range"`下。`apply()`方法告诉 Android 你已经完成修改共享首选项的值，并且可以应用这些更改。

现在我们可以将范围存储到共享首选项中，需要在`onOptionsItemSelected()`方法的事件监听器中为用户可以选择的每个`case`添加`storeRange()`函数：

public boolean onOptionsItemSelected(MenuItem item) {

switch (item.getItemId()) {

case R.id.action_settings:

final CharSequence[] items = {"1 到 10", "1 到 100", "1 到 1000"};

AlertDialog.Builder builder = new AlertDialog.Builder(this);

builder.setTitle("选择范围：");

builder.setItems(items, new DialogInterface.OnClickListener() {

public void onClick(DialogInterface dialog, int item) {

switch(item) {

case 0:

range = 10;

storeRange(10);

newGame();

break;

case 1:

range = 100;

storeRange(100);

newGame();

break;

case 2:

range = 1000;

storeRange(1000);

newGame();

break;

}

dialog.dismiss();

}

});

AlertDialog alert = builder.create();

alert.show();

return true;

最后，我们需要在游戏加载时检索范围，以便用户上次选择的范围将成为下次运行游戏时使用的范围。向上滚动到`onCreate()`方法，并添加以下两行代码来从共享首选项中检索范围：

protected void onCreate(Bundle savedInstanceState) {

super.onCreate(savedInstanceState);

setContentView(R.layout.activity_main);

txtGuess = (EditText) findViewById(R.id.txtGuess);

btnGuess = (Button) findViewById(R.id.btnGuess);

lblOutput = (TextView) findViewById(R.id.lblOutput);

lblRange = (TextView) findViewById(R.id.textView2);

SharedPreferences preferences =

PreferenceManager.getDefaultSharedPreferences(this);

range = preferences.getInt("range", 100);

newGame();

注意，我们在调用`newGame()`方法之前*先*检索了共享偏好设置，以确保每次应用程序重新启动时，用户能得到他们上次使用的范围。`getInt()`方法查找存储在键名`"range"`下的值，如果没有找到，则第二个参数会告诉它默认使用`100`。我们这样做是为了确保在用户第一次运行应用时，`range`有一个默认值。

保存文件，构建并运行。此次选择一个不同的范围，然后完全关闭应用程序。下次启动应用时，同样的范围会等着你！

#### *存储获胜次数*

高分、排行榜、连胜纪录——任何记录我们成就的东西，总会让我们想更加努力，玩得更久，打破记录。我们将给游戏添加的一个点睛之笔就是能够追踪获胜的游戏次数。同样，我们可以将这些统计数据轻松地存储为共享偏好设置。

当用户通过猜对数字赢得一局时，我们可以使用共享偏好设置来检索他们获胜的游戏次数，加`1`，并存储新的值。将这段代码添加到`checkGuess()`方法中，把它放到赢得游戏的`else`语句中：

public void checkGuess() {

String guessText = txtGuess.getText().toString();

String message = "";

try {

int guess = Integer.parseInt(guessText);

if (guess < theNumber)

message = guess + " 太低了。再试一次。";

else if (guess > theNumber)

message = guess + " 太高了。再试一次。";

else {

message = guess +

" 是正确的。你赢了！再玩一次吧！";

➊ SharedPreferences preferences =

PreferenceManager.getDefaultSharedPreferences(this);

➋ int gamesWon = preferences.getInt("gamesWon", 0) + 1;

➌ SharedPreferences.Editor editor = preferences.edit();

➍ editor.putInt("gamesWon", gamesWon);

➎ editor.apply();

newGame();

}

在这里，我们在➊访问了默认的`SharedPreferences`，在➋，我们检索了存储在键名`"gamesWon"`下的值（如果这是用户第一次获胜，默认为`0`），并加了`1`来记录这次获胜。在➌，我们创建了一个编辑器来写入新的共享偏好设置值。在➍，我们将整数值`gamesWon`存储到共享偏好设置中，使用相应的键名以便以后使用，并在➎告诉 Android 将更改写入设备。

这部分处理了存储获胜次数，但如何向用户展示这些统计数据呢？为此，我们需要在`onOptionsItemSelected()`方法中为`action_gamestats case`添加代码，如下所示：

case R.id.action_gamestats:

➊ SharedPreferences preferences =

PreferenceManager.getDefaultSharedPreferences(this);

➋ int gamesWon = preferences.getInt("gamesWon", 0);

➌ AlertDialog statDialog = new AlertDialog.Builder(MainActivity.this).create();

statDialog.setTitle("猜数字游戏统计");

➍ statDialog.setMessage("你已经赢得了 " + gamesWon + " 局。干得好！");

statDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "确定",

new DialogInterface.OnClickListener() {

public void onClick(DialogInterface dialog, int which) {

dialog.dismiss();

}

});

statDialog.show();

return true;

在➊，我们连接到应用的默认共享偏好设置，➋时，我们检索已赢得的游戏次数（如果这是程序的第一次运行，则给定默认值`0`）。在➌时，我们构建一个警告对话框，向用户显示他们赢得的游戏次数，➍时，我们显示该次数并附上鼓励的信息。

保存最后的更改，然后构建并运行你的应用。你最后的挑战可能是试图停止游戏！图 5-3 展示了如果你有一些数学天才在玩你的游戏时，游戏统计界面可能的样子。

![Images](img/f0121-01.jpg)

*图 5-3：游戏统计界面记录了你（或你的朋友）猜对数字的次数。*

添加选项菜单、保存游戏统计和用户偏好、显示警告对话框——这些就是能够让你的游戏或任何应用真正脱颖而出的终极修饰。继续根据你的想法改进应用，你将拥有一个值得与朋友们分享——或者与全世界分享——的应用。祝编码愉快！

### 你学到了什么

通过给 Hi-Lo 猜数字游戏应用添加一些最终修饰，你已经打造了一款专业质量的 Android 移动游戏，修饰包括：

• 向 Android 应用添加选项菜单

• 通过编辑菜单的 XML 文件设计选项菜单

• 使用`MenuInflater`显示选项菜单

• 响应用户在菜单中的选择

• 使用带有多个`case`语句的`switch`语句来替代冗长的`if-else`链

• 使用`AlertDialog`类在 Android 中创建自定义弹窗

• 使用`SharedPreferences`类存储共享偏好设置和应用统计信息

• 在应用启动时检索用户的共享偏好设置

### 编程挑战

尝试这些编程挑战练习，回顾和实践你所学的知识，并扩展你的编程技能。访问本书的官方网站 *[`www.nostarch.com/learnjava/`](https://www.nostarch.com/learnjava/)* 下载示例解决方案。

#### *#1: 有赢有输*

第四章的编程挑战#1（第 106 页）要求你给用户七次机会猜一个 1 到 100 之间的数字。现在你已经增加了更改范围的功能，您需要根据新的范围调整尝试次数。

在第四章你学到了我们可以使用二分查找策略来猜 1 到 100 之间的数字（每次猜剩余可能值的中间值），因为 2⁷，即 2 的七次方，等于 128。 这意味着每次使用二分查找方法，我们应该能在七次猜测中猜出 1 到 128 之间的数字。但是，若要猜 1 到 10 之间的数字，或是 1 到 1,000 之间的数字，我们需要多少次猜测呢？

为了计算所需的尝试次数，我们需要知道能将 2 提升到的最小指数，使得结果大于范围。例如，对于 1 到 10 之间的数字，2⁴ = 16，而 16 > 10，因此我们需要最多四次猜测；对于 1 到 1,000 之间的范围，2¹⁰ = 1,024，因此我们需要 10 次猜测。

要找到将一个数字提升到某个指数使其等于另一个数字的指数，你可以使用*对数*。对数通过给定一个数字和一个基数，来找到基数应提升到的指数，以得出给定的数字。Java 提供了一个`Math.log()`方法，接受一个数字并找到其以 10 为底的对数。当你将一个数字的对数除以另一个数字的对数时，结果就相当于用第二个数字作为基数计算第一个数字的对数。这意味着将`Math.log(range)`除以`Math.log(2)`，就能告诉你 2 的哪个指数能得到`range`。因为指数可以是小数，而你不希望用户得到一个非整数的猜测次数，比如`7.25`，所以你需要将结果向上舍入并强制转换为`int`类型。要找到每个范围所需猜测次数的指数，你可以使用表达式`(int)(Math.log(range)/Math.log(2)+1)`。

修改 Hi-Lo 猜数字游戏，使其最大猜测次数适应用户选择的范围，无论是在游戏开始时还是每当用户在选项菜单中选择新范围时。例如，你可以创建一个名为`maxTries`的变量，代替硬编码的数字`7`来测试用户是否已经用完了所有尝试次数。

#### *#2: 胜负比*

在完成编程挑战#1 后，修改 Hi-Lo 猜数字游戏应用程序，存储获胜和失败的游戏数量。修改游戏统计菜单代码，检索这两个数字，并显示获胜的游戏数量、总游戏数和获胜百分比（获胜游戏数除以总游戏数，再乘以 100）。图 5-4 展示了一个例子。

![图片](img/f0123-01.jpg)

*图 5-4：游戏统计界面，显示获胜游戏的百分比*

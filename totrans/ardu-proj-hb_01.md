![image](../images/f0001-01.jpg)

## PROJECT 0: GETTING STARTED

**BEFORE YOU START BUILDING WITH THE ARDUINO, THERE ARE A FEW THINGS YOU NEED TO KNOW AND DO. LET’S TAKE A LOOK AT THE HARDWARE AND SOFTWARE YOU’LL NEED FOR THIS BOOK AND HOW TO SET UP A WORKSTATION. YOU’LL THEN TEST OUT THE ARDUINO WITH A SIMPLE LED PROJECT AND GET STARTED WITH A FEW TECHNIQUES THAT WILL COME IN HANDY, LIKE SOLDERING AND DOWNLOADING USEFUL CODE LIBRARIES.**

### **HARDWARE**

First let’s look at the Arduino Uno board and a few pieces of hardware that you’ll use in almost every project.

#### **The Arduino Uno**

There are numerous types of Arduino boards available, but this book will exclusively use the most popular one—the Arduino Uno, shown in [Figure 0-1](ch00.xhtml#ch0fig1). The Arduino Uno is open source (meaning its designs may be freely copied), so in addition to the official board, which costs about $25, you’ll find numerous compatible clone boards for around $15.

Let’s walk through the different elements of the Arduino Uno.

**FIGURE 0-1:**
The Arduino Uno board

![image](../images/f00-01.jpg)

The Arduino controls components you attach to it, like motors or LEDs, by sending information to them as *output* (information sent *out* from the Arduino). Data that the Arduino reads from a sensor is *input* (information going *in* to the Arduino). There are 14 digital input/output pins (pins 0–13). Each can be set to either input or output, and [Appendix B](app02.xhtml#app02) has a full pin reference table.

#### **Power**

The Arduino Uno board is powered from your computer’s USB port when you connect it to your PC to upload a program. When the Arduino is not linked to your PC, you can run it independently by connecting a 9-volt AC adapter or 9-volt battery pack with a 2.1 mm jack, with the center pin connected to the positive wire, shown in [Figure 0-2](ch00.xhtml#ch0fig2). Simply insert the jack into the power socket of the Arduino.

**FIGURE 0-2:**
A 9-volt battery pack, which you can plug into the Arduino to give it power

![image](../images/f00-02.jpg)

#### **Breadboards**

A *breadboard* acts as a construction base for electronics prototyping. All of the projects in this book use a breadboard instead of soldering.

The word *breadboard* dates back to when electronics projects were created on wooden boards. Nails were hammered into the wood and wires wrapped around them to connect components without the use of solder. Today’s breadboards, such as the one shown in [Figure 0-3](ch00.xhtml#ch0fig3), are made of plastic with predrilled holes (called *tie points*) into which you insert components or wires that are held in place by clips. The holes are connected by strips of conductive material that run underneath the board.

**FIGURE 0-3:**
Breadboard connections

![image](../images/f00-03.jpg)

Breadboards come in various sizes. To build the projects in this book, you’ll need four breadboards: two full-size, typically with 830 holes; one half-size with 420 holes; and one mini with 170 holes. The full-size breadboard is ideal for projects that use an LCD screen or a lot of components, and the half-size and mini boards are best for smaller projects. I recommend that for the projects in this book you buy breadboards that look like the one shown in [Figure 0-3](ch00.xhtml#ch0fig3), with red and blue lines and a center break between the holes.

**TIP**

*It’s conventional to use red wires for connections to 5V and black wires for connections to ground (GND), so you can easily tell which is which. The rest of the wires can be your choice of color.*

The main board area has 30 columns of tie points that are connected vertically, as shown in [Figure 0-3](ch00.xhtml#ch0fig3). There is a break in the center of the board, which you’ll often have to straddle with components to make your circuit. This break helps to connect the pins individually so they are not shorted together unintentionally, which can doom your project and even damage your components.

The blue and red lines at the top and bottom are *power rails* that you use to power the components inserted in the main breadboard area (see [Figure 0-4](ch00.xhtml#ch0fig4)). The power rails connect all the holes in the rail horizontally; the red lines are for positive power and the blue lines for negative power (or *ground*, as you’ll often see it referred to).

**FIGURE 0-4:**
Positive and negative breadboard rails

![image](../images/f00-04.jpg)

#### **Jumper Wires**

You’ll use *jumper wires* to make connections on the breadboard. Jumper wires are solid-core wires with a molded plastic holder on each end that makes it easier to insert and remove the wires. (You could use your own wire if you have it, but make sure to use solid-core wire, as stranded wire is not strong enough to push into the hole clips.)

When you insert a jumper wire into a breadboard hole, it’s held in place beneath the board by a small spring clip, making an electrical connection in that row that typically consists of five holes. You can then place a component in an adjoining hole to help create a circuit, as shown in [Figure 0-5](ch00.xhtml#ch0fig5).

**FIGURE 0-5:**
An example breadboard circuit

![image](../images/f00-05.jpg)

### **PROGRAMMING THE ARDUINO**

To make our projects do what we want, we need to write programs that give the Arduino instructions. We do so using a tool called the Arduino *integrated development environment (IDE)*. The Arduino IDE is free to download from *[http://www.arduino.cc/](http://www.arduino.cc/)*, and will run on Windows, OS X, and Linux. It enables you to write computer programs (a set of step-by-step instructions, known as *sketches* in the Arduino world) that you then upload to the Arduino using a USB cable. Your Arduino will carry out the instructions based on its interaction with the outside world.

**NOTE**

*Because the IDE versions can change fairly quickly, I won’t take you through installing them, but you should find installation straightforward. All versions of the IDE and full details of how to install for your operating system are available online at* [http://www.arduino.cc/](http://www.arduino.cc/).

#### **The IDE Interface**

When you open the Arduino IDE, it should look very similar to [Figure 0-6](ch00.xhtml#ch0fig6).

The IDE is divided into a toolbar at the top, with buttons for the most commonly used functions; the code or sketch window in the center, where you’ll write or view your programs; and the Serial Output window at the bottom. The Serial Output window displays communication messages between your PC and the Arduino, and will also list any errors if your sketch doesn’t compile properly.

**FIGURE 0-6:**
The Arduino IDE

![image](../images/f00-06.jpg)

#### **Arduino Sketches**

I’ll give you the sketch for each project within the relevant project, and talk through it there. All of the sketches are available to download from *[http://www.nostarch.com/arduinohandbook/](http://www.nostarch.com/arduinohandbook/)*.

Like any program, sketches are a very strict set of instructions, and very sensitive to errors. To make sure you’ve copied the sketch correctly, press the green check mark at the top of the screen. This is the Verify button, and it checks for mistakes and tells you in the Serial Output window whether the sketch has compiled correctly. If you get stuck, you can always download the sketch and then copy and paste it into the IDE.

#### **Libraries**

In the Arduino world, a *library* is a small piece of code that carries out a specific function. Rather than enter this same code repeatedly in your sketches, you can add a command that borrows code from the library. This shortcut saves time and makes it easy for you to connect to items such as a sensor, display, or module.

The Arduino IDE includes a number of built-in libraries—such as the LiquidCrystal library, which makes it easy to talk to LCD displays—and there are many more available online. To create the projects in the book, you will need to import the following libraries: RFID, Tone, Pitches, Keypad, Password, Ultrasonic, NewPing, IRRemote, and DHT. You’ll find all of the libraries you need at *[http://www.nostarch.com/arduinohandbook/](http://www.nostarch.com/arduinohandbook/)*.

Once you’ve downloaded the libraries, you’ll need to install them. To install a library in Arduino version 1.0.6 and higher, follow these steps:

1.  Choose **Sketch ![image](../images/arrow.jpg) Include Library ![image](../images/arrow.jpg) Add .ZIP Library**.

2.  Browse to the ZIP file you downloaded and select it. For older versions of Arduino, you’ll need to unzip the library file and then put the whole folder and its contents into the *sketchbook/libraries* folder on Linux, *My Documents\Arduino\Libraries* on Windows, or *Documents/Arduino/libraries* on OS X.

To install a library manually, go to the ZIP file containing the library and uncompress it. For example, if you were installing a library called *keypad* in a compressed file called *keypad.zip*, you would uncompress *keypad.zip*, which would expand into a folder called *keypad*, which in turn contains files like *keypad.cpp* and *keypad.h*. Once the ZIP file was expanded, you would drag the *keypad* folder into the *libraries* folder on your operating system: *sketchbook/libraries* in Linux, *My Documents\Arduino\Libraries* on Windows, and *Documents/Arduino/libraries* on OS X. Then restart the Arduino application.

Libraries are listed at the start of a sketch and are easily identified because they begin with the command `#include`. Libraries are surrounded by angle brackets, `<>`, and end with `.h`, as in the following call to the Servo library:

```
#include <Servo.h>
```

Go ahead and install the libraries you’ll need for the projects now to save yourself a bit of time later.

### **TESTING YOUR ARDUINO: BLINKING AN LED**

Now that you’ve seen the hardware and software, let’s begin our tour with the classic first Arduino project: blinking a *light emitting diode (LED)*. Not only is this the simplest way to make sure that your Arduino is working correctly, but it will also introduce you to a simple sketch. As I mentioned earlier, a sketch is just a series of instructions that run on a computer. The Arduino can hold only one sketch at a time, so once you upload your sketch to your Arduino, that sketch will run every time the Arduino is switched on until you upload a new one.

For this project we’ll use the *Blink* example sketch that comes with the Arduino IDE. This program turns on an LED for 1 second and then off for 1 second, repeatedly. An LED emits light when a small current is passed through it. The LED will work only with current flowing in one direction, so the longer wire must connect to a positive power connection. LEDs also require a current limiting resistor; otherwise, they may burn out. There is a built-in resistor inline with pin 13 of the Arduino.

Follow these steps to set up your test:

1.  Insert the long positive leg (also known as +5V or *anode*) of the LED into pin 13 on the Arduino, as shown in [Figure 0-7](ch00.xhtml#ch0fig7). Connect the short negative leg (also known as *cathode*) to the GND pin next to pin 13.

    **FIGURE 0-7:**
    The *Blink* project setup

    ![image](../images/f00-07.jpg)
2.  Connect the Arduino to your computer with the USB cable.

3.  Enter the following sketch into the IDE.

    ```
    ➊ // Blinking LED Project
    ➋ int led = 13;
    ➌ void setup() {
    ➍   pinMode(led, OUTPUT);
       }
    ➎ void loop() {
    ➏   digitalWrite(led, HIGH);
    ➐   delay(1000);
    ➑   digitalWrite(led, LOW);
    ➒   delay(1000);
    ➓ }
    ```

4.  Click the **Verify** button (which looks like a check mark) to confirm that the sketch is working correctly.

5.  Now click the **Upload** button to send the sketch to your Arduino.

#### **Understanding the Sketch**

Here’s what’s happening on each line of the sketch:

➊ This is a comment. Any line in your program starting with `//` is meant to be read by the user only, and is ignored by the Arduino, so use this technique to enter notes and describe your code (called *commenting* your code). If a comment extends beyond one line, start the first line with `/*` and end the comment with `*/`. Everything in between will be ignored by the Arduino.

➋ This gives pin 13 the name `led`. Every mention of `led` in the sketch refers to pin 13.

➌ This means that the code between the curly brackets, `{}`, that follow this statement will run once when the program starts. The open curly bracket, `{`, begins the setup code.

➍ This tells the Arduino that pin 13 is an output pin, indicating that we want to send power to the LED. The close curly bracket, `}`, ends the setup code.

➎ This creates a loop. Everything between the curly brackets, `{}`, after the `loop()` statement will run once the Arduino is powered on and then repeat until it is powered off.

➏ This tells the Arduino to set `led` (pin 13) to `HIGH`, which sends power to that pin. Think of it as switching the pin on. In this sketch, this turns on the LED.

➐ This tells the Arduino to wait for 1 second. Time on the Arduino is measured in milliseconds, so 1 second = 1,000 milliseconds.

➑ This tells the Arduino to set `led` (pin 13) to `LOW`, which removes power and switches off the pin. This turns off the LED.

➒ Again the Arduino is told to wait for 1 second.

➓ This closing curly bracket ends the loop. All code that comes after the initial `setup` must be enclosed within curly brackets. A common cause of errors in a sketch is missing open or close brackets, which will prevent your sketch from compiling correctly. After this curly bracket, the sketch goes back to the start of the loop at ➎.

Running this code should make your LED flash on and off. Now that you’ve tested your Arduino and understand how a sketch works and how to upload it, we’ll take a look next at the components you’ll need to carry out all of the projects in this book. [Appendix A](app01.xhtml#app01) has more details about each component, what it looks like, and what it does.

### **PROJECT COMPONENT LIST**

This is a complete list of the items you’ll need in order to complete the projects in this book. The most important part, of course, is the Arduino board itself—all projects use the Arduino Uno R3 version. As mentioned earlier, only the official boards are named Arduino, but clone boards compatible with the software can be bought from companies like SlicMicro, Sainsmart, and Adafruit and will be referred to as Uno R3 or Arduino Uno R3 compatible. (You’ll find a list of official suppliers at *[http://arduino.cc/en/Main/Buy/](http://arduino.cc/en/Main/Buy/)*.)

Each project will list the required items first, so if you want to complete only a few of the projects, you can flip to a project that appeals to you and obtain just those components. Although you can buy each item individually, I suggest buying an electronics hobby starter kit or Arduino kit. You’ll find many of them online, and there is a list of suggested suppliers in [Appendix A](app01.xhtml#app01). The components marked with an asterisk (*) can all be found in an Arduino Bare Bones Kit, which can save you a bit of time and money.

1 Arduino Uno R3 (or compatible alternative)

1 9V battery pack with 2.1 mm jack

2 full-size breadboards

1 half-size breadboard

1 mini breadboard

50 male-to-male jumper wires

10 female-to-male jumper wires

30 220-ohm resistors

10 330-ohm resistors

1 470-ohm resistor

1 10k-ohm resistor

1 1M-ohm resistor

40 5 mm LEDs: red, green, yellow, blue (10 of each color)

1 50k-ohm potentiometer

4 momentary tactile four-pin pushbuttons

1 HL-69 hygrometer soil moisture sensor

1 piezo buzzer

1 3.5 mm phone jack

2 Tower Pro SG90 9g servomotors

1 photoresistor (also known as a light resistor, or LDR)

1 analog five-pin, two-axis joystick module

1 pan-and-tilt housing module

1 four-pin HC-SR04 ultrasonic range sensor

1 4×4 membrane keypad

1 seven-segment LED display

1 four-digit, seven-segment serial display

1 DHT11 humidity sensor

1 16x2 LCD screen (Hitachi HD44780 compatible)

1 tilt ball switch

1 8×8 RGB LED matrix

1 38 kHz infrared (IR) sensor

1 HC SR501 PIR (passive infrared) sensor

1 Mifare RFID RC-522 reader, card, and fob

4 74HC595 shift registers

1 low-powered laser-pointer pen

1 WLToys RC V959 missile launcher

1 ATMEL ATmega328p chip*

1 16 MHz crystal oscillator (HC-495)*

1 L7805cv 5V regulator*

2 100 μF electrolytic capacitors*

1 PP3 9V battery clip*

2 22 pF disc capacitors*

9V battery*

### **SETTING UP YOUR WORKSPACE**

To get the most out of working with the Arduino, you should create a workspace that allows you to let your imagination loose but keeps you organized at the same time. If possible, it should also be a dedicated space, something like the one shown in [Figure 0-8](ch00.xhtml#ch0fig8); some projects can take a few hours to put together, so you may not have time to finish them all in one sitting, and there is nothing worse than having to stop and put everything away only to get it all out again next time.

**FIGURE 0-8:**
An example workspace

![image](../images/f00-08.jpg)

A workspace can be anywhere, but the main thing you will need is a table or flat surface big enough for your computer or laptop (so you can use the IDE and upload programs easily) and for you to actually do your building.

You may also want space to keep your components at hand as well as any tools you may need, such as a soldering iron, wire strippers, hobby knife, hobby drill, and so on. It may not be practical to have all of your tools and materials out all of the time, so it’s a good idea to buy some hobby or craft cases to store your parts. I use one bin for equipment, like soldering irons or wire cutters, and smaller bins for components. Plastic boxes for fishing tackle or craft use are perfect for storing components (see [Figure 0-9](ch00.xhtml#ch0fig9)), and a cantilever toolbox is great to house your soldering iron and other small equipment ([Figure 0-10](ch00.xhtml#ch0fig10)). Small plastic boxes, usually designed to store jewelry or craft supplies, are also a good way to store very small components ([Figure 0-11](ch00.xhtml#ch0fig11)).

**FIGURE 0-9:**
Tackle or craft boxes are handy for storing components.

![image](../images/f00-09.jpg)

**FIGURE 0-10:**
A cantilever toolbox works well for storing a soldering iron and other small tools.

![image](../images/f00-10.jpg)

**FIGURE 0-11:**
Plastic jewelry boxes are perfect for organizing very small items.

![image](../images/f00-11.jpg)

Consider buying a ledger-sized cutting mat to use as a defined and *nonconductive* workspace (one that doesn’t pass electricity), so you won’t run the risk of short-circuiting your sensitive electronics.

### **EQUIPMENT AND TOOL GUIDE**

While they’re not necessarily required for the projects in this book, here are some of the more useful pieces of equipment that you may consider buying when setting up a workspace.

• Helping hands—useful for holding items

![image](../images/f0015-01.jpg)

• Ledger-sized, nonconductive cutting mat

![image](../images/f0015-02.jpg)

• Needle-nose pliers

![image](../images/f0015-03.jpg)

• Wire cutters

![image](../images/f0016-01.jpg)

• 30-watt soldering iron and solder (see the “[Quick Soldering Guide](ch00.xhtml#ch00lev1sec07)” on [page 18](ch00.xhtml#page_18))

• Solder sucker to suck up solder!

![image](../images/f0016-02.jpg)

• Wire stripper—especially useful for making jumper wires

![image](../images/f0016-03.jpg)

• USB A-to-B cable for use with your Arduino

![image](../images/f0016-04.jpg)

• Digital multimeter

![image](../images/f0017-01.jpg)

• Screwdriver

![image](../images/f0017-02.jpg)

• Rotary tool and attachments

![image](../images/f0017-03.jpg)

• Glue gun

![image](../images/f0017-04.jpg)

### **QUICK SOLDERING GUIDE**

A few of the components you’ll need may come without their header pins ([Figure 0-12](ch00.xhtml#ch0fig12)) attached for ease of transport, and you’ll need to solder them in place. Header pins are rows of pins you attach to a component so you can make connections with jumper wires or insert into a breadboard. They come in strips that can be easily snapped to the size needed, and they are usually inserted into holes on the component designed for them.

**FIGURE 0-12:**
Header pins

![image](../images/f00-12.jpg)

The RFID module used in [Project 23](ch23.xhtml#ch23), for example, doesn’t come with the pins attached, so I’ll demonstrate how to solder those in place now as a quick guide to soldering. If you want something more in-depth, there’s a handy cartoon soldering guide at *[https://mightyohm.com/files/soldercomic/FullSolderComic_EN.pdf](https://mightyohm.com/files/soldercomic/FullSolderComic_EN.pdf)*.

First you will need a soldering iron ([Figure 0-13](ch00.xhtml#ch0fig13)). A general-purpose, 30-watt soldering iron with a fine tip should meet your needs. It’s worthwhile to buy a kit that includes a soldering iron, stand, and solder.

**FIGURE 0-13:**
Soldering iron and solder wire

![image](../images/f00-13.jpg)

To solder, you heat the area you want to solder with the soldering iron—for example, the place where the pin and the component meet—and then apply the soldering wire to the heated area; the wire quickly melts, and when it resets, it should create a clean connection between the two items you soldered. Here’s a demonstration.

1.  Plug in your soldering iron and wait at least five minutes for it to reach operating temperature.

2.  Break off the right number of header pins for your component. For the RFID module in [Project 23](ch23.xhtml#ch23), we need a row of eight pins. Insert them into the module as shown in [Figure 0-14](ch00.xhtml#ch0fig14).

    **FIGURE 0-14:**
    Insert the header pins into the module.

    ![image](../images/f00-14.jpg)

    **NOTE**

    *You do not apply solder directly to the iron, only to the joint you are soldering.*

3.  Now we will solder the pins in place. Start with the leftmost pin. Hold the heated tip of the soldering iron to the pin and module at the same time. You only need to hold it there for about two seconds. While holding the iron in place, add solder to the area; the solder should melt and create a joint.

4.  Quickly remove both the iron and solder—more than a couple of seconds could damage your components. Wait for the joint to cool.

A good solder joint should be like a shiny cone ([Figure 0-15](ch00.xhtml#ch0fig15)). With a little bit of practice, you will be able to solder in no time at all.

**FIGURE 0-15:**
Solder joints should look like this.

![image](../images/f00-15.jpg)

#### **Safety First**

Soldering irons get very, very hot and should be used with extreme care and not used by unsupervised children. Here are a few safety tips:

• Be sure to use a stand and never lay a hot soldering iron down on a table.

• Solder in a well-ventilated room. The fumes released from melting solder can be harmful.

• Keep flammable materials away from your work area.

• Keep equipment out of reach of children.

• Wear eye protection.

• Wait for a soldering iron to cool down completely before storing it.
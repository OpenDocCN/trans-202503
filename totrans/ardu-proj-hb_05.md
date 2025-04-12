# **PART 4**
![image](../images/common-01.jpg)
**LCDS**

## PROJECT 12: LCD SCREEN WRITER

**NOT ONLY IS THERE SOMETHING VERY SATISFYING ABOUT HAVING AN LCD SCREEN DISPLAY YOUR OWN MESSAGES, BUT IT’S ALSO VERY USEFUL.**

![image](../images/f0102-01.jpg)![image](../images/f0103-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 16×2 LCD screen (Hitachi HD44780 compatible)

• 50k-ohm potentiometer

**LIBRARIES REQUIRED**

• LiquidCrystal

### **HOW IT WORKS**

An LCD (liquid crystal display) screen is made of two sheets of polarizing material with a liquid crystal solution between them. Current passing through the solution creates an image or, in this case, characters. For this project, you’ll need an LCD screen that’s compatible with the Hitachi HD44780 driver for it to work with the Arduino—there are lots of them out there and you can usually identify them by their 16-pin interface.

We’ll use the LiquidCrystal library to send characters to the LCD screen. The LiquidCrystal library maps the characters and uses the `print.lcd` commands to copy the message from the sketch to the screen.

Before you start, you need to prepare your LCD screen.

### **PREPARING THE LCD SCREEN**

The LCD screen will probably require a bit of assembly. Your screen should come with 16 holes (as shown in [Figure 12-1](ch12.xhtml#ch12fig1)) and a separate strip of header pins.

**FIGURE 12-1:**
The LCD screen has 16 pins running along the top.

![image](../images/f12-01.jpg)

Take the strip of pins and break off a row of 16 pins. Insert the shorter side of the pins into the 16 LCD holes. You’ll need to solder these in place: solder the far-right and far-left pins first to hold the strip in place and wait a moment for them to set. Then solder each pin in turn, holding the solder and soldering iron to each pin. Holding the iron to the pins for too long will damage them; you only need to solder them for a couple of seconds. (If you’ve never soldered before, see the “[Quick Soldering Guide](ch00.xhtml#ch00lev1sec07)” on [page 18](ch00.xhtml#page_18).)

### **THE BUILD**

1.  Place your LCD screen in the breadboard, inserting the header pins into the breadboard holes. Also place the potentiometer in the breadboard, and use the breadboard and jumper wires to connect your LCD screen, Arduino, and potentiometer as shown in the following table and in [Figure 12-2](ch12.xhtml#ch12fig2). There are three GND connections from the LCD module, so use the breadboard GND rail to make those connections.

    **FIGURE 12-2:**
    Connections between the LCD screen and the Arduino. LCD screen pins 15 and 16 are the power and ground for the backlight of the screen.

    ![image](../images/f12-02.jpg)

    | **LCD SCREEN** | **ARDUINO** |
    | --- | --- |
    | 1 VSS | GND |
    | 2 VDD | +5V |
    | 3 VO contrast | Potentiometer center pin |
    | 4 RS | Pin 7 |
    | 5 R/W | GND |
    | 6 Enable | Pin 8 |
    | 7 D0 | Not used |
    | 8 D1 | Not used |
    | 9 D2 | Not used |
    | 10 D3 | Not used |
    | 11 D4 | Pin 9 |
    | 12 D5 | Pin 10 |
    | 13 D6 | Pin 11 |
    | 14 D7 | Pin 12 |
    | 15 A BcL+ | +5V |
    | 16 K BcL– | GND |

2.  The center pin of the 50k-ohm potentiometer is connected to LCD pin 3 (VO). The potentiometer controls the screen contrast. Turn it until you can clearly see the characters on the screen. Now connect one of the outer pins to GND and the other to +5V.

3.  Backlit LCD screens (see [Figure 12-3](ch12.xhtml#ch12fig3)) will have resistors built in, but if you have a non-backlit LCD screen, you should insert a 220-ohm resistor between LCD 15 and +5V. (The screen’s packaging will say whether it is backlit or not.)

    **FIGURE 12-3:**
    A backlit LCD screen

    ![image](../images/f12-03.jpg)
4.  Your setup should look like [Figure 12-4](ch12.xhtml#ch12fig4). Check your work against the circuit diagram in [Figure 12-5](ch12.xhtml#ch12fig5), and then upload the code in “[The Sketch](ch12.xhtml#ch12lev1sec04)” on [page 107](ch12.xhtml#page_107).

    **FIGURE 12-4:**
    The complete setup

    ![image](../images/f12-04.jpg)

    **FIGURE 12-5:**
    The circuit diagram for the LCD screen writer

    ![image](../images/f12-05.jpg)

### **THE SKETCH**

This sketch is included in your IDE examples. Load it from the IDE by going to **File ![image](../images/arrow.jpg) Examples ![image](../images/arrow.jpg) LiquidCrystal** and then clicking **Scroll**. The sketch uses the LiquidCrystal library that’s built into the Arduino IDE to send messages from the Arduino to the LCD screen. You can change the message by replacing `"Arduino Sketch"` at ➋.

To use this circuit setup with the example sketches in the Arduino IDE, we also change the LCD pins in the sketch (12, 11, 5, 4, 3, 2) at ➊ to 7, 8, 9, 10, 11, 12, as these are the pins we’ve assigned. I’ve re-created the sketch here as you’ll see it in the IDE, but with those changes made.

```
   /*
   Library originally added 18 Apr 2008 by David A. Mellis
     library modified 5 Jul 2009 by Limor Fried (http://www.ladyada.net)
     example added 9 Jul 2009 by Tom Igoe
     modified 22 Nov 2010 by Tom Igoe
     This example code is in the public domain.
     http://www.arduino.cc/en/Tutorial/LiquidCrystal

   LiquidCrystal Library - scrollDisplayLeft() and scrollDisplayRight()

   Demonstrates the use of a 16x2 LCD display. The LiquidCrystal
   library works with all LCD displays that are compatible with the
   Hitachi HD44780 driver. There are many of them out there, and you
   can usually tell them by the 16-pin interface.

   This sketch prints "Arduino Sketch" to the LCD and uses the
   scrollDisplayLeft() and scrollDisplayRight() methods to scroll
   the text.
   */

   // Include the library code
   #include <LiquidCrystal.h>

   // Initialize the library with the numbers of the interface pins
➊ LiquidCrystal lcd(7, 8, 9, 10, 11, 12);

   void setup() {
     // Set up the LCD's number of columns and rows
     lcd.begin(16, 2);
     // Print a message to the LCD
➋   lcd.print("Arduino Sketch");
     delay(1000);
   }

   void loop() {
     // Scroll 13 positions (string length) to the left
     // to move it offscreen left
     for (int positionCounter = 0; positionCounter < 13;
   positionCounter++) {
       // Scroll one position left
       lcd.scrollDisplayLeft();
       // Wait a bit
       delay(150);
     }
     // Scroll 29 positions (string length + display length) to the right
     // to move it offscreen right
     for (int positionCounter = 0; positionCounter < 29;
   positionCounter++) {
       // Scroll one position right
       lcd.scrollDisplayRight();
       // Wait a bit
       delay(150);
     }
     // Scroll 16 positions (display length + string length) to the left
     // to move it back to center
     for (int positionCounter = 0; positionCounter < 16;
   positionCounter++) {
       // Scroll one position left
       lcd.scrollDisplayLeft();
       // Wait a bit
       delay(150);
     }
     // Delay at the end of the full loop
     delay(1000);
   }
```

## PROJECT 13: WEATHER STATION

**IN THIS PROJECT YOU’LL SET UP A WEATHER STATION TO MEASURE TEMPERATURE AND HUMIDITY, AND DISPLAY THE VALUES ON AN LCD SCREEN.**

![image](../images/f0110-01.jpg)![image](../images/f0111-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 50k-ohm potentiometer

• 16x2 LCD screen (Hitachi HD44780 compatible)

• DHT11 humidity sensor

**LIBRARIES REQUIRED**

• LiquidCrystal

• DHT

### **HOW IT WORKS**

The humidity sensor used in this project is the relatively cheap DHT11, shown in [Figure 13-1](ch13.xhtml#ch13fig1), which measures both humidity and temperature. It uses a capacitive humidity sensor and resistive-type temperature sensor to take a reading from its environment. It sends this reading to the Arduino as voltage, and the Arduino converts this to readable values displayed on the screen. For best results, you should mount your sensor on an outside wall with a decent amount of open space. You’ll want to mount your LCD screen indoors or seal it carefully in a clear, waterproof bag or casing to keep it protected from the elements.

**FIGURE 13-1:**
The DHT11 measures both temperature and humidity.

![image](../images/f13-01.jpg)

The DHT11 comes with either four pins or three pins. The sensor shown in [Figure 13-1](ch13.xhtml#ch13fig1) has four pins, but you can use either version for this project, because you won’t be using pin 3\. Check the retailers at the beginning of the book for ideas on where to buy a DHT11.

### **THE BUILD**

1.  First, prepare the LCD screen as per the soldering instructions in “[Preparing the LCD Screen](ch12.xhtml#ch12lev1sec02)” on [page 104](ch12.xhtml#page_104). Insert the DHT11 sensor into your breadboard. The DHT11 pins are numbered 1 to 4 (or 3) from the left, when the front is facing you. Connect pin 1 to the +5V rail, connect pin 2 directly to Arduino pin 8, and connect pin 4 (or 3) to GND.

    | **DHT11** | **ARDUINO** |
    | --- | --- |
    | Pin 1 | +5V |
    | Pin 2 | Pin 8 |
    | Pin 3 | Not used |
    | Pin 4 | GND |

2.  Insert the LCD screen into the breadboard and connect the pins to the Arduino as shown in the following table and in [Figure 13-2](ch13.xhtml#ch13fig2). The GND and +5V rails will have multiple connections.

    | **LCD SCREEN** | **ARDUINO** |
    | --- | --- |
    | 1 VSS | GND |
    | 2 VDD | +5V |
    | 3 VO contrast | Potentiometer center pin |
    | 4 RS | Pin 12 |
    | 5 R/W | GND |
    | 6 Enable | Pin 11 |
    | 7 D0 | Not used |
    | 8 D1 | Not used |
    | 9 D2 | Not used |
    | 10 D3 | Not used |
    | 11 D4 | Pin 5 |
    | 12 D5 | Pin 4 |
    | 13 D6 | Pin 3 |
    | 14 D7 | Pin 2 |
    | 15 A BcL + | +5V |
    | 16 K BcL – | GND |

    **FIGURE 13-2:**
    Inserting the LCD screen into the breadboard

    ![image](../images/f13-02.jpg)
3.  Insert a potentiometer into the breadboard as shown in [Figure 13-3](ch13.xhtml#ch13fig3) and connect the center pin to LCD pin 3\. Connect one outer pin to the +5V rail and the other to the GND rail.

    **FIGURE 13-3:**
    Inserting the potentiometer into the breadboard

    ![image](../images/f13-03.jpg)
4.  Remember to connect the power rails of the breadboard to Arduino GND and +5V. Confirm that your setup matches the circuit diagram in [Figure 13-4](ch13.xhtml#ch13fig4), and upload the code in “[The Sketch](ch13.xhtml#ch13lev1sec03)” on [page 116](ch13.xhtml#page_116).

    **FIGURE 13-4:**
    The circuit diagram for the weather station

    ![image](../images/f13-04.jpg)

### **THE SKETCH**

This sketch uses the LiquidCrystal library, which comes with the Arduino IDE, and the DHT library, which you will need to download and install from *[http://nostarch.com/arduinohandbook/](http://nostarch.com/arduinohandbook/)* (see “[Libraries](ch00.xhtml#ch00lev2sec07)” on [page 7](ch00.xhtml#page_7)). The DHT library controls the function of the sensor, and the LCD library displays the readings on the screen.

```
/* Example testing sketch for various DHT humidity/temperature
sensors. Written by ladyada, public domain. */

#include <LiquidCrystal.h>
#include "DHT.h" // Call the DHT library
#define DHTPIN 8 // Pin connected to DHT
LiquidCrystal lcd(12, 11, 5, 4, 3, 2);
#define DHTTYPE DHT11  // Define the type of DHT module
DHT dht(DHTPIN, DHTTYPE); // Command to the DHT.h library

void setup() {
  dht.begin(); // Start the sensor
  lcd.begin(16, 2); // LCD screen is 16 characters by 2 lines
}

void loop() {
  float h = dht.readHumidity(); // Value for humidity
  float t = dht.readTemperature(); // Value for temperature
  t = t * 9 / 5 + 32; // Change reading from Celsius to Fahrenheit
  if (isnan(t) || isnan(h)) { // Check that DHT sensor is working
    lcd.setCursor(0, 0);
    lcd.print("Failed to read from DHT");  // If DHT is not working,
                                           // display this
  } else { // Otherwise show the readings on the screen
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("Humidity: ");
    lcd.print(h);
    lcd.print("%");
    lcd.setCursor(0, 1);
    lcd.print("Temp: ");
    lcd.print(t);
    lcd.print("f");
  }
}
```

## PROJECT 14: FORTUNE TELLER

**IN THIS PROJECT, WE’LL CREATE AN ELECTRONIC VERSION OF A CLASSIC FORTUNE-TELLING DEVICE: THE MAGIC 8 BALL.**

![image](../images/f0117-01.jpg)![image](../images/f0118-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 16x2 LCD screen (Hitachi HD44780 compatible)

• Tilt ball switch

• 50k-ohm potentiometer

• 1k-ohm resistor

**LIBRARIES REQUIRED**

• LiquidCrystal

### **HOW IT WORKS**

The Magic 8 Ball, a novelty toy created in the 1950s, is made of a hollow sphere in which a 20-sided die floated in alcohol. When you ask the ball a question and shake it, one side of the die floats up and displays your answer in the ball’s window.

For this project, you’ll use a tilt ball switch, shown in [Figure 14-1](ch14.xhtml#ch14fig1). The tilt ball switch is composed of a metal ball inside a metal casing that makes a connection when the switch is in an upright position. If you tilt the switch, the ball shifts and the connection is broken. There are lots of tilt switches available, and all do the same job. In this project, you’ll ask a question and shake the switch. When the switch settles upright again, it connects to the Arduino, which then randomly selects a response from eight preset answers and displays it on the LCD screen.

**FIGURE 14-1:**
Tilt ball switch inserted in the breadboard

![image](../images/f14-01.jpg)

The potentiometer controls the contrast of the LCD screen.

### **THE BUILD**

1.  Prepare the LCD screen as per the soldering instructions in “[Preparing the LCD Screen](ch12.xhtml#ch12lev1sec02)” on [page 104](ch12.xhtml#page_104).

2.  Place your LCD screen in the breadboard, inserting the header pins into the breadboard holes. Also place the potentiometer in the breadboard, and use the breadboard and jumper wires to connect your LCD screen, Arduino, and potentiometer.

    | **LCD SCREEN** | **ARDUINO** |
    | --- | --- |
    | 1 VSS | GND |
    | 2 VDD | +5V |
    | 3 VO contrast | Potentiometer center pin |
    | 4 RS | Pin 12 |
    | 5 R/W | GND |
    | 6 Enable | Pin 11 |
    | 7 D0 | Not used |
    | 8 D1 | Not used |
    | 9 D2 | Not used |
    | 10 D3 | Not used |
    | 11 D4 | Pin 5 |
    | 12 D5 | Pin 4 |
    | 13 D6 | Pin 3 |
    | 14 D7 | Pin 2 |
    | 15 A BcL + | +5V |
    | 16 K BcL – | GND |

3.  Remember to use a breadboard rail to make the multiple connections to the Arduino GND pin, as shown in [Figure 14-2](ch14.xhtml#ch14fig2).

    **FIGURE 14-2:**
    The LCD screen is connected to the Arduino.

    ![image](../images/f14-02.jpg)
4.  You should have already connected the center pin of the 10k-ohm potentiometer to LCD pin 3 (VO). Now connect one of the outer pins to GND and the other to +5V. This controls the contrast of your LCD screen.

5.  Insert the tilt switch into your breadboard and attach one side to Arduino pin 6 via a 1k-ohm resistor and the other side to GND.

    | **TILT BALL SWITCH** | **ARDUINO** |
    | --- | --- |
    | Leg 1 | Pin 6 via 1k-ohm resistor |
    | Leg 2 | GND |

6.  Connect your breadboard rails to the Arduino +5V and GND for power.

7.  Confirm that your setup matches [Figure 14-3](ch14.xhtml#ch14fig3), and upload the code in “[The Sketch](ch14.xhtml#ch14lev1sec03)” on [page 122](ch14.xhtml#page_122).

    **FIGURE 14-3:**
    The circuit diagram for the fortune teller

    ![image](../images/f14-03.jpg)

### **THE SKETCH**

The code for this project is fairly simple. When you switch on the Arduino, the LCD screen displays the message `Ask a Question`. Shaking the tilt switch activates the sketch, and the Arduino chooses a random answer from the eight available answers (cases 0–7).

Here’s the line in the code that does this:

reply = random(8);

To add in your own responses, change the value `8` to the number of possible responses, and then add your responses (or cases) in the same style as the others:

case 8:
  lcd.print("You betcha");
  break;

Here’s the full sketch:

```
/* Created 13 September 2012 by Scott Fitzgerald
   http://arduino.cc/starterKit
   This example code is part of the public domain
*/

#include <LiquidCrystal.h>

LiquidCrystal lcd(12, 11, 5, 4, 3, 2); // Pins attached to LCD screen

const int switchPin = 6; // Pin attached to tilt switch
int switchState = 0;
int prevSwitchState = 0;
int reply;

void setup() {
  lcd.begin(16, 2);
  pinMode(switchPin, INPUT);   // Set tilt switch pin as an input
  lcd.print("FORTUNE TELLER"); // Print this on line 1
  lcd.setCursor(0, 1);
  lcd.print("Ask a Question"); // Print this on line 2
}

void loop() {
  switchState = digitalRead(switchPin); // Read tilt switch pin
  if (switchState != prevSwitchState) {
    if (switchState == LOW) { // If circuit is broken, give answer
      reply = random(8); // Reply is 1 of 8 random cases as below
      lcd.clear();
      lcd.setCursor(0, 0);
      lcd.print("The answer is: "); // Print this to the screen
      lcd.setCursor(0, 1);

      switch (reply) { // Reply will be one of the following cases
        case 0:
          lcd.print("Yes");
          break;

        case 1:
          lcd.print("Probably");
          break;

        case 2:
          lcd.print("Definitely");
          break;

        case 3:
          lcd.print("Don't be silly");
          break;

        case 4:
          lcd.print("Of course");
          break;

        case 5:
          lcd.print("Ask again");
          break;

        case 6:
          lcd.print("Doubtful");
          break;

        case 7:
          lcd.print("No");
          break;
      }
    }
  }
   prevSwitchState = switchState; // Reset the switch
}
```

## PROJECT 15: REACTION TIMER GAME

**IN THIS PROJECT, LET’S COMBINE OUR LCD SCREEN WITH AN RGB LED AND A PIEZO BUZZER TO MAKE A REACTION TIMER GAME.**

![image](../images/f0124-01.jpg)![image](../images/f0125-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 16x2 LCD screen (Hitachi HD44780 compatible)

• RGB LED module

• Piezo buzzer

• Momentary tactile four-pin pushbutton

• 50k-ohm potentiometer

• 220-ohm resistor

**LIBRARIES REQUIRED**

• LiquidCrystal

### **HOW IT WORKS**

You start the game by holding down the pushbutton. The RGB LED lights up and fades through some random colors. Your aim is to react as quickly as possible when it turns red and release the pushbutton. The LCD screen shows your reaction time in milliseconds, from when the LED turned red to when you released the button (see [Figure 15-1](ch15.xhtml#ch15fig1)).

**FIGURE 15-1:**
After you release the pushbutton, your reaction time will be shown on the LED screen.

![image](../images/f15-01.jpg)

The piezo buzzer tries to distract you by making random sounds. If you release the button too soon, the LCD screen displays a message saying so, and you’ll have to start over.

As its name implies, an RGB LED is actually three LEDs in one: red, green, and blue (see [Figure 15-2](ch15.xhtml#ch15fig2)).

**FIGURE 15-2:**
An RGB LED can be red, green, or blue.

![image](../images/f15-02.jpg)

RGB is an *additive* color model, which means that by combining the light of two or more colors we can create other colors. Red, green, and blue are the additive primary colors usually used as the base for other colors, as shown in [Figure 15-3](ch15.xhtml#ch15fig3).

**FIGURE 15-3:**
The RGB color model is additive.

![image](../images/f15-03.jpg)

Let’s take a look at an RGB LED in a bit more detail. [Figure 15-4](ch15.xhtml#ch15fig4) shows a clear common-cathode LED. Note that the LED has four legs instead of the usual two: one each for red, green, and blue, and the final one is either the cathode or anode. In this case the longest pin is the cathode, and it connects to ground (GND).

**FIGURE 15-4:**
An RGB LED has four legs instead of the usual two.

![image](../images/f15-04.jpg)

The RGB LED used in this project is on a module with built-in resistors, which allows us to save space on our breadboard.

### **THE BUILD**

1.  Prepare the LCD screen as per the soldering instructions in “[Preparing the LCD Screen](ch12.xhtml#ch12lev1sec02)” on [page 104](ch12.xhtml#page_104).

2.  Place your LCD screen in the breadboard, inserting the header pins into the breadboard holes. Also place the potentiometer in the breadboard, and use the breadboard and jumper wires to connect your LCD screen, Arduino, and potentiometer.

    | **LCD SCREEN** | **ARDUINO** |
    | --- | --- |
    | 1 VSS | GND |
    | 2 VDD | +5V |
    | 3 VO contrast | Potentiometer center pin |
    | 4 RS | Pin 11 |
    | 5 R/W | GND |
    | 6 Enable | Pin 12 |
    | 7 D0 | Not used |
    | 8 D1 | Not used |
    | 9 D2 | Not used |
    | 10 D3 | Not used |
    | 11 D4 | Pin 5 |
    | 12 D5 | Pin 4 |
    | 13 D6 | Pin 3 |
    | 14 D7 | Pin 2 |
    | 15 A BcL + | +5V |
    | 16 K BcL – | GND |

3.  You should have already connected the center pin of the 50-kilohm potentiometer to LCD pin 3 (VO). Now connect one of the outer pins to GND and the other to +5V. This controls the contrast of your LCD screen.

4.  Insert the pushbutton into the breadboard so that it straddles the break in the center. We’ll label the pins as shown in [Figure 15-5](ch15.xhtml#ch15fig5).

    **FIGURE 15-5:**
    The pushbutton straddles the center break.

    ![image](../images/f15-05.jpg)

    Connect pin A to ground via a 220-ohm resistor, pin C to Arduino pin 9, and pin D to +5V (see [Project 1](ch01.xhtml#ch01) for more on how the pushbutton works).

    | **PUSHBUTTON** | **ARDUINO** |
    | --- | --- |
    | Pin A | GND via 220-ohm resistor |
    | Pin C | Pin 9 |
    | Pin D | +5V |

5.  Insert the RGB module and connect the red pin to Arduino pin 8, green to pin 6, blue to pin 7, and + to +5V.

    | **RGB LED** | **ARDUINO** |
    | --- | --- |
    | Red | Pin 8 |
    | Green | Pin 6 |
    | Blue | Pin 7 |
    | + | +5V |

6.  Connect the piezo buzzer’s red wire directly to Arduino pin 13 and its black wire to GND.

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Red wire | Pin 13 |
    | Black wire | GND |

7.  Check your build against Figure 15-7, and then upload the code in “[The Sketch](ch15.xhtml#ch15lev1sec03)” on [page 130](ch15.xhtml#page_130) to start playing!

    **FIGURE 15-6:**
    Circuit diagram for the reaction timer game. You’ll probably find that it’s easier to add all the GND and +5V wires before the data wires.

    ![image](../images/f15-06.jpg)

### **THE SKETCH**

When you press and hold the pushbutton, the LED flashes random colors and eventually turns red. The duration of time for which each color shows is set to random, as is the duration of the pauses between lights. This means you can’t learn the sequence of the colors and predict when the LED might turn red.

You can make the game more difficult by increasing the duration of the intervals in the following line of the sketch:

```
PSE = random(500, 1200);
```

The full sketch is as follows:

```
// Created by Steven De Lannoy and reproduced with kind permission
// http://www.wingbike.nl
// Used an RGB LED with a common anode (3 cathodes: R, G, B)
#include <LiquidCrystal.h>
LiquidCrystal lcd(12, 11, 5, 4, 3, 2);
int LEDR = 8;   // Pin connected to red LED
int LEDB = 7;   // Pin connected to blue LED
int LEDGr = 6;  // Pin connected to green LED
int Button = 9; // Pin connected to pushbutton
int COLOR;      // Variable color
int Beep;
int PSE;        // Variable pause
int TME;        // Time
int RTME = 0;   // Reaction time

void setup() {
  lcd.begin(16, 2);
  pinMode(LEDR, OUTPUT);   // Set LED pins as output
  pinMode(LEDB, OUTPUT);
  pinMode(LEDGr, OUTPUT);
  pinMode(Button, INPUT);  // Set pushbutton as input
  digitalWrite(LEDR, LOW); // Switch on all LED colors
  digitalWrite(LEDB, LOW);
  digitalWrite(LEDGr, LOW);
}

void loop() {
  lcd.clear(); // Clear screen
  lcd.print("Hold Button to"); // Display message on LCD screen
  lcd.setCursor(0, 1); // Move to second line
  lcd.print("start.");
  while (digitalRead(Button) == LOW) { // Test does not start until
                                       // button is pushed (and held)
    tone(13, 1200, 30);
    delay(1400);
    noTone(13);
  }
 lcd.clear();
  digitalWrite(LEDR, HIGH); // Switch off start light
  digitalWrite(LEDB, HIGH);
  digitalWrite(LEDGr, HIGH);
  randomSeed(analogRead(0)); // Random noise from pin 0
  COLOR = random(1, 4); // Generate random color
  PSE = random(500, 1200); // Set random pause duration between lights
  // Repeat this loop while color is green or blue AND pushbutton
  // is held
  while (COLOR != 1 && digitalRead(Button) == HIGH) {
    digitalWrite(LEDGr, HIGH);
    digitalWrite(LEDB, HIGH);
    delay(PSE);
    randomSeed(analogRead(0));
    Beep = random(1, 4); // Select random beep from buzzer
                         // (buzzer beeps 1 in 3 times)
    PSE = random(750, 1200); // Select random pause duration between
                             // lights (to increase surprise effect)
    if (Beep == 1) {
      tone(13, 1600, 350);
      delay(750);
      noTone(13);
    }
    if (COLOR == 2) {
      digitalWrite(LEDGr, LOW);
    }
    if (COLOR == 3) {
      digitalWrite(LEDB, LOW);
    }
    delay(PSE);
    randomSeed(analogRead(0));
    COLOR = random(1, 4); // Select random color
  }
  // Execute this loop if color is red
  if (COLOR == 1 && digitalRead(Button) == HIGH) {
    digitalWrite(LEDGr, HIGH);
    digitalWrite(LEDB, HIGH);
    delay(PSE);
    TME = millis(); // Record time since program has started
    digitalWrite(LEDR, LOW);
    while (digitalRead(Button) == HIGH) { // Runs until button is
                                          // released, recording the
                                          // reaction time
      delay(1);
    }
    lcd.display();
    RTME = millis() - TME; // Reaction time in ms
    lcd.print("Reaction Time:"); // Display on LCD screen
    lcd.setCursor(0, 1);
    lcd.print(RTME);
  }

  // Execute if color is NOT red but the pushbutton is released
  if (COLOR != 1) {
    lcd.print("Released too");
    lcd.setCursor(0, 1); // Move to second line
    lcd.print("soon!!!");
    tone(13, 3000, 1500);
    delay(500);
    noTone(13);
  }
  // Test does not restart until the button is pushed once
  while (digitalRead(Button) == LOW) {
    delay(10);
  }
  digitalWrite(LEDR, LOW); // Reset all lights to begin again
  digitalWrite(LEDB, LOW);
  digitalWrite(LEDGr, LOW);
  lcd.clear();
  lcd.print("Hold Button to");
  lcd.setCursor(0, 1);
  lcd.print("start.");
  int Time = 0;
  delay(1000);
}
```
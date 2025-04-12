# **PART 7**
![image](../images/common-01.jpg)
**ADVANCED**

## PROJECT 24: RAINBOW LIGHT SHOW

**IN THIS PROJECT, WE’LL CREATE A RAINBOW LIGHT SHOW USING AN 8×8 RGB LED MATRIX. WE’LL ALSO USE SHIFT REGISTERS TO EXTEND THE ARDUINO AND CONTROL THE MATRIX.**

![image](../images/f0208-01.jpg)![image](../images/f0209-01.jpg)

**PARTS REQUIRED**

• Arduino board

• 2 full-size breadboards

• Jumper wires

• 8×8 RGB LED matrix

• 4 74HC595 shift registers

• 16 220-ohm resistors

• 8 330-ohm resistors

### **HOW IT WORKS**

An RGB LED matrix ([Figure 24-1](ch24.xhtml#ch24fig1)) is a grid of 64 red, green, and blue LEDs. You can create the colors of the rainbow by controlling each LED individually and by mixing colors together.

**FIGURE 24-1:**
An RGB LED matrix

![image](../images/f24-01.jpg)

The LED matrix has a total of 32 pins ([Figure 24-2](ch24.xhtml#ch24fig2)); 8 pins control the common-anode positive leg of each LED, and 8 pins apiece control the level of red, green, and blue. In the matrix we’ve used here, pins 17–20 and 29–32 are the anode pins, 9–16 are for red, 21–28 for green, and 1–8 for blue, but your matrix may have different connections. Pin number 1 will be identified as shown in the bottom-left corner of [Figure 24-2](ch24.xhtml#ch24fig2)—the pin numbers run clockwise in this image.

**FIGURE 24-2:**
The pins of an RGB LED matrix

![image](../images/f24-02.jpg)

Your matrix should have come with a data sheet that tells you which pins control the red, green, and blue LEDs. If the pin numbers on your data sheet are different from those listed in [Table 24-1](ch24.xhtml#ch24tab1), follow your data sheet to make the connections to the shift registers and the Arduino. Each color pin requires a resistor to prevent it from overloading and burning out, but the values are slightly different—use 220-ohm resistors for the blue and green, and 330-ohm resistors for the red.

**TABLE 24-1:**
Pin configuration for an RGB LED matrix

| **MATRIX PIN FUNCTION** | **MATRIX PIN NUMBER** |
| --- | --- |
| Common anode (+) | 17, 18, 19, 20, 29, 30, 31, 32 |
| Red LEDs | 9, 10, 11, 12, 13, 14, 15, 16 |
| Green LEDs | 21, 22, 23, 24, 25, 26, 27, 28 |
| Blue LEDs | 1, 2, 3, 4, 5, 6, 7, 8 |

The layout may look complicated, but that’s simply because we’re using so many different wires. Just remember to take the project one step at a time.

Because there are so many connections, we’ll run out of pins on the Arduino board, so we’ll extend the board using *shift registers*. A shift register is a digital memory circuit found in calculators, computers, and data-processing systems. This project uses the 74HC595 shift register to control eight outputs at a time, while taking up only three pins on your Arduino. We’ll link multiple registers together to control more pins at once, using one for the common anode and one for each LED color.

The pin layout for the shift register is shown in [Figure 24-3](ch24.xhtml#ch24fig3), and the functions are described in [Table 24-2](ch24.xhtml#ch24tab2). When building the project, we’ll refer to the pin number of the shift register and function to assist identification.

**FIGURE 24-3:**
Pin layout for the shift register

![image](../images/f24-03.jpg)

**TABLE 24-2:**
Shift register pins

| **SHIFT REGISTER** | **CONNECTIONS** | **PIN FUNCTION** |
| --- | --- | --- |
| Pins 1–7, 15 | Q0–Q7 | Output pins |
| Pin 8 | GND | Ground, VSS |
| Pin 9 | SO | Serial out |
| Pin 10 | MR | Master Reclear, active low |
| Pin 11 | SH_CP | Shift register clock pin (CLOCK pin) |
| Pin 12 | ST_CP | Storage register clock pin (LATCH pin) |
| Pin 13 | OE | Output Enable, active low |
| Pin 14 | DS | Serial data input (DATA pin) |
| Pin 16 | VCC | Positive power |

### **THE BUILD**

1.  Insert the 8×8 RGB LED matrix across two full-size breadboards.

2.  Insert a 330-ohm resistor for each red LED pin and a 220-ohm resistor for each green or blue LED pin.

3.  Insert the first shift register into one of the breadboards near the common-anode pins on the LED matrix. Place the register so that it straddles the center break, as shown in [Figure 24-4](ch24.xhtml#ch24fig4). Connect the common-anode pins of the LED matrix to shift register 1 as follows. These pins do not need resistors.

    | **COMMON-ANODE PINS** | **SHIFT REGISTER 1 PINS** |
    | --- | --- |
    | **LED MATRIX** | **SHIFT REGISTER** | **SHIFT REGISTER** | **ARDUINO** |
    | --- | --- | --- | --- |
    | 32 | 15: Q0 | 8: GND | GND |
    | 31 | 1: Q1 | 9: SO | Shift 3 DS |
    | 30 | 2: Q2 | 10: MR | +5V |
    | 29 | 3: Q3 | 11: SH-CP | 13 |
    | 20 | 4: Q4 | 12: ST-CP | 10 |
    | 19 | 5: Q5 | 13: OE | GND |
    | 18 | 6: Q6 | 14: DS | Shift 2 SO |
    | 17 | 7: Q7 | 16: VCC | +5V |

    **FIGURE 24-4:**
    The shift registers should straddle the break of the breadboard.

    ![image](../images/f24-04.jpg)
4.  Now insert the remaining three shift registers into the breadboard. Shift register 2 controls the green LEDs, shift register 3 controls the blue LEDs, and shift register 4 controls the red LEDs. Connect the wires for each shift register as shown in the following tables. All color LED pins will need resistors.

    | **GREEN LED PINS** | **SHIFT REGISTER 2 PINS** |
    | --- | --- |
    | **LED MATRIX** | **SHIFT REGISTER** | **SHIFT REGISTER** | **ARDUINO** |
    | --- | --- | --- | --- |
    | 28 | 15: Q0 | 8: GND | GND |
    | 27 | 1: Q1 | 9: SO | Shift 1 DS |
    | 26 | 2: Q2 | 10: MR | +5V |
    | 25 | 3: Q3 | 11: SH-CP | 13 |
    | 24 | 4: Q4 | 12: ST-CP | 10 |
    | 23 | 5: Q5 | 13: OE | GND |
    | 22 | 6: Q6 | 14: DS | 11 |
    | 21 | 7: Q7 | 16: VCC | +5V |

    | **BLUE LED PINS** | **SHIFT REGISTER 3 PINS** |
    | --- | --- |
    | **LED MATRIX** | **SHIFT REGISTER** | **SHIFT REGISTER** | **ARDUINO** |
    | --- | --- | --- | --- |
    | 1 | 15: Q0 | 8: GND | GND |
    | 2 | 1: Q1 | 9: SO | Shift 4 DS |
    | 3 | 2: Q2 | 10: MR | +5V |
    | 4 | 3: Q3 | 11: SH-CP | 13 |
    | 5 | 4: Q4 | 12: ST-CP | 10 |
    | 6 | 5: Q5 | 13: OE | GND |
    | 7 | 6: Q6 | 14: DS | Shift 1 SO |
    | 8 | 7: Q7 | 16: VCC | +5V |

    | **RED LED PINS** | **SHIFT REGISTER 4 PINS** |
    | --- | --- |
    | **LED MATRIX** | **SHIFT REGISTER** | **SHIFT REGISTER** | **ARDUINO** |
    | --- | --- | --- | --- |
    | 9 | 15: Q0 | 8: GND | GND |
    | 10 | 1: Q1 | 9: SO | Shift 3 DS |
    | 11 | 2: Q2 | 10: MR | +5V |
    | 12 | 3: Q3 | 11: SH-CP | 13 |
    | 13 | 4: Q4 | 12: ST-CP | 10 |
    | 14 | 5: Q5 | 13: OE | GND |
    | 15 | 6: Q6 | 14: DS | Shift 2 SO |
    | 16 | 7: Q7 | 16: VCC | +5V |

5.  The Arduino controls the LEDs through three PWM pins, one each for clock, data, and latch. Each pin is connected to the Arduino as follows.

    | **SHIFT REGISTER** | **ARDUINO** | **FUNCTION** |
    | --- | --- | --- |
    | Pin 9 (shift reg 2) | Pin 11 | Data |
    | Pin 12 (all shift reg) | Pin 10 | Latch |
    | Pin 11 (all shift reg) | Pin 13 | Clock |

6.  Check that your setup matches the circuit diagram in [Figure 24-5](ch24.xhtml#ch24fig5), and then upload the code in “[The Sketch](ch24.xhtml#ch24lev1sec03)” below.

    **FIGURE 24-5:**
    The circuit diagram for the rainbow maker

    ![image](../images/f24-05.jpg)

### **THE SKETCH**

The sketch first defines the three Arduino pins that control the shift registers. The latch pin is defined as Arduino pin 10, the clock pin as 13, and the data pin as 11\. We define a number of variables between 0 and 255 to control the brightness of the LED colors. The sketch then turns on each LED fully in turn and combines the three colors to create the colors of the rainbow. For instance, with green on, blue off, and red on, the color yellow is displayed. The sketch then finishes by cycling though random colors.

```
/* Example 18.1 - experimenting with RGB LED matrix
   CC by-sa 3.0
   http://tronixstuff.wordpress.com/tutorials
*/

int latchpin = 10; // Connect to pin 12 on all shift registers
int clockpin = 13; // Connect to pin 11 on all shift registers
int datapin = 11;  // Connect to pin 14 on shift register 2
int zz = 500; // Delay variable
int va[] = {
  1, 2, 4, 8, 16, 32, 64, 128, 255
};
int va2[] = {
  1, 3, 7, 15, 31, 63, 127, 255
};

void setup() {
  pinMode(latchpin, OUTPUT);
  pinMode(clockpin, OUTPUT);
  pinMode(datapin, OUTPUT);
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 0);
  shiftOut(datapin, clockpin, MSBFIRST, 0);
  shiftOut(datapin, clockpin, MSBFIRST, 0);
  shiftOut(datapin, clockpin, MSBFIRST, 0);
  digitalWrite(latchpin, HIGH);
  randomSeed(analogRead(0));
}

void allRed() { // Turn on all red LEDs
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Turn cathodes to full
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Turn green to 0
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Turn blue to 0
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Turn red to full
  digitalWrite(latchpin, HIGH);
}

void allBlue() { // Turn on all blue LEDs
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Turn cathodes to full
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Turn green to 0
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Turn blue to full
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Turn red to 0
  digitalWrite(latchpin, HIGH);
}

void allGreen() { // Turn on all green LEDs
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Cathodes
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Green
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Blue
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Red
  digitalWrite(latchpin, HIGH);
}

void allOn() { // Turn on all LEDs
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Cathodes
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Green
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Blue
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Red
  digitalWrite(latchpin, HIGH);
}

void allYellow() { // Turn on green and red LEDs (yellow)
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Cathodes
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Green
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Blue
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Red
  digitalWrite(latchpin, HIGH);
}

void allAqua() { // Turn on green and blue LEDs (aqua)
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Cathodes
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Green
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Blue
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Red
  digitalWrite(latchpin, HIGH);
}

void allPurple() { // Turn on blue and red LEDs (purple)
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Cathodes
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Green
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Blue
  shiftOut(datapin, clockpin, MSBFIRST, 255); // Red
  digitalWrite(latchpin, HIGH);
}

void clearMatrix() { // Turn off all LEDs
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Cathodes
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Green
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Blue
  shiftOut(datapin, clockpin, MSBFIRST, 0); // Red
  digitalWrite(latchpin, HIGH);
}

void lostinspace() { // Random flashes of the LEDs
  for (int z = 0; z < 100; z++) {
    digitalWrite(latchpin, LOW);
    shiftOut(datapin, clockpin, MSBFIRST, va[random(8)]); // Cathodes
    shiftOut(datapin, clockpin, MSBFIRST, va[random(8)]); // Green
    shiftOut(datapin, clockpin, MSBFIRST, va[random(8)]); // Blue
    shiftOut(datapin, clockpin, MSBFIRST, va[random(8)]); // Red
    digitalWrite(latchpin, HIGH);
    delay(100);
  }
}

void displayLEDs(int rr, int gg, int bb, int cc, int dd) {
// Insert the base-10 values into the shiftOut functions
// and hold the display for dd milliseconds
  digitalWrite(latchpin, LOW);
  shiftOut(datapin, clockpin, MSBFIRST, cc); // Cathodes
  shiftOut(datapin, clockpin, MSBFIRST, gg); // Green
  shiftOut(datapin, clockpin, MSBFIRST, bb); // Blue
  shiftOut(datapin, clockpin, MSBFIRST, rr); // Red
  digitalWrite(latchpin, HIGH);
  delay(dd);
}

void loop() { // Light up the whole display in solid colors
  allOn();
  delay(zz);

  delay(zz);
  allRed();
  delay(zz);

  delay(zz);
  allGreen();
  delay(zz);

  delay(zz);
  allBlue();
  delay(zz);

  delay(zz);
  allPurple();
  delay(zz);

  delay(zz);
  allYellow();
  delay(zz);

  delay(zz);
  allAqua();
  delay(1000);
  // Light some individual LEDs using random values
  lostinspace(); // Scroll some horizontal and vertical lines
  for (int z = 0; z < 5; z++) {
    for (int q = 1; q < 129; q *= 2) {
      displayLEDs(255, 0, 0, q, 200);
    }
  }
  clearMatrix();
  delay(1000);

  for (int z = 0; z < 5; z++) {
    for (int q = 1; q < 129; q *= 2) {
      displayLEDs(0, 255, 0, q, 200);
      displayLEDs(q, 0, 0, 255, 200);
    }
  }
  clearMatrix();
  delay(1000);

  for (int z = 0; z < 5; z++) {
    for (int q = 1; q < 9; q++) {
      displayLEDs(0, 0, 255, va2[q], 200);
    }
  }
  clearMatrix();
  delay(1000);
}
```

## PROJECT 25: BUILD YOUR OWN ARDUINO!

**THIS PROJECT WILL TEACH YOU HOW TO BUILD YOUR OWN ARDUINO USING MINIMAL INDIVIDUAL COMPONENTS.**

![image](../images/f0220-01.jpg)![image](../images/f0221-01.jpg)

**PARTS REQUIRED**

• ATMEL ATmega328p chip

• Breadboard

• Green LED

• Red LED

• 3 220-ohm resistors

• 16 MHz crystal oscillator (HC-495)

• L7805cv 5V regulator

• 2 100 μF electrolytic capacitors

• PP3 9V battery clip

• Momentary tactile four-pin pushbutton

• 2 22 pF disc capacitors

• Jumper wires

• 9V battery

This is a fun and inexpensive little board with the same functionality as an Arduino, so it can be used as part of a permanent project in place of the pricier Arduino board.

### **HOW IT WORKS**

Our project board works exactly the same as an Arduino board. At its heart is the ATMEL ATmega328p chip ([Figure 25-1](ch25.xhtml#ch25fig1)), to which we’ll connect additional components. The ATmega chip is the brain of the Arduino and carries out the instructions from an uploaded sketch.

**FIGURE 25-1:**
The ATMEL ATmega328p chip

![image](../images/f25-01.jpg)

The L7805cv 5V regulator regulates the voltage and limits the current of the 9V battery to 5V, the level at which the ATmega chip operates, thereby protecting the chip and additional components. The 16 MHz crystal oscillator ([Figure 25-2](ch25.xhtml#ch25fig2)) allows the Arduino to calculate time, and the capacitors act as a filter to smooth voltage.

**FIGURE 25-2:**
The 16 MHz crystal oscillator

![image](../images/f25-02.jpg)

[Table 25-1](ch25.xhtml#ch25tab1) details the pins of the ATmega328p chip and how they correspond to the Arduino pins. For example, pin 13 on the Arduino, which we used to test our Arduino in “[Testing Your Arduino: Blinking an LED](ch00.xhtml#ch00lev1sec03)” on [page 9](ch00.xhtml#page_9), would be pin 19 on the actual chip. The top of the chip can be identified by the small semicircle indentation ([Figure 25-3](ch25.xhtml#ch25fig3)). Pin 1 is below this indentation, and the pins are numbered 1–28 counterclockwise from there.

**TABLE 25-1:**
The ATmega chip’s pins and their corresponding Arduino pins

| **ATMEGA PIN** | **ARDUINO FUNCTION** | **ATMEGA PIN** | **ARDUINO FUNCTION** |
| --- | --- | --- | --- |
| 1 | Reset | 15 | Pin 9 |
| 2 | Pin 0 | 16 | Pin 10 |
| 3 | Pin 1 | 17 | Pin 11 |
| 4 | Pin 2 | 18 | Pin 12 |
| 5 | Pin 3 | 19 | Pin 13 |
| 6 | Pin 4 | 20 | BCC |
| 7 | VCC | 21 | AREF |
| 8 | GND | 22 | GND |
| 9 | Crystal | 23 | A0 |
| 10 | Crystal | 24 | A1 |
| 11 | Pin 5 | 25 | A2 |
| 12 | Pin 6 | 26 | A3 |
| 13 | Pin 7 | 27 | A4 |
| 14 | Pin 8 | 28 | A5 |

**FIGURE 25-3:**
The top of the chip is marked with a semicircle indentation.

![image](../images/f25-03.jpg)

### **PREPARING THE CHIP**

Make sure to buy an ATmega chip with the Arduino bootloader installed, as it will also come preloaded with the blinking LED sketch, which you’ll need for this project.

Our homemade Arduino does not have a USB connector for the chip to connect directly to your PC, so if you want to use this Arduino breadboard with a different sketch (or ir your chip didn’t come with the bootloader installed), you’ll need to use an existing Arduino board as a host and upload the sketch to your ATmega chip as follows:

1.  Carefully pry the Arduino ATmega chip from your existing Arduino board ([Figure 25-4](ch25.xhtml#ch25fig4)), and replace it with your ATmega chip.

    **FIGURE 25-4:**
    Removing the ATmega chip from the Arduino

    ![image](../images/f25-04.jpg)
2.  Connect the Arduino to your PC using a USB cable.

3.  Open the Arduino IDE on your PC.

4.  Load the sketch onto the chip.

5.  Once the sketch is uploaded, disconnect the Arduino from your PC, gently remove this chip from the board, and replace the original Arduino ATmega chip.

The new ATmega chip should be loaded with the desired sketch. Generally you’d want to build your own Arduino as part of a permanent project, so the ability to easily load new sketches is not usually required; you’d just load one sketch at the beginning of the project and use that sketch from then on.

You are now ready to prepare your own board.

### **BUILDING THE ARDUINO CIRCUIT**

I normally show the circuit diagram at the end of the chapter, but in this instance it’s helpful to look at it first to reference the layout and identify the components being used ([Figure 25-5](ch25.xhtml#ch25fig5)).

**FIGURE 25-5:**
The complete circuit diagram

![image](../images/f25-05.jpg)

1.  Insert the ATmega chip into the breadboard with its legs straddling either side of the center break. You need a little space at either end for components, so place it roughly as shown in [Figure 25-6](ch25.xhtml#ch25fig6). Remember, pin 1 of the ATmega328p is directly below the small semicircle indentation on the chip. From here, pins are numbered 1–28 counterclockwise. Use this to position your chip correctly. The semicircle should be on the left side of your circuit.

    **FIGURE 25-6:**
    Placing the ATmega chip so it straddles the center break

    ![image](../images/f25-06.jpg)
2.  Connect pins 7, 20, and 21 of the ATmega to their closest positive power rail on the breadboard, and pins 8 and 23 to the negative power rails. Use jumper wires to connect the positive and GND power rails on either side of the board, as shown in [Figure 25-7](ch25.xhtml#ch25fig7).

    **FIGURE 25-7:**
    Connecting to the power rails

    ![image](../images/f25-07.jpg)
3.  Connect one leg of the crystal oscillator to pin 9 on the ATmega chip, and connect the other leg to pin 10\. Connect the legs of one of the 22 pF disc capacitors to pin 9 and GND, and the legs of the other disc capacitor to pin 10 and GND, as shown in [Figure 25-8](ch25.xhtml#ch25fig8).

    **FIGURE 25-8:**
    Inserting the crystal oscillator and 22pf disc capacitors

    ![image](../images/f25-08.jpg)
4.  Insert the pushbutton into the breadboard to the left of the ATmega chip, with the legs straddling the center break in the breadboard. Using jumper wires, connect the lower-right pin of the pushbutton to pin 1 on the ATmega, and the lower-left pin to GND, as shown in [Figure 25-9](ch25.xhtml#ch25fig9). Connect a 220-ohm resistor to the lower-right pin, and connect the other side of this resistor to the GND rail. This pushbutton will act as our reset button.

    **FIGURE 25-9:**
    Inserting the reset button

    ![image](../images/f25-09.jpg)
5.  Insert the L7805cv 5V regulator into the top-left corner of the breadboard with the printed number of the component facing you, as shown in [Figure 25-10](ch25.xhtml#ch25fig10)—the pins are numbered 1–3 from left to right. Insert one 100 μF electrolytic capacitor into the top power rail of the breadboard, with one pin in the positive rail and the other pin in the negative rail. Connect the second 100 μF electrolytic capacitor to pins 1 and 2 of the 5V regulator. Then connect pin 2 of the regulator to the negative power rail and pin 3 to the positive power rail.

    **FIGURE 25-10:**
    Connecting the electrolytic capacitors and the L7805cv 5V regulator

    ![image](../images/f25-10.jpg)
6.  Insert the red LED into the breadboard, connecting the long, positive leg to the positive rail via a 220-ohm resistor, and the short, negative leg to GND. Then insert the green LED, connecting the short leg to pin 21 on the ATmega, and the long leg to the positive power rail via a 220-ohm resistor, as shown in [Figure 25-11](ch25.xhtml#ch25fig11). Add positive power from the battery to pin 1 on the 5V regulator and GND to pin 2 on the regulator.

    **FIGURE 25-11:**
    Inserting the LEDs and connecting the battery

    ![image](../images/f25-11.jpg)

Your board is now complete and should look like [Figure 25-12](ch25.xhtml#ch25fig12). The red LED lights when power is added to the breadboard rails to indicate that the Arduino is on and working, and the green LED lights in response to the “Blinking an LED” sketch loaded on the ATmega chip.

**FIGURE 25-12:**
The completed circuit

![image](../images/f25-12.jpg)

Using the reference in [Table 25-1](ch25.xhtml#ch25tab1), you can use this board just like an Arduino Uno by connecting components to the ATmega chip pins instead of the Arduino pins. If you want to make any of the projects from this book permanent, consider building your own Arduino to power it! Remember to load the sketch to the ATmega chip through the real Arduino board first.
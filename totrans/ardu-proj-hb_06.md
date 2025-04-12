# **PART 5**
![image](../images/common-01.jpg)
**NUMERIC COUNTERS**

## PROJECT 16: ELECTRONIC DIE

**BOARD GAMES ARE PERILOUS ENOUGH WITHOUT ARGUMENTS OVER NUMBER READINGS FROM FALLEN OR LOST DICE. THE PERFECT SOLUTION: AN ELECTRONIC DIE.**

![image](../images/f0134-01.jpg)![image](../images/f0135-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 8 220-ohm resistors

• Seven-segment LED display

• 74HC595 shift register

• Momentary tactile four-pin pushbutton

### **HOW IT WORKS**

In this project we’ll create a die using a seven-segment LED display. When the pushbutton is pressed, a pulse is sent to the Arduino, and the LED “shakes” and displays a random digit between 1 and 6.

This project uses a 74HC595 *shift register*, a small integrated circuit (IC) and sequential logic counter that allows the Arduino to make more connections than it usually can with the pins it has, by “shifting” and storing data. The shift register has 16 pins; at one end you’ll find a dot or semicircle, which marks pin 1 on the left. The pins are then numbered counterclockwise from here. [Figure 16-1](ch16.xhtml#ch16fig1) shows the pinout, and [Table 16-1](ch16.xhtml#ch16tab1) describes the function of each pin.

**FIGURE 16-1:**
Pinout of the 74HC595 shift register

![image](../images/f16-01.jpg)

**TABLE 16-1:**
74HC595 shift register pins

| **SHIFT REGISTER PINS** | **CONNECTIONS** | **PIN FUNCTION** |
| --- | --- | --- |
| Pins 1–7, 15 | Q0–Q7 | Output pins |
| Pin 8 | GND | Ground, VSS |
| Pin 9 | Q7 | Serial out |
| Pin 10 | MR | Master Reclear, active low |
| Pin 11 | SH_CP | Shift register clock pin (CLOCK pin) |
| Pin 12 | ST_CP | Storage register clock pin (LATCH pin) |
| Pin 13 | OE | Output Enable, active low |
| Pin 14 | DS | Serial data input (DATA pin) |
| Pin 16 | VCC | Positive power |

The wire attached to Arduino pin 2 is connected to our pushbutton and, when pressed, will create a pulse. To use the die, push the button to make the digit on the die shake and display a random digit.

### **THE BUILD**

1.  Insert the seven-segment LED into your breadboard, making sure it straddles the center break; otherwise, the pins opposite each other will connect and short-circuit. Connect pin 3 to the GND rail, and connect 220-ohm resistors to the remaining pins except pin 8, which is not used. The resistors are needed to prevent the segment LEDs from burning out. See [Figure 16-2](ch16.xhtml#ch16fig2) for this setup.

    **FIGURE 16-2:**
    Connecting the seven-segment LED

    ![image](../images/f16-02.jpg)
2.  Insert the 74HC595 shift register into the breadboard with the semicircle marker of the IC on the left side. The bottom left-hand pin should be pin 1\. Your IC needs to straddle the center break, as shown in [Figure 16-3](ch16.xhtml#ch16fig3).

    **FIGURE 16-3:**
    The 74HC595 shift register should straddle the breadboard center break.

    ![image](../images/f16-03.jpg)
3.  Carefully make the connections shown in the following table between the seven-segment LED display and the 74HC595 shift register.

    | **SEVEN-SEGMENT LED DISPLAY** | **SHIFT REGISTER** | **ARDUINO** |
    | --- | --- | --- |
    | Pin 1 (E)[*](ch16.xhtml#fn01) | Pin 4 |  |
    | Pin 2 (D)[*](ch16.xhtml#fn01) | Pin 3 |  |
    | Pin 3 |  | GND |
    | Pin 4 (C)[*](ch16.xhtml#fn01) | Pin 2 |  |
    | Pin 5 (DP)[*](ch16.xhtml#fn01) | Pin 7 |  |
    | Pin 6 (B)[*](ch16.xhtml#fn01) | Pin 1 |  |
    | Pin 7 (A)[*](ch16.xhtml#fn01) | Pin 15 |  |
    | Pin 8 |  | Not used |
    | Pin 9 (F)[*](ch16.xhtml#fn01) | Pin 5 |  |
    | Pin 10 (G)[*](ch16.xhtml#fn01) | Pin 6 |  |

    [*](ch16.xhtml#fn_01) These pins require a 220-ohm resistor between the seven-segment LED display and the 74HC595 shift register.

4.  Now connect the remaining shift register pins to the Arduino as shown in the following table.

    | **SHIFT REGISTER** | **ARDUINO** |
    | --- | --- |
    | Pin 9 | Not used |
    | Pin 10 | +5V |
    | Pin 11 | Pin 12 |
    | Pin 12 | Pin 8 |
    | Pin 13 | GND |
    | Pin 14 | Pin 11 |
    | Pin 16 | +5V |
    | Pulse | Pin 2 |

5.  Insert the pushbutton into the breadboard with the pins straddling the center break, as shown in [Figure 16-4](ch16.xhtml#ch16fig4). Connect one side to pin 2 on the Arduino and the other side to GND.

    **FIGURE 16-4:**
    The pushbutton should also straddle the breadboard center break.

    ![image](../images/f16-04.jpg)
6.  Confirm that your setup matches the circuit diagram in [Figure 16-5](ch16.xhtml#ch16fig5), and upload the code in “[The Sketch](ch16.xhtml#ch16lev1sec03)” on [page 140](ch16.xhtml#page_140).

    **FIGURE 16-5:**
    The circuit diagram for the electronic die

    ![image](../images/f16-05.jpg)

### **THE SKETCH**

The sketch first sets the pins to control the 74HC595 chip that drives the seven-segment LED. When the seven-segment LED display is powered up, the dot is lit. When you press the pushbutton, the LEDs light in a short, rotating animation to signify that the die is shaking. After a moment a random number between 1 and 6 will be displayed. Press the button again to generate your next roll of the die.

```
// Code by Warrick A. Smith and reproduced with kind permission
// http://startingelectronics.com

const int latchPin = 8;   // Pins connected to shift register
const int clockPin = 12;
const int dataPin = 11;
const int buttonPin = 2;  // Pin connected to switch wire
// 1 to 6 and DP (decimal point) on 7-segment display
unsigned char lookup_7seg[] = {0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x80};
// Shaking die pattern on 7-segment display
unsigned char shake_dice[] = {0x63, 0x5C};
// Rolling die on 7-segment display
unsigned char roll_dice[] = {0x1C, 0x58, 0x54, 0x4C};
// Vary duration of time before die number is received
int rand_seed;
int rand_num = 0;                // Generate random number
unsigned char shake_toggle = 0;  // For shaking dice animation
int index = 0;                   // For rolling dice animation
int shake_speed;                 // Accelerates dice shake speed

void setup() {
  pinMode(latchPin, OUTPUT);     // Output pins for controlling the
                                 // shift register
  pinMode(clockPin, OUTPUT);
  pinMode(dataPin, OUTPUT);
  pinMode(buttonPin, INPUT);     // Read switch wire state
  digitalWrite(latchPin, LOW);   // Display DP on 7-segment display
                                 // at startup
  shiftOut(dataPin, clockPin, MSBFIRST, lookup_7seg[6]);
  digitalWrite(latchPin, HIGH);
  randomSeed(analogRead(0));     // Generate random seed
}

void loop() {
  if (digitalRead(buttonPin)) {
    shake_speed = 150; // Reset die shaking speed
    delay(30);
    // Generate number for random speed and show shaking animation
    while (digitalRead(buttonPin)) {
      rand_seed++;      // Generate random number
      // Animate shaking die
      if (shake_toggle) {
        AnimateDice(0, shake_dice);
        shake_toggle = 0;
      }
      else {
        AnimateDice(1, shake_dice);
        shake_toggle = 1;
      }
      delay(80 + shake_speed);  // Accelerate animation speed
      if (shake_speed > 0) {
        shake_speed -= 10;
      }
    }
    // Animate rolling die
    for (int rolls = 0; rolls < (rand_seed % 10 + 14); rolls++) {
      AnimateDice(index, roll_dice);
      delay((1 + rolls) * 20);
      index++;
      if (index > 3) {
        index = 0;
      }
    }
    rand_num = random(0, 6);  // Generate number thrown on die
    DiceNumber(rand_num);
  }
}

// Display the die number on 7-segment display
void DiceNumber(unsigned char num) {
  digitalWrite(latchPin, LOW);
  shiftOut(dataPin, clockPin, MSBFIRST, lookup_7seg[num]);
  digitalWrite(latchPin, HIGH);
}

// Display one frame of the shaking or rolling dice
void AnimateDice(int seg, unsigned char *table) {
  digitalWrite(latchPin, LOW);
  shiftOut(dataPin, clockPin, MSBFIRST, table[seg]);
  digitalWrite(latchPin, HIGH);
}
```

## PROJECT 17: ROCKET LAUNCHER

**IN THIS PROJECT WE’LL CREATE A PROGRAMMABLE COUNTDOWN TIMER THAT WE’LL USE TO LAUNCH A ROCKET BY IGNITING A FUSE WHEN THE COUNTDOWN REACHES 0.**

![image](../images/f0143-01.jpg)![image](../images/f0144-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• Four-digit, seven-segment serial display

• Piezo buzzer

• 2 momentary tactile four-pin pushbutton

• 50k-ohm potentiometer

• 3 LEDs (red, green, yellow)

• 3 220-ohm resistors

**LIBRARIES REQUIRED**

• SoftwareSerial

We’ll use a four-digit, seven-segment serial display that has a built-in integrated circuit to control the LEDs and can be connected to the Arduino with only three wires. When choosing your display, make sure it has an RX input so you’ll be able to control it with only one wire.

### **HOW IT WORKS**

You could use a timer like this to set off anything that requires power, like a servomotor, LED, or alarm. You’ll use a potentiometer to select the duration of your countdown (anywhere from 5 to 60 seconds). The LED screen will display the digits so you can see what you are setting the countdown to. We’ll include two pushbuttons: an Arm button and a Launch button. Once you’ve chosen the duration of your countdown, press the Arm button to ready the timer. The red LED light shows that it’s armed. (The Arm button is a safety feature to prevent you from accidentally setting off the launcher.) Once you’ve armed the rocket, press the Launch button to start the countdown. The green LED light signifies that it’s ready, and the countdown begins.

As the timer counts down, the piezo buzzer beeps every second. When the counter reaches five seconds, the timer beeps increasingly quickly until launch. When the timer reaches 0, power is sent through pin 7 to whatever output you have there—in this case, it lights the yellow LED. You could connect this timer to a buzzer, a servomotor to unlock a door, or even a fuse to ignite a rocket. I’ll show you how to make your own simple ignition for a fuse later in this project.

### **THE BUILD**

1.  Connect the seven-segment serial display RX pin to Arduino pin 3, connect VCC to +5V, and connect GND to Arduino GND via the breadboard, as shown in [Figure 17-1](ch17.xhtml#ch17fig1). You might need to strip back some of the wire to make the connection.

    | **SEVEN-SEGMENT SERIAL DISPLAY** | **ARDUINO** |
    | --- | --- |
    | RX | Pin 3 |
    | VCC | +5V |
    | GND | GND |

    **FIGURE 17-1:**
    Connecting the seven-segment display to the Arduino

    ![image](../images/f17-01.jpg)
2.  Insert the potentiometer into the breadboard and connect the left pin to +5V, the center pin to Arduino pin A0, and the right pin to GND, as shown in [Figure 17-2](ch17.xhtml#ch17fig2).

    | **POTENTIOMETER** | **ARDUINO** |
    | --- | --- |
    | Left pin | +5V |
    | Center pin | A0 |
    | Right pin | GND |

    **FIGURE 17-2:**
    Placing the potentiometer into the breadboard

    ![image](../images/f17-02.jpg)
3.  Connect the red wire of the piezo buzzer to Arduino pin 4 and the black wire to GND, as shown in [Figure 17-3](ch17.xhtml#ch17fig3).

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Red wire | Pin 4 |
    | Black wire | GND |

    **FIGURE 17-3:**
    Connecting the piezo buzzer

    ![image](../images/f17-03.jpg)
4.  Insert the two pushbuttons into your breadboard, with pins A and B on one side of the center break and pins D and C on the other, following the configuration in [Figure 17-4](ch17.xhtml#ch17fig4).

    **FIGURE 17-4:**
    The pin connections of the pushbutton

    ![image](../images/f17-04.jpg)
5.  Next, we’ll connect the pushbuttons, as shown in [Figure 17-5](ch17.xhtml#ch17fig5). To create the Arm button, connect pin C of the first pushbutton to GND and pin D to Arduino pin 5\. To create the Launch button, connect pin C of the other pushbutton to GND and pin D to Arduino pin 6.

    | **PUSHBUTTONS** | **ARDUINO** |
    | --- | --- |
    | Arm pin C | GND |
    | Arm pin D | Pin 5 |
    | Launch pin C | GND |
    | Launch pin D | Pin 6 |

    **FIGURE 17-5:**
    Connecting the pushbuttons and LEDs

    ![image](../images/f17-05.jpg)
6.  Insert the red LED into the breadboard with the shorter, negative leg connected to pin B of the Arm button. Connect the other leg to a 220-ohm resistor, and connect the other side of the resistor to +5V. Then insert the green LED with the negative leg connected to pin B of the Launch button, and the positive leg connected to +5V via a 220-ohm resistor.

    | **RESISTORS** | **ARDUINO** |
    | --- | --- |
    | Negative legs | GND |
    | Positive legs | +5V via 220-ohm resistor |

7.  Connect the igniter. We’re using a yellow LED as our igniter indicator for now. Insert it into the breadboard with the negative leg connected to GND and the positive leg connected to Arduino pin 7 via a 220-ohm resistor. (See “[Create a Working Fuse](ch17.xhtml#ch17lev1sec03)” on [page 149](ch17.xhtml#page_149) to learn how to make your own fuse igniter.)

    | **IGNITER** | **ARDUINO** |
    | --- | --- |
    | Negative leg | GND |
    | Positive leg | Pin 7 via 220-ohm resistor |

    When the countdown reaches 0, pin 7 is set to `HIGH` and triggers the igniter. Instead of actually igniting a fuse, we light the yellow LED to represent the ignition.

8.  Confirm that your setup matches the circuit diagram in [Figure 17-6](ch17.xhtml#ch17fig6), and upload the code in “[The Sketch](ch17.xhtml#ch17lev1sec04)” on [page 151](ch17.xhtml#page_151).

    **FIGURE 17-6:**
    The circuit diagram for the rocket launcher

    ![image](../images/f17-06.jpg)

### **CREATE A WORKING FUSE**

Instead of using an LED to indicate ignition, you can create a working fuse using a simple Christmas tree light. Be sure to wear eye protection when creating your fuse. These instructions are for entertainment purposes and should be carried out only by an adult.

**WARNING**

*There may be restrictions to launching a hobby rocket or firework in your country or state, so please check beforehand. It is your responsibility to keep project use within the law.*

1.  Using a hobby drill, apply light pressure to the top of the glass casing on a Christmas light to cut it off (see [Figure 17-7](ch17.xhtml#ch17fig7)).

    **FIGURE 17-7:**
    Cutting the tip with a hobby drill

    ![image](../images/f17-07.jpg)
2.  Cut near the tip of the glass casing and the top should pop off easily ([Figure 17-8](ch17.xhtml#ch17fig8)).

    **FIGURE 17-8:**
    Popping off the tip

    ![image](../images/f17-08.jpg)
3.  Now cut off the head of a wooden match (make sure you don’t ignite it!) and gently insert the match head into the open bulb, taking care not to damage the filament ([Figure 17-9](ch17.xhtml#ch17fig9)).

    **FIGURE 17-9:**
    Inserting a match head into the bottom half of the bulb

    ![image](../images/f17-09.jpg)
4.  Finally, connect the bulb wires to your ignition wires. When power is sent to the bulb, the filament will heat up and ignite the match head ([Figure 17-10](ch17.xhtml#ch17fig10)), creating enough energy to ignite a fuse.

    **FIGURE 17-10:**
    After the fuse has been lit

    ![image](../images/f17-10.jpg)

### **THE SKETCH**

The sketch first defines each component and its connection to the Arduino. The SoftwareSerial library controls the four-digit, seven-segment serial LED display, while the analog input from the potentiometer changes the time displayed from 5 to 60 seconds. When pressed, the Arm button acts as a digital switch and safety feature to allow the Launch button to be pressed. If the Arm button is pushed during countdown, the countdown aborts and the display resets.

The `tone` commands in the sketch pulse the piezo buzzer in time to the countdown to create a beep. When the countdown reaches 0, the igniter pin (in this case, connected to an LED) is set to `HIGH` and turns on the LED.

```
// Ardunaut Arduining.com, reproduced with kind permission

#define FuseTIME      1500   // Duration of fuse current in ms
#include <SoftwareSerial.h>  // Call the SoftwareSerial library

#define Fuse     7     // Pin connected to fuse (your LED or igniter)
#define GoButt   6     // Pin connected to Launch button
#define ArmButt  5     // Pin connected to Arm button
#define BuzzPin  4     // Pin connected to piezo buzzer
#define TXdata   3     // Pin connected to RX of display
#define RXdata   2     // Not used
#define SetPot   0     // Analog pin connected to potentiometer

SoftwareSerial mySerialPort(RXdata, TXdata);

void setup() {
  pinMode(TXdata, OUTPUT);
  pinMode(RXdata, INPUT);
  pinMode(Fuse, OUTPUT);
  pinMode(ArmButt, INPUT);       // Set Arm button pin to input
  pinMode(GoButt, INPUT);        // Set Launch button pin to input
  digitalWrite(Fuse, LOW);       // Open igniter circuit
  digitalWrite(ArmButt, HIGH);   // Turn on resistor
  digitalWrite(GoButt, HIGH);    // Turn on resistor
  mySerialPort.begin(9600);
  delay(10);                     // Wait for serial display startup
  mySerialPort.print("v");       // Reset the serial display
  mySerialPort.print("z");       // Brightness
  mySerialPort.write(0x40);      // 3/4 intensity
  mySerialPort.print("w");       // Decimal point control
  mySerialPort.write(0x10);      // Turn on colon in serial display
}

int DownCntr;   // Countdown (1/10 seconds)
int Go = 0;     // Stopped

void loop() {
  if (!digitalRead(GoButt) || !digitalRead(ArmButt)) {
    Go = 0;   // Abort the countdown
    tone(BuzzPin, 440, 1500);
    delay(1500);
  }

  if (Go == 0) {
    WaitARM();
    WaitGO();
  }
  ShowTimer();
  if (DownCntr > 50) {
    if (DownCntr % 10 == 0)tone(BuzzPin, 1000, 50); // One beep/sec
  }
  else if (DownCntr % 2 == 0)tone(BuzzPin, 1000, 50); // Beep faster

  if (DownCntr == 0) {
    tone(BuzzPin, 440, FuseTIME);  // Launch tone
    digitalWrite(Fuse, HIGH);      // Close the fuse circuit
    delay(FuseTIME);
    digitalWrite(Fuse, LOW);       // Open the fuse circuit
    Go = 0;
  }
  while (millis() % 100);          // Wait 50 ms
  delay(50);
  DownCntr--;
}

void WaitGO() {
  ShowTimer();
  while (digitalRead(GoButt));
  Go = 1;
  delay(20);
  while (!digitalRead(GoButt)); // Debounce Launch button
}

void ReadTimer() {
  DownCntr = map(analogRead(SetPot), 0, 1023, 5, 60);
  DownCntr *= 10;
}

void ShowTimer() {
  String seconds = String (DownCntr, DEC);
  while (seconds.length() < 3)seconds = "0" + seconds; // Format to
                                                       // 3 numbers
  mySerialPort.print(seconds); // Write to serial display
  mySerialPort.print(" ");     // Last digit off
}

void WaitARM() {
  while (digitalRead(ArmButt) == 1) {
    ReadTimer();
    delay(50);
    ReadTimer();
    ShowTimer();
    delay(150);
  }

  Go = 0;
  ShowTimer();
  tone(BuzzPin, 2000, 150);
  delay(200);
  tone(BuzzPin, 2000, 150);
  delay(200);
  tone(BuzzPin, 2000, 150);

  delay(20);
  while (!digitalRead(ArmButt)); // Debounce Arm button
}
```
# **PART 2**
![image](../images/common-01.jpg)
**SOUND**

## PROJECT 7: ARDUINO MELODY

**SO FAR ALL THE PROJECTS HAVE BEEN VISUAL, SO NOW IT’S TIME TO MAKE SOME MUSIC. IN THIS PROJECT WE WILL BE USING A PIEZOELECTRIC BUZZER TO PLAY SOME MELODIES.**

![image](../images/f0064-01.jpg)![image](../images/f0065-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Piezo buzzer

### **HOW IT WORKS**

The Arduino melody uses a piezo buzzer to create frequencies that resemble recognizable notes. You use the Arduino IDE to give the order, rate, and duration of the notes to play a specific tune.

*Piezos* are inexpensive buzzers often used in small toys. A piezo element without its plastic housing looks like a gold metallic disc with connected positive (typically red) and negative (typically black) wires. A piezo is capable only of making a clicking sound, which we create by applying voltage. We can make recognizable notes by getting the piezo to click hundreds of times a second at a particular frequency, so first we need to know the frequency of the different tones we want. [Table 7-1](ch07.xhtml#ch7tab1) shows the notes and their corresponding frequencies. *Period* is the duration of time, in microseconds, at which the frequency is created. We halve this number to get the `timeHigh` value, which is used in the code to create the note.

**TABLE 7-1:**
Notes and their corresponding frequences

| **NOTE** | **FREQUENCY** | **PERIOD** | **TIMEHIGH** |
| --- | --- | --- | --- |
| C | 261 Hz | 3,830 | 1915 |
| D | 294 Hz | 3,400 | 1700 |
| E | 329 Hz | 3,038 | 1519 |
| F | 349 Hz | 2,864 | 1432 |
| G | 392 Hz | 2,550 | 1275 |
| A | 440 Hz | 2,272 | 1136 |
| B | 493 Hz | 2,028 | 1014 |
| C | 523 Hz | 1,912 | 956 |

The code sends a square wave of the appropriate frequency to the piezo, generating the corresponding tone (see [Project 2](ch02.xhtml#ch02) for more on waveform). The tones are calculated through the following equation:

```
timeHigh = period / 2 = 1 / (2 * toneFrequency)
```

The setup of this project is really simple and uses only two wires connected to the Arduino.

### **THE BUILD**

1.  Connect the piezo’s black wire directly to GND on the Arduino, and the red wire to Arduino pin 9.

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Red wire | Pin 9 |
    | Black wire | GND |

2.  Check that your setup matches that of [Figure 7-1](ch07.xhtml#ch7fig1), and then upload the code shown next in “[The Sketch](ch07.xhtml#ch07lev1sec03)”.

    **FIGURE 7-1**
    Circuit diagram for the Arduino melody

    ![image](../images/f07-01.jpg)

### **THE SKETCH**

We’ll start off with a simple tune. At ➊, we tell the IDE that the tune is made up of 15 notes. Then we store the notes of the melody in a character array as a text string in the order in which they should be played, and the length for which each note will play is stored in another array as integers. If you want to change the tune, you can alter the notes in the array at ➋, and the number of beats for which each corresponding note plays at ➌. Finally at ➍ we set the tempo at which the tune will be played. Put it all together, and what does it play?

```
   // Melody (cleft) 2005 D. Cuartielles for K3

   int speakerPin = 9; // Pin connected to the piezo
➊ int length = 15; // Number of notes
➋ char notes[] = "ccggaagffeeddc "; // A space represents a rest
➌ int beats[] = { 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 2, 4 };
➍ int tempo = 300;
 void playTone(int tone, int duration) {
     for (long i = 0; i < duration * 1000L; i += tone * 2) {
       digitalWrite(speakerPin, HIGH);
       delayMicroseconds(tone);
       digitalWrite(speakerPin, LOW);
       delayMicroseconds(tone);
     }
   }

   // Set timeHigh value to specific notes
   void playNote(char note, int duration) {
     char names[] = { 'c', 'd', 'e', 'f', 'g', 'a', 'b', 'C' };
     int tones[] = { 1915, 1700, 1519, 1432, 1275, 1136, 1014, 956 };
     for (int i = 0; i < 8; i++) { // Play tone that corresponds
                                   // to note name
       if (names[i] == note) {
         playTone(tones[i], duration);
       }
     }
   }

   void setup() {
     pinMode(speakerPin, OUTPUT); // Set speakerPin as output
   }

   // Play the tune
   void loop() {
     for (int i = 0; i < length; i++) {
       if (notes[i] == ' ') {
         delay(beats[i] * tempo); // Rest
       }
       else {
         playNote(notes[i], beats[i] * tempo);
       }
       delay(tempo / 2); // Pause between notes
     }
   }
```

## PROJECT 8: MEMORY GAME

**IN THIS PROJECT WE’LL CREATE OUR OWN VERSION OF AN ATARI ARCADE MEMORY GAME CALLED TOUCH ME, USING FOUR LEDS, FOUR PUSHBUTTON SWITCHES, A PIEZO BUZZER, AND SOME RESISTORS AND JUMPER WIRES.**

![image](../images/f0069-01.jpg)![image](../images/f0070-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• Piezo buzzer

• 4 momentary tactile four-pin pushbuttons

• 4 LEDs

• 4 220-ohm resistors

**LIBRARIES REQUIRED**

• Tone

### **HOW IT WORKS**

The original Atari game had four colored panels, each with an LED that lit up in a particular pattern that players had to repeat back (see [Figure 8-1](ch08.xhtml#ch8fig1)).

**FIGURE 8-1:**
The original *Touch Me* game

![image](../images/f08-01.jpg)

This memory game plays a short introductory tune and flashes an LED. When you press the correct corresponding button, the lights flash again in a longer sequence. Each time you repeat the sequence back correctly, the game adds an extra step to make the sequence more challenging for you. When you make an error, the game resets itself.

### **THE BUILD**

1.  Place the pushbuttons in the breadboard so they straddle the center break with pins A and B on one side of the break, and C and D on the other, as shown in [Figure 8-2](ch08.xhtml#ch8fig2). (See [Project 1](ch01.xhtml#ch01) for more information on how the pushbutton works.)

    **FIGURE 8-2:**
    A pushbutton has four pins.

    ![image](../images/f08-02.jpg)
2.  Connect pin B of each pushbutton to the GND rail of your breadboard, and connect the rail to Arduino GND.

3.  Connect pin D of each pushbutton to Arduino’s digital pins 2 through 5 in order.

4.  Insert the LEDs into the breadboard with the shorter, negative legs connected to pin C of each pushbutton. Insert the positive leg into the hole on the right, as shown in the circuit diagram in [Figure 12-3](ch12.xhtml#ch12fig3).

    | **PUSHBUTTON** | **ARDUINO/LED** |
    | --- | --- |
    | Pin B | GND |
    | Pin C | LED negative legs |
    | Pin D | Arduino pins 2–5 |

5.  Place a 220-ohm resistor into the breadboard with one wire connected to the positive leg of each LED. Connect the other wire of the resistor to the Arduino as follows.

    | **LEDS** | **ARDUINO/PUSHBUTTON** |
    | --- | --- |
    | Positive legs | Arduino pins 8–11 via 220-ohm resistors |
    | Negative legs | Pushbutton pin C |

    Make sure the red LED connected to pin 11 is paired with the pushbutton connected to pin 5, the yellow LED connected to pin 10 is paired with the pushbutton connected to pin 4, the green LED connected to pin 9 is paired with the pushbutton connected to pin 3, and the blue LED connected to pin 8 is paired with the pushbutton connected to pin 2.

6.  Connect the black wire of the piezo directly to Arduino GND, and the red wire to Arduino pin 12.

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Red wire | Pin 12 |
    | Black wire | GND |

7.  Check your setup against [Figure 8-3](ch08.xhtml#ch8fig3), and then upload the code in “[The Sketch](ch08.xhtml#ch08lev1sec03)” on [page 73](ch08.xhtml#page_73).

    **FIGURE 8-3:**
    Circuit diagram for the memory game

    ![image](../images/f08-03.jpg)

### **THE SKETCH**

The sketch generates a random sequence in which the LEDs will light; a random value generated for `y` in the pattern loop determines which LED is lit (e.g., if y is 2, the LED connected to pin 2 will light). You have to follow and repeat back the pattern to advance to the next level.

In each level, the previous lights are repeated and one more randomly generated light is added to the pattern. Each light is associated with a different tone from the piezo, so you get a different tune each time, too. When you get a sequence wrong, the sketch restarts with a different random sequence. For the sketch to compile correctly, you will need to install the Tone library (available from *[http://nostarch.com.com/arduinohandbook/](http://nostarch.com.com/arduinohandbook/)*). See “[Libraries](ch00.xhtml#ch00lev2sec07)” on [page 7](ch00.xhtml#page_7) for details.

```
// Used with kind permission from Abdullah Alhazmy www.Alhazmy13.net

#include <Tone.h>
Tone speakerpin;
int starttune[] = {NOTE_C4, NOTE_F4, NOTE_C4, NOTE_F4, NOTE_C4,
                   NOTE_F4, NOTE_C4, NOTE_F4, NOTE_G4, NOTE_F4,
                   NOTE_E4, NOTE_F4, NOTE_G4};
int duration2[] = {100, 200, 100, 200, 100, 400, 100, 100, 100, 100,
                   200, 100, 500};
int note[] = {NOTE_C4, NOTE_C4, NOTE_G4, NOTE_C5, NOTE_G4, NOTE_C5};
int duration[] = {100, 100, 100, 300, 100, 300};
boolean button[] = {2, 3, 4, 5}; // Pins connected to
                                 // pushbutton inputs
boolean ledpin[] = {8, 9, 10, 11}; // Pins connected to LEDs
int turn = 0;         // Turn counter
int buttonstate = 0;  // Check pushbutton state
int randomArray[100]; // Array that can store up to 100 inputs
int inputArray[100];

void setup() {
  Serial.begin(9600);
  speakerpin.begin(12); // Pin connected to piezo buzzer
  for (int x = 0; x < 4; x++) {
    pinMode(ledpin[x], OUTPUT); // Set LED pins as output
  }
  for (int x = 0; x < 4; x++) {
    pinMode(button[x], INPUT); // Set pushbutton pins as inputs
    digitalWrite(button[x], HIGH); // Enable internal pullup;
                                   // pushbuttons start in high
                                   // position; logic reversed
  }
  // Generate "more randomness" with randomArray for the output
  // function so pattern is different each time
  randomSeed(analogRead(0));
  for (int thisNote = 0; thisNote < 13; thisNote ++) {
    speakerpin.play(starttune[thisNote]); // Play the next note
    if (thisNote == 0 || thisNote == 2 || thisNote == 4 ||
        thisNote == 6) { // Hold the note
      digitalWrite(ledpin[0], HIGH);
    }
    if (thisNote == 1 || thisNote == 3 || thisNote == 5 ||
        thisNote == 7 || thisNote == 9 || thisNote == 11) {
      digitalWrite(ledpin[1], HIGH);
    }
    if (thisNote == 8 || thisNote == 12) {
      digitalWrite(ledpin[2], HIGH);
    }
    if (thisNote == 10) {
      digitalWrite(ledpin[3], HIGH);
    }
    delay(duration2[thisNote]);
    speakerpin.stop(); // Stop for the next note
    digitalWrite(ledpin[0], LOW);
    digitalWrite(ledpin[1], LOW);
    digitalWrite(ledpin[2], LOW);
    digitalWrite(ledpin[3], LOW);
    delay(25);
  }
  delay(1000);
}

void loop() {
  // Generate the array to be matched by the player
  for (int y = 0; y <= 99; y++) {
    digitalWrite(ledpin[0], HIGH);
    digitalWrite(ledpin[1], HIGH);
    digitalWrite(ledpin[2], HIGH);
    digitalWrite(ledpin[3], HIGH);
    // Play the next note
    for (int thisNote = 0; thisNote < 6; thisNote ++) {
      speakerpin.play(note[thisNote]); // Hold the note
      delay(duration[thisNote]);       // Stop for the next note
      speakerpin.stop();
      delay(25);
    }
    digitalWrite(ledpin[0], LOW);
    digitalWrite(ledpin[1], LOW);
    digitalWrite(ledpin[2], LOW);
    digitalWrite(ledpin[3], LOW);
    delay(1000);
    // Limited by the turn variable
    for (int y = turn; y <= turn; y++) {
      Serial.println("");
      Serial.print("Turn: ");
      Serial.print(y);
      Serial.println("");
      randomArray[y] = random(1, 5); // Assign a random number (1-4)
      // Light LEDs in random order
      for (int x = 0; x <= turn; x++) {
        Serial.print(randomArray[x]);
        for (int y = 0; y < 4; y++) {
          if (randomArray[x] == 1 && ledpin[y] == 8) {
            digitalWrite(ledpin[y], HIGH);
            speakerpin.play(NOTE_G3, 100);
            delay(400);
            digitalWrite(ledpin[y], LOW);
            delay(100);
          }
          if (randomArray[x] == 2 && ledpin[y] == 9) {
            digitalWrite(ledpin[y], HIGH);
            speakerpin.play(NOTE_A3, 100);
            delay(400);
            digitalWrite(ledpin[y], LOW);
            delay(100);
          }
          if (randomArray[x] == 3 && ledpin[y] == 10) {
            digitalWrite(ledpin[y], HIGH);
            speakerpin.play(NOTE_B3, 100);
            delay(400);
            digitalWrite(ledpin[y], LOW);
            delay(100);
          }
          if (randomArray[x] == 4 && ledpin[y] == 11) {
            digitalWrite(ledpin[y], HIGH);
            speakerpin.play(NOTE_C4, 100);
            delay(400);
            digitalWrite(ledpin[y], LOW);
            delay(100);
          }
        }
      }
    }
    input();
  }
}

// Check whether input matches the pattern
void input() {
  for (int x = 0; x <= turn;) {
    for (int y = 0; y < 4; y++) {
      buttonstate = digitalRead(button[y]); // Check for button push
      if (buttonstate == LOW && button[y] == 2) {
        digitalWrite(ledpin[0], HIGH);
        speakerpin.play(NOTE_G3, 100);
        delay(200);
        digitalWrite(ledpin[0], LOW);
        inputArray[x] = 1;
        delay(250);
        Serial.print(" ");
        Serial.print(1);
        // Check if value of user input matches the generated array
        if (inputArray[x] != randomArray[x]) {
          fail(); // If not, fail function is called
        }
        x++;
      }
      if (buttonstate == LOW && button[y] == 3) {
        digitalWrite(ledpin[1], HIGH);
        speakerpin.play(NOTE_A3, 100);
        delay(200);
        digitalWrite(ledpin[1], LOW);
        inputArray[x] = 2;
        delay(250);
        Serial.print(" ");
        Serial.print(2);
        if (inputArray[x] != randomArray[x]) {
          fail();
        }
        x++;
      }
      if (buttonstate == LOW && button[y] == 4) {
        digitalWrite(ledpin[2], HIGH);
        speakerpin.play(NOTE_B3, 100);
        delay(200);
        digitalWrite(ledpin[2], LOW);
        inputArray[x] = 3;
        delay(250);
        Serial.print(" ");
        Serial.print(3);
        if (inputArray[x] != randomArray[x]) {
          fail();
        }
        x++;
      }
      if (buttonstate == LOW && button[y] == 5) {
        digitalWrite(ledpin[3], HIGH);
        speakerpin.play(NOTE_C4, 100);
        delay(200);
        digitalWrite(ledpin[3], LOW);
        inputArray[x] = 4;
        delay(250);
        Serial.print(" ");
        Serial.print(4);
        if (inputArray[x] != randomArray[x]) {
          fail();
        }
        x++;
      }
    }
  }
  delay(500);
  turn++; // Increment turn count
}

// Function used if player fails to match the sequence
void fail() {
  for (int y = 0; y <= 2; y++) { // Flash lights to indicate failure
    digitalWrite(ledpin[0], HIGH);
    digitalWrite(ledpin[1], HIGH);
    digitalWrite(ledpin[2], HIGH);
    digitalWrite(ledpin[3], HIGH);
    speakerpin.play(NOTE_G3, 300);
    delay(200);
    digitalWrite(ledpin[0], LOW);
    digitalWrite(ledpin[1], LOW);
    digitalWrite(ledpin[2], LOW);
    digitalWrite(ledpin[3], LOW);
    speakerpin.play(NOTE_C3, 300);
    delay(200);
  }
  delay(500);
  turn = -1; // Reset turn value to start the game again
}
```

## PROJECT 9: SECRET KNOCK LOCK

**FOR CENTURIES CLANDESTINE GROUPS HAVE USED SECRET KNOCKS TO PREVENT UNAUTHORIZED ENTRY. LET’S BRING THIS SYSTEM INTO MODERN TIMES, BY CREATING OUR OWN ELECTRONIC GATEKEEPER.**

![image](../images/f0078-01.jpg)![image](../images/f0079-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• Tower Pro SG90 9g servomotor

• Piezo buzzer

• 3 LEDs

• 1M-ohm resistor

• 3 220-ohm resistors

**LIBRARIES REQUIRED**

• Servo

### **HOW IT WORKS**

In this project, you’ll make a circuit that moves a servo arm to unlock a box or door when you provide the correct secret knock. So far we’ve been using a piezo buzzer only to make noise, but we can also use it as a sensor to detect sounds—in this case, knocks. When a piezo is struck it rings like a bell, but instead of producing sound it outputs voltage, which generates a number depending on the force of the strike. We’ll measure this voltage in numbers, and if the knocks fall within a certain range, the Arduino will register them as correct. If three knocks of the correct voltage are detected, you’ve cracked the code, and the servo arm moves to unlock the box or door.

Here are the two lines of code we’ll use later in the sketch to set the range for the voltage; if the voltage is between 10 and 100, the knock will be registered.

```
const int quietKnock = 10;
const int loudKnock = 100;
```

If you knock too softly or too hard, the knock won’t register. You’ll need to do three “correct” knocks to trigger the servo arm to move. When the correct sequence and strength of knock are registered, the servo arm swings 90 degrees to “unlock” whatever it is set up with. The LEDs, shown in [Figure 9-1](ch09.xhtml#ch9fig1), serve as indicators of your lock’s status: the red LED lights when the knocks are incorrect and the servo arm has not moved (that is, the box or door is still locked); the yellow LED flashes when a knock is registered and a correct code is sensed; and the green LED lights and the servomotor moves after three correct knocks.

**FIGURE 9-1:**
The LED setup

![image](../images/f09-01.jpg)

For the best result, remove your piezo from its casing and attach it directly to the inside of a box or outside of a door so it is more sensitive to the vibration of the knock.

### **THE BUILD**

1.  Insert a 1M-ohm resistor into your breadboard and connect the piezo’s red wire to one leg and its black wire to the other. Connect the black wire to the GND rail, and the red wire to Arduino pin A0.

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Red wire | A0 via 1M-ohm resistor |
    | Black wire | GND via 1M-ohm resistor |

2.  Connect the servo’s yellow signal wire directly to Arduino pin 9, its brown wire to GND, and its red wire to +5V.

    | **SERVO** | **ARDUINO** |
    | --- | --- |
    | Yellow wire | Pin 9 |
    | Red wire | +5V |
    | Brown wire | GND |

3.  Insert the LEDs into your breadboard with the short, negative legs connected to GND. The positive legs should connect to the pins via 220-ohm resistors as follows: yellow connects to Arduino pin 3, green to pin 4, and red to pin 5.

    | **LEDS** | **ARDUINO** |
    | --- | --- |
    | Positive legs | Pins 3–5 via 220-ohm resistors |
    | Negative legs | GND |

4.  Connect Arduino pin 2 to the positive power rail. In our setup this is always on, but you could add a switch in the connection between Arduino pin 2 and the power rail to save power when the project is not in use.

5.  Connect the breadboard rails to Arduino GND and +5V.

6.  Make sure your setup matches the circuit diagram in [Figure 9-2](ch09.xhtml#ch9fig2), and then upload the code in “[The Sketch](ch09.xhtml#ch09lev1sec03)” on [page 82](ch09.xhtml#page_82).

    **FIGURE 9-2:**
    The circuit diagram for the secret knock lock

    ![image](../images/f09-02.jpg)

### **THE SKETCH**

We first call on the Servo library and set Arduino pin 9 to control the servo. LEDs are attached to Arduino pins 3, 4, and 5, and these will light depending on the validity of a knock. The piezo acts as a sensor rather than a buzzer in this project and is attached to Arduino pin A0\. When someone knocks, the knock is sensed by the piezo and a voltage value is sent to the A0 analog pin of the Arduino depending on the strength of the knock—the harder the knock, the higher the value. A knock with a value below 10 is considered too quiet, and one with a value above 100 too loud, so neither will be accepted as a valid knock. The red LED lights if the knock is not accepted, and the yellow LED lights if it is. Any knock value between 10 and 100 is accepted as a valid knock and counted, and if three valid knocks are received, the servomotor moves and the green LED lights.

As mentioned earlier, these are the two lines of code that set the parameters for measuring the voltage:

```
const int quietKnock = 10;
const int loudKnock = 100;
```

If you were feeling particularly secretive, you could set this range even tighter to make the code harder to crack. Here’s the sketch:

```
/* Created 18 September 2012 by Scott Fitzgerald
   Thanks to Federico Vanzati for improvements
   http://arduino.cc/starterKit
   This example code is part of the public domain.
*/

#include <Servo.h>
Servo servo9; // Pin connected to servo mpo

const int piezo = A0;    // Pin connected to piezo
const int switchPin = 2; // Pin connected to servo
const int yellowLed = 3; // Pin connected to yellow LED
const int greenLed = 4;  // Pin connected to green LED
const int redLed = 5;    // Pin connected to red LED

int knockVal;   // Value for the knock strength
int switchVal;

const int quietKnock = 10; // Set min value that will be accepted
const int loudKnock = 100; // Set max value that will be accepted
boolean locked = false;    // A true or false variable
int numberOfKnocks = 0;    // Value for number of knocks

void setup() {
  servo9.attach(9);
  pinMode(yellowLed, OUTPUT);   // Set LED pins as outputs
  pinMode(greenLed, OUTPUT);
  pinMode(redLed, OUTPUT);
  pinMode(switchPin, INPUT);    // Set servo pin as input
  Serial.begin(9600);
  digitalWrite(greenLed, HIGH); // Green LED is lit when the
                                // sequence is correct
  servo9.write(0);
  Serial.println("The box is unlocked!");
}

void loop() {
  if (locked == false) {
    switchVal = digitalRead(switchPin);
    if (switchVal == HIGH) {
      locked = true;
      digitalWrite(greenLed, LOW);
      digitalWrite(redLed, HIGH);
      servo9.write(90);
      Serial.println("The box is locked!");
      delay(1000);
    }
  }
  if (locked == true) {
    knockVal = analogRead(piezo); // Knock value is read by analog pin
    if (numberOfKnocks < 3 && knockVal > 0) {
      if (checkForKnock(knockVal) == true) { // Check for correct
                                             // number of knocks
        numberOfKnocks++;
      }
      Serial.print(3 - numberOfKnocks);
      Serial.println(" more knocks to go");
    }
    if (numberOfKnocks >= 3) { // If 3 valid knocks are detected,
                               // the servo moves
      locked = false;
      servo9.write(0);
      delay(20);
      digitalWrite(greenLed, HIGH);
      digitalWrite(redLed, LOW);
      Serial.println("The box is unlocked!");
    }
  }
}

boolean checkForKnock(int value) { // Checks knock value
  if (value > quietKnock && value < loudKnock) { // Value needs to be
                                                 // between these
    digitalWrite(yellowLed, HIGH);
    delay(50);
    digitalWrite(yellowLed, LOW);
    Serial.print("Valid knock of value ");
    Serial.println(value);
    return true;
  }
  else { // If value is false then send this to the IDE serial
    Serial.print("Bad knock value ");
    Serial.println(value);
    return false;
  }
}
```
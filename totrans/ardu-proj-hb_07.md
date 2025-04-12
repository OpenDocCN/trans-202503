# **PART 6**
![image](../images/common-01.jpg)
**SECURITY**

## PROJECT 18: INTRUDER SENSOR

**IN THIS PROJECT, WE’LL USE AN ULTRASONIC SENSOR TO DETECT AN INTRUDER.**

![image](../images/f0156-01.jpg)![image](../images/f0157-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• Four-pin HC-SR04 ultrasonic sensor

• Servomotor

• Red LED

• Green LED

• 2 220-ohm resistors

We’ll connect the intruder sensor to a servo and some LEDs so that when someone comes within a certain distance, a green LED turns off, a red LED turns on, and the servomotor moves (see [Figure 18-1](ch18.xhtml#ch18fig1)).

**FIGURE 18-1:**
The LEDs alert you to an intruder.

![image](../images/f18-01.jpg)

### **HOW IT WORKS**

This project is versatile and can be used and adapted in various ways. Because the ultrasonic sensor can define distance, you could, for example, use it to define an area and trigger an alarm when that perimeter is breached. The sensor works similarly to a radar: it sends out an ultrasonic signal, or *ping*. When this signal hits an object, it bounces back like an echo, and the time between the ping and the echo is used to calculate distance. The Arduino can use this calculation to trigger an event, depending on the value received.

In this project, when the sensor detects an intruder within a predefined vicinity, the red LED will light and the servo arm will move. You can adapt this project to trigger a different event when the intruder is detected, like pressing a security system button or locking a door. For a friendlier scenario, you could set the distance really close so that when you wave your hand in front of the sensor, the servo presses a button to release a treat, like candy.

**NOTE**

*To use the same ultrasonic sensor shown in these figures, see “[Retailer List](app01.xhtml#app01lev1sec02)” on [page 240](app01.xhtml#page_240) or search online for* HC-SR04 ultrasonic module.

### **THE BUILD**

1.  Insert the ultrasonic sensor into the breadboard. The sensor we’re using in this project has four pins, as shown in [Figure 18-2](ch18.xhtml#ch18fig2). Connect the sensor’s GND to the Arduino GND rail, VCC to Arduino +5V, Trig to Arduino pin 12, and Echo to Arduino pin 13.

    | **ULTRASONIC SENSOR** | **ARDUINO** |
    | --- | --- |
    | GND | GND |
    | VCC | +5V |
    | Trig | Pin 12 |
    | Echo | Pin 13 |

    **FIGURE 18-2:**
    The HC-SR04 ultrasonic sensor

    ![image](../images/f18-02.jpg)
2.  Connect the servo’s brown (ground) wire to the Arduino GND rail, its red (power) wire to the Arduino +5V rail, and its yellow signal (control) wire to Arduino pin 9.

    | **SERVO** | **ARDUINO** |
    | --- | --- |
    | Red wire | +5V |
    | Brown wire | GND |
    | Yellow wire | Pin 9 |

3.  Insert the red and green LEDs into the breadboard with the shorter, negative legs in the Arduino GND rail. Add a 220-ohm resistor to each of the positive legs, and connect the red LED to Arduino pin 2 and the green LED to pin 3 via the resistors.

    | **LEDS** | **ARDUINO** |
    | --- | --- |
    | Negative legs | GND |
    | Positive leg (red) | Pin 2 via 220-ohm resistor |
    | Positive leg (green) | Pin 3 via 220-ohm resistor |

4.  Connect the power rails on the breadboard to Arduino +5V and GND. The final configuration is shown in [Figure 18-3](ch18.xhtml#ch18fig3).

    **FIGURE 18-3:**
    The complete intruder sensor project

    ![image](../images/f18-03.jpg)
5.  Check that your setup matches that of [Figure 18-4](ch18.xhtml#ch18fig4) and then upload the code in “[The Sketch](ch18.xhtml#ch18lev1sec03)” on [page 161](ch18.xhtml#page_161).

    **FIGURE 18-4:**
    The circuit diagram for the intruder sensor

    ![image](../images/f18-04.jpg)

### **THE SKETCH**

When an object is within the trigger distance, the red LED will light and the servo will move 45 degrees. You can change the distance of the sensor field in the following line of the sketch:

```
if (distance <= 15)
```

In this example, if something is sensed within a distance of 15 centimeters, the next block of code will run.

The Trig pin on the sensor is connected to Arduino pin 12 and emits an ultrasonic signal or ping. When the signal reaches an object, it bounces back to the module, and this echo is sent to Arduino pin 13\. The time difference between the two signals gives us our distance reading. If the distance is more than our set minimum, the green LED stays on; if not, the red LED lights and the servo moves.

```
/* NewPing Library created by Tim Eckel teckel@leethost.com.
   Copyright 2012 License: GNU GPL v3
   http://www.gnu.org/licenses/gpl-3.0.html
*/

#include <NewPing.h> // Call NewPing library
#include <Servo.h>   // Call Servo library
#define trigPin 12   // Trig pin connected to Arduino 12
#define echoPin 13   // Echo pin connected to Arduino 13
#define MAX_DISTANCE 500
NewPing sonar(trigPin, echoPin, MAX_DISTANCE); // Library setting
int greenLed = 3, redLed = 2; // Set green LED to pin 3, red to pin 2
int pos = 20;
Servo myservo;

void setup() {
  Serial.begin (115200);
  pinMode(trigPin, OUTPUT);
  pinMode(echoPin, INPUT);
  pinMode(greenLed, OUTPUT);
  pinMode(redLed, OUTPUT);
  myservo.attach(9); // Servo attached to pin 9
}

void loop() {
  int duration, distance, pos = 0, i;
  digitalWrite(trigPin, LOW);
  delayMicroseconds(2);
  digitalWrite(trigPin, HIGH); // Trig pin sends a ping
  delayMicroseconds(10);
  digitalWrite(trigPin, LOW);
  duration = pulseIn(echoPin, HIGH); // Echo receives the ping
  distance = (duration / 2) / 29.1;
  Serial.print(distance);
  Serial.println(" cm");
  // If sensor detects object within 15 cm
  if (distance <= 15) {
    digitalWrite(greenLed, LOW); // Turn off green LED
    digitalWrite(redLed, HIGH);  // Turn on red LED
    myservo.write(180);          // Move servo arm 180 degrees
    delay(450);
    digitalWrite(redLed, LOW);   // Light the red LED
    myservo.write(90);
    delay(450);
    digitalWrite(redLed, HIGH);
    myservo.write(0);
    delay(450);
    digitalWrite(redLed, LOW);
    myservo.write(90);
  }
  // Otherwise
  else {
    digitalWrite(redLed, LOW);    // Turn off red LED
    digitalWrite(greenLed, HIGH); // Turn on green LED
    myservo.write(90);
  }
  delay(450);
}
```

## PROJECT 19: LASER TRIP WIRE ALARM

**IN THIS PROJECT, YOU’LL CREATE A SIMPLE LASER TRIP WIRE ALARM.**

![image](../images/f0163-01.jpg)![image](../images/f0164-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• Photoresistor

• Piezo buzzer

• Green LED

• 10k-ohm resistor

• Laser pen

You’ve probably seen a movie where a valuable item is protected by a grid of laser beams. The beams look cool and seem pretty high-tech, but the principles behind them are actually very simple.

### **HOW IT WORKS**

When the laser pen shines on the photoresistor, the green LED will light up to signify that the circuit is ready. When the laser beam is broken, the LED turns off and the buzzer sounds.

As we know from [Projects 13](ch13.xhtml#ch13) and [18](ch18.xhtml#ch18), photoresistors produce variable resistance depending on the amount of light falling on their sensor. When the photoresistor does not detect light from the laser, it will drop its resistance and trigger the Arduino to send voltage to the pin controlling the buzzer.

Laser beams that are visible in daylight or even in the dark are very powerful and can be extremely dangerous. In this project we’ll use a low-powered laser pen instead (see [Figure 19-1](ch19.xhtml#ch19fig1)).

**FIGURE 19-1:**
Laser pens can still be dangerous and should never be directed toward anybody’s eyes!

![image](../images/f19-01.jpg)

### **THE BUILD**

1.  Insert your photoresistor into the breadboard. Connect one leg to the +5V rail using a jumper wire. Connect a 10k-ohm resistor to the other leg, and connect the other side of this resistor to Arduino A0 and GND on the breadboard.

    | **PHOTORESISTOR** | **ARDUINO** |
    | --- | --- |
    | Leg 1 | +5V |
    | Leg 2 | A0 via 10k-ohm resistor and GND |

2.  Connect the red (positive) wire of the piezo buzzer directly to Arduino pin 11 on the Arduino and the black (GND) wire to GND on the breadboard.

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Black wire | GND |
    | Red wire | Pin 11 |

3.  Insert the green LED’s long leg into Arduino pin 13 and the short leg into GND.

4.  Connect the power rails to the breadboard.

5.  Before you upload the code, you need to check the photo-resistor’s value in ambient light. Run the following small program with the photoresistor set up as instructed.

    ```
    void setup() {
      pinMode(4, OUTPUT);
      Serial.begin(9600);
    }

    void loop() {
      digitalWrite(4, HIGH);
      Serial.println(analogRead(0));
    }
    ```

6.  Open the Serial Monitor in the Arduino IDE. It will show the value being read from the light resistor—in [Figure 19-2](ch19.xhtml#ch19fig2), it’s 964—in normal lighting conditions. Take note of your number, which will be different depending on your lighting conditions.

    **FIGURE 19-2:**
    Reading values from the photoresistor

    ![image](../images/f19-02.jpg)

    Now shine the laser on the resistor’s cell, and also note this number; my reading is 620\. This might seem counterintuitive, as you would expect more light to provide a higher number, but the figure is actually translating the resistance—more light, less resistance. Your values will differ from those shown here, so make sure to record your two readings.

7.  Check that your setup matches that of [Figure 19-3](ch19.xhtml#ch19fig3) and then upload the code in “[The Sketch](ch19.xhtml#ch19lev1sec03)” on [page 168](ch19.xhtml#page_168).

    **FIGURE 19-3:**
    The circuit diagram for the laser trip wire alarm

    ![image](../images/f19-03.jpg)

### **THE SKETCH**

The sketch first sets Arduino pin 11 as an `OUTPUT` for the piezo buzzer and pin 13 as an `OUTPUT` for the LED. The photoresistor is connected to Arduino pin A0\. If the analog reading from A0 is more than 850 (meaning that there is less light and the laser beam has been broken), the buzzer will be set to `HIGH` and turn on and the LED will turn off. Remember to change the resistance value depending on your calibration on this line:

```
if (analogRead(0) > 850) {
```

As noted earlier, when the laser is shining on the resistor it reads about 620, so in the sketch I’ve set the buzzer to sound only if the value is more than 850\. This value is between our laser value and our nonlaser value, so we know the laser beam to the resistor has been broken if the value reaches 850.

```
int buzzPin = 11; // Pin connected to the piezo
int LED = 13;     // Pin connected to the LED

void setup() {
  pinMode(buzzPin, OUTPUT); // Set pin as output
  pinMode(LED, OUTPUT);     // Set pin as output
}

void loop() {
  if (analogRead(0) > 850) { // Set this value depending on the
                             // values of your photoresistor
    digitalWrite(buzzPin, HIGH); // If value is above 850,
                                 // turn the piezo ON
    digitalWrite(LED, LOW);      // If value is above 850,
                                 // turn the LED OFF
    delay(1000); // Wait for 1 second
    digitalWrite(buzzPin, LOW);
    digitalWrite(LED, LOW);
  } else {
    digitalWrite(buzzPin, LOW); // If value is 850 or below
                                // (light shining on photoresistor),
                                // the piezo is off
    digitalWrite(LED, HIGH);    // If value is 850 or below
                                // (light shining on photoresistor),
                                // the LED is on
  }
}
```

## PROJECT 20: SENTRY GUN

**A SENTRY GUN IS AN UNMANNED WEAPON CAPABLE OF AUTONOMOUSLY SENSING AND FIRING UPON ENEMY TARGETS USING ULTRASONIC DETECTION. IN THIS PROJECT, WE’LL CREATE A MINIATURE VERSION OF THIS GUN.**

![image](../images/f0170-01.jpg)![image](../images/f0171-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Mini breadboard

• Jumper wires

• Male-to-male jumper wires

• Four-pin HC-SR04 ultrasonic sensor

• WLToys RC V959 missile launcher

• Tower Pro SG90 9g servomotor

**LIBRARIES REQUIRED**

• Servo

• NewPing

### **HOW IT WORKS**

We’ll attach the toy missile launcher and the ultrasonic sensor to a servo arm (see [Figure 20-1](ch20.xhtml#ch20fig1)) so that the servo sweeps the gun and sensor back and forth across 180 degrees, giving the ultrasonic sensor a wide range of detection. When an enemy is detected, the Arduino triggers the sentry gun and discharges the missiles. For more on the ultrasonic sensor, see [Project 18](ch18.xhtml#ch18).

**FIGURE 20-1:**
Attaching the toy gun and ultrasonic sensor to the servo arm gives them a wide range of detection and motion.

![image](../images/f20-01.jpg)

The key component for this project is the WLToys RC V959 missile launcher, also known as the Walkera Part RC V959-19 missile bullet launcher, intended for radio-controlled helicopters ([Figure 20-2](ch20.xhtml#ch20fig2)).

**FIGURE 20-2:**
The Walkera Part RC V959-19 missile bullet launcher

![image](../images/f20-02.jpg)

This cool part is really cheap (around $6 –10) and is widely available online. Inside this launcher is a mini servo that revolves to set off the missiles. The wires that control this servo are white (GND) and yellow (+5V). You’ll also find black and red wires, which are for a single shot, but we’ll use only yellow and white for a continuous Gatling gun effect.

### **THE BUILD**

1.  First we’ll prepare the toy missile launcher. Carefully remove the four wires from the small plastic socket; they should come out fairly easily. You can use a male-to-male jumper wire to push down on the plastic clip to help.

2.  The core of the wire is stranded and quite flimsy, so strip the end of the yellow and white wires and solder them to separate solid-core wires that can be inserted into the Arduino, as shown in [Figure 20-3](ch20.xhtml#ch20fig3). Trim the black and red wires or tape them out of the way.

    **FIGURE 20-3:**
    Stripping and soldering the missile launcher wires

    ![image](../images/f20-03.jpg)
3.  Glue the servo motor’s arm to the base of the missile launcher, as shown in [Figure 20-4](ch20.xhtml#ch20fig4).

    **FIGURE 20-4:**
    Gluing the servo motor’s arm

    ![image](../images/f20-04.jpg)
4.  Attach the ultrasonic sensor to the top of the launcher, as shown in [Figure 20-5](ch20.xhtml#ch20fig5). You can use a hot-glue gun for a solid connection or just tape it for now if you might want to alter it later.

    **FIGURE 20-5:**
    Attaching the ultrasonic sensor

    ![image](../images/f20-05.jpg)
5.  Use the jumper wires to connect the ultrasonic sensor to the Arduino: connect Trig directly to Arduino pin 13, and Echo directly to Arduino pin 12\. We will use a mini breadboard to assist with multiple power connections to Arduino +5V and GND.

    | **ULTRASONIC SENSOR** | **ARDUINO** |
    | --- | --- |
    | VCC | +5V |
    | Trig | Pin 13 |
    | Echo | Pin 12 |
    | GND | GND |

6.  Connect the servomotor’s brown wire to Arduino GND and the red wire to +5V via the mini breadboard, and the yellow/white wire directly to Arduino pin 9.

    | **SERVO** | **ARDUINO** |
    | --- | --- |
    | Brown wire | GND |
    | Red wire | +5V |
    | Yellow wire | Pin 9 |

7.  Connect the launcher’s white wire to the GND rail of the mini breadboard, and the yellow wire directly to Arduino pin 3.

    | **LAUNCHER** | **ARDUINO** |
    | --- | --- |
    | White wire | GND |
    | Yellow wire | Pin 3 |

8.  Your sentry gun should look like [Figure 20-6](ch20.xhtml#ch20fig6). Insert the missiles into the launcher.

    **FIGURE 20-6:**
    Your sentry gun is ready to fire!

    ![image](../images/f20-06.jpg)
9.  Confirm that your completed setup matches that of [Figure 20-7](ch20.xhtml#ch20fig7). Upload the code in “[The Sketch](ch20.xhtml#ch20lev1sec03)” on [page 176](ch20.xhtml#page_176).

    **FIGURE 20-7:**
    The circuit diagram for the sentry gun

    ![image](../images/f20-07.jpg)

### **THE SKETCH**

The sketch first calls the NewPing and Servo libraries to access the functions you’ll need to control the servomotor and ultrasonic sensor, respectively. (Make sure the NewPing library is downloaded from *[http://nostarch.com/arduinohandbook/](http://nostarch.com/arduinohandbook/)* and saved in your Arduino folder.) The servomotor sweeps back one way and then forth the other, moving the ultrasonic sensor 180 degrees. The sensor sends out an ultrasonic signal, or *ping*, and when this ping reaches an object, it echoes back to give a time value. The Arduino converts this value into the distance between the sensor and the object. When the distance to the object is fewer than 15 centimeters, the servo stops and power is sent to the launcher to fire the bullets at the object. You can change this trigger distance (given in centimeters) at ➊.

```
   #include <NewPing.h> // Call NewPing library
   #include <Servo.h>   // Call Servo library
   #define trigPin 12   // Pin connected to ultrasonic sensor Trig
   #define echoPin 13   // Pin connected the ultrasonic sensor Echo
   #define MAX_DISTANCE 500

   NewPing sonar(trigPin, echoPin, MAX_DISTANCE);

   int blaster = 3; // Pin connected to the blaster

   int angle = 0; // Set servo position in degrees

   Servo servo;

   void setup() {
     Serial.begin (115200);
     pinMode(trigPin, OUTPUT);
     pinMode(echoPin, INPUT);
     pinMode(blaster, OUTPUT);
     servo.attach(9); // Pin connected to servo
   }

   void loop() {
     int duration, distance, pos = 0, i;
     digitalWrite(trigPin, LOW);
     delayMicroseconds(2);
     digitalWrite(trigPin, HIGH); // trigPin sends a ping
     delayMicroseconds(10);
     digitalWrite(trigPin, LOW);
     duration = pulseIn(echoPin, HIGH); // echoPin receives the ping
     distance = (duration / 2) / 29.1;
     Serial.print(distance);
     Serial.println(" cm");
➊   if (distance <= 15) { // If distance is fewer than 15 cm
       digitalWrite(blaster, HIGH); // Blaster will fire
       servo.write(90);
     }
     else {
       digitalWrite(blaster, LOW); // Otherwise, blaster won't activate
       for (angle = 0; angle < 180; angle++) { // Sweep the servo
         servo.write(angle);
         delay(15);
       }
       for (angle = 180; angle > 0; angle--) {
         servo.write(angle);
       }
       delay(450);
     }
   }
```

## PROJECT 21: MOTION SENSOR ALARM

**IN THIS PROJECT, WE’LL BUILD A MOTION-SENSING ALARM USING A PASSIVE INFRARED (PIR) SENSOR.**

![image](../images/f0178-01.jpg)![image](../images/f0179-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• HC SR501 PIR sensor

• LED

• Piezo buzzer

You can use this alarm to trigger a variety of outputs, such as lights, motors, or even a “welcome home” message when you approach your front door.

### **HOW IT WORKS**

This project is based on the HC SR501 PIR sensor, which is widely available online for a few dollars. We’re going to set it up so that when someone passes in front of the PIR sensor, the LED will light up and the piezo buzzer will sound (see [Figure 21-1](ch21.xhtml#ch21fig1)), but you can adapt it for various other output.

**FIGURE 21-1:**
Any piezo buzzer will work for this project, but remember that most have polarity, so the red wire must be connected to +5V and the black wire to GND.

![image](../images/f21-01.jpg)

Other similar PIR sensors will work with this code, but it’s important to check the pin layout of your sensor on the data sheet, as this can vary. All sensors should have +5V, GND, and output pins. On this model, the pins are not clearly marked, but if you simply remove the outer lens (it’s clipped in place and can be unclipped easily), you can identify the pins underneath, as shown in [Figure 21-2](ch21.xhtml#ch21fig2).

**FIGURE 21-2:**
A PIR sensor with the lens removed

![image](../images/f21-02.jpg)

The two orange potentiometers on the sensor indicate that there are two adjustable settings. With the sensor upright, as shown in [Figure 21-3](ch21.xhtml#ch21fig3), the left potentiometer controls how long the output is set to `HIGH` when something is detected, and can be set between 5 and 200 seconds. When we attach an LED to the output, the LED will be lit for between 5 and 200 seconds depending on the setting. The right potentiometer adjusts the detection range from 0 to 7 meters.

**FIGURE 21-3:**
PIR sensor potentiometers. The left controls how long the output is set to `HIGH` (5–200 seconds), while the right controls the range (0–7 meters).

![image](../images/f21-03.jpg)

The sensor works by detecting infrared radiation, which is emitted from objects that generate heat. Crystalline material within the sensor detects the infrared radiation, and when it detects a set level, it triggers the output signal of the sensor. The Arduino reads this output as voltage, so we can use this as a simple switch to turn something on—in this instance, an LED.

We are setting up the sensor so that an alarm sounds when the sensor is triggered, but there are other ways that you can customize the project. For example, you could scare your friends by attaching a servo and setting it up to release a rubber band when they walk by.

### **THE BUILD**

1.  Connect the PIR sensor’s +5V and GND wires to the +5V and GND rails on the breadboard, and connect these rails to the Arduino. Connect the PIR sensor’s output wire to Arduino pin 2\. (See [Figure 21-4](ch21.xhtml#ch21fig4).)

    | **PIR SENSOR** | **ARDUINO** |
    | --- | --- |
    | +5V | +5V |
    | GND | GND |
    | Output | Pin 2 |

    **FIGURE 21-4:**
    PIR sensor connected to wires

    ![image](../images/f21-04.jpg)
2.  Insert an LED into the breadboard and connect the long, positive leg to Arduino pin 13, and the short, negative leg to GND. You don’t need a resistor for the LED in this project.

    | **LED** | **ARDUINO** |
    | --- | --- |
    | Positive leg | Pin 13 |
    | Negative leg | GND |

3.  Connect the piezo buzzer by attaching the red wire to Arduino pin 10 and the black wire to GND.

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Red wire | Pin 10 |
    | Black wire | GND |

4.  Confirm that your setup matches the circuit diagram in [Figure 21-5](ch21.xhtml#ch21fig5), and then upload the code in “[The Sketch](ch21.xhtml#ch21lev1sec03)” on [page 183](ch21.xhtml#page_183).

    **FIGURE 21-5:**
    The circuit diagram for the motion sensor alarm

    ![image](../images/f21-05.jpg)

### **THE SKETCH**

The sketch works by setting Arduino pin 13 as output for the LED, pin 2 as input for the PIR sensor, and pin 10 as output for the piezo buzzer. When the PIR sensor is triggered, a `HIGH` signal is sent to the Arduino, which will in turn light the LED and play a tone on the piezo buzzer.

```
int ledPin = 13;           // Pin connected to LED
int inputPin = 2;          // Pin connected to PIR sensor
int pirState = LOW;        // Start PIR state LOW with no motion
int val = 0;               // Variable for reading the pin status
int pinSpeaker = 10;       // Pin connected to piezo

void setup() {
  pinMode(ledPin, OUTPUT);  // Set LED as output
  pinMode(inputPin, INPUT); // Set sensor as input
  pinMode(pinSpeaker, OUTPUT);
  Serial.begin(9600);
}

void loop() {
  val = digitalRead(inputPin);   // Read PIR input value
  if (val == HIGH) {             // Check if input is HIGH
    digitalWrite(ledPin, HIGH);  // If it is, turn ON LED
    playTone(300, 160);
    delay(150);
    if (pirState == LOW) {
      // Print to the Serial Monitor if motion detected
      Serial.println("Motion detected!");

      pirState = HIGH;
    }
  } else {
      digitalWrite(ledPin, LOW); // If input is not HIGH,
                                 // turn OFF LED
      playTone(0, 0);
      delay(300);
      if (pirState == HIGH) {
      Serial.println("Motion ended!");
      pirState = LOW;
    }
  }
}

void playTone(long duration, int freq) { // Duration in ms,
                                         // frequency in Hz
    duration *= 1000;
    int period = (1.0 / freq) * 1000000;
    long elapsed_time = 0;
    while (elapsed_time < duration) {
      digitalWrite(pinSpeaker, HIGH);
      delayMicroseconds(period / 2);
      digitalWrite(pinSpeaker, LOW);
      delayMicroseconds(period / 2);
      elapsed_time += (period);
    }
}
```

## PROJECT 22: KEYPAD ENTRY SYSTEM

**IT’S TIME TO INTRODUCE A KEYPAD TO YOUR ARDUINO BY BUILDING A KEYPAD ENTRY SYSTEM.**

![image](../images/f0185-01.jpg)![image](../images/f0186-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• Tower Pro SG90 9g servomotor

• Green LED

• Red LED

• 4×4 membrane keypad

• 2 220-ohm resistors

**LIBRARIES REQUIRED**

• Keypad

• Servo

• Password

This project uses a 4×4 membrane keypad with a ribbon of eight wires running from the bottom, connected to a servo that sweeps to open a lock.

### **HOW IT WORKS**

A keypad is basically a series of buttons that output a number or character depending on which button is pressed. With the keypad face up, the wires are numbered 1–8 from left to right. The first four wires correspond to the rows, and the latter four to the columns.

You’ll need to download the library for the keypad from the *[http://nostarch.com/arduinohandbook/](http://nostarch.com/arduinohandbook/)* and save it in your IDE’s Arduino libraries folder.

We’ll connect this keypad to a servo and some LEDs to create a lock system like the secret knock lock in [Project 9](ch09.xhtml#ch09). To use the lock, enter your code and press the asterisk (*) to confirm. If the code matches the password defined in the sketch, the green LED will flash and the servo will move 90 degrees. If the code is incorrect, the red LED will flash. Use the hash key (#) to reset between code inputs. You could swap this servo for a more substantial one capable of unlocking a heavier deadbolt on a door, or locking and unlocking a box from the inside with the keypad and LEDs mounted externally.

### **TESTING THE KEYPAD**

First we’ll test the keypad with the following code:

```
#include <Keypad.h>

const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {2,3,4,5};
byte colPins[COLS] = {6,7,8,9};

Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins,
                       ROWS, COLS);

void setup() {
  Serial.begin(9600);
}

void loop() {
  char key = keypad.getKey();
  if (key != NO_KEY){
    Serial.println(key);
  }
}
```

Upload this code and then open the Serial Monitor in your IDE ([Figure 22-1](ch22.xhtml#ch22fig1)).

**FIGURE 22-1:**
Testing the keypad

![image](../images/f22-01.jpg)

With the keypad face up, connect the wires in sequence from left to right to Arduino digital pins 9–2\. Once you have uploaded the code, press a few keys. As each key is pressed, the corresponding character should appear on a separate line in the Arduino IDE’s serial console.

### **THE BUILD**

1.  Connect the pins of the keypad directly to the Arduino pins as follows. The keypad pins are numbered as shown in [Figure 22-2](ch22.xhtml#ch22fig2).

    | **KEYPAD** | **ARDUINO** |
    | --- | --- |
    | Pin 1 | Pin 9 |
    | Pin 2 | Pin 8 |
    | Pin 3 | Pin 7 |
    | Pin 4 | Pin 6 |
    | Pin 5 | Pin 5 |
    | Pin 6 | Pin 4 |
    | Pin 7 | Pin 3 |
    | Pin 8 | Pin 2 |

    **FIGURE 22-2:**
    Keypad pins 1–8

    ![image](../images/f22-02.jpg)
2.  Place a green LED and a red LED into the breadboard with the shorter, negative legs connected to the Arduino GND rail. Add a 220-ohm resistor to each longer, positive leg. Connect the resistor that’s attached to the green LED to Arduino pin 11, and the resistor that’s attached to the red LED to Arduino pin 12.

    | **LEDS** | **ARDUINO** |
    | --- | --- |
    | Positive legs | Pins 11 and 12 via 220-ohm resistors |
    | Negative legs | GND |

3.  Now attach the servo (see [Figure 22-3](ch22.xhtml#ch22fig3)). Connect the brown wire to the GND rail, the red wire to the +5V rail, and the yellow/white wire directly to pin 13 on the Arduino.

    | **SERVO** | **ARDUINO** |
    | --- | --- |
    | Brown wire | GND |
    | Red wire | +5V |
    | Yellow wire | Pin 13 |

    **FIGURE 22-3:**
    Attaching the servo

    ![image](../images/f22-03.jpg)
4.  Make sure your setup matches that of [Figure 22-4](ch22.xhtml#ch22fig4), and upload the code in “[The Sketch](ch22.xhtml#ch22lev1sec04)” on [page 192](ch22.xhtml#page_192).

    **FIGURE 22-4:**
    Circuit diagram for the keypad entry system

    ![image](../images/f22-04.jpg)

### **THE SKETCH**

First, the sketch calls on the Keypad, Servo, and Password libraries. The Servo library is included in the IDE, but you’ll have to download the Keypad and Password libraries (*[http://nostarch.com/arduinohandbook/](http://nostarch.com/arduinohandbook/)*). We then set the eight pins that will determine the input from the keypad, and set Arduino pins 11 and 12 to control the LEDs and pin 13 to control the servomotor. The Arduino waits for your code input from the keypad and for you to confirm your input with *. Once you’ve pressed the asterisk key, the sketch will check the entry against the password in the code. If the entry doesn’t match the password, the red LED will be set to `HIGH` and light; if the entry *does* match the password, the green LED will be set to `HIGH` and light, and the servomotor will turn. Pressing # will reset the sketch so it’s ready for another entry.

To alter the password, change the number in quotation marks in the following line.

```
Password password = Password("2468");
```

The default password in the sketch is 2468.

```
/* Keypad Library for Arduino
   Authors: Mark Stanley, Alexander Brevig
   http://playground.arduino.cc/Main/KeypadTutorial
*/

#include <Password.h>
#include <Keypad.h>
#include <Servo.h>

Servo myservo;
Password password = Password("2468"); // Set password

const byte ROWS = 4; // Set four rows
const byte COLS = 4; // Set four columns

char keys[ROWS][COLS] = { // Define the keymap
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = { 9,8,7,6 };  // Pins connected to keypad
                                   // ROW0, ROW1, ROW2 and ROW3
byte colPins[COLS] = { 5,4,3,2, }; // Pins connected to keypad
                                   // COL0, COL1 and COL2
// Create the keypad
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins,
                       ROWS, COLS);
void setup() {
  Serial.begin(9600);
  delay(200);
  pinMode(11, OUTPUT); // Set green LED as output
  pinMode(12, OUTPUT); // Set red LED as output
  myservo.attach(13);  // Pin connected to servo
  keypad.addEventListener(keypadEvent); // Add an event listener to
                                        // detect keypresses
}

void loop() {
  keypad.getKey();
  myservo.write(0);
}

void keypadEvent(KeypadEvent eKey) {
  switch (keypad.getState()) {
    case PRESSED:
    Serial.print("Pressed: ");
    Serial.println(eKey);
    switch (eKey) {
      case '*': checkPassword(); break;
      case '#': password.reset(); break;
      default: password.append(eKey);
    }
  }
}

void checkPassword() {
  if (password.evaluate() ){
    Serial.println("Success"); // If the password is correct...
    myservo.write(90);         // Move servo arm 90 degrees
    digitalWrite(11, HIGH);    // Turn on green LED
    delay(500);                // Wait 5 seconds
    digitalWrite(11, LOW);     // Turn off green LED
  } else {
    Serial.println("Wrong");   // If the password is incorrect...
    myservo.write(0);
    digitalWrite(12, HIGH);    // Turn on red LED
    delay(500);                // Wait 5 seconds
    digitalWrite(12, LOW);     // Turn off red LED

  }
}
```

## PROJECT 23: WIRELESS ID CARD ENTRY SYSTEM

**IN THIS PROJECT, WE’LL USE A RADIO FREQUENCY IDENTIFICATION (RFID) READER TO BUILD A WIRELESS ID CARD ENTRY SYSTEM.**

![image](../images/f0194-01.jpg)![image](../images/f0195-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• Mifare RFID-RC522 module

• Tower Pro SG90 9g servomotor

• Piezo buzzer

• Red LED

• Green LED

• 2 220-ohm resistors

**LIBRARIES REQUIRED**

• RFID

• SPI

• Wire

• Servo

• Pitches

### **HOW IT WORKS**

An RFID reader uses wireless technology to identify a card, tag, or key fob without contact. The reader will respond when the card is placed near it. First, we need the reader to read the unique number of our RFID card, and then we’ll add a servo that will move depending on whether the RFID reader recognizes the card. We could use this ID system for something like a door or box lock, as with the secret knock code lock in [Project 9](ch09.xhtml#ch09).

You may have seen a sticker like the one in [Figure 23-1](ch23.xhtml#ch23fig1) on an item you have purchased. These stickers use RFID to allow the store to track items for security purposes. If you pass through the RFID field at the exit without paying, the stickers will set off the alarm. RFID readers and cards are also often used as identification to allow access into restricted areas, like top-secret labs or gated communities.

**FIGURE 23-1:**
An RFID sticker

![image](../images/f23-01.jpg)

There are two types of RFID: passive and active. Each RFID system uses a radio frequency to exchange a signal between the reader and the tag or card. This signal contains the tag or card’s unique code, and if the RFID reader recognizes that code, it reacts appropriately—for example, by allowing the item to pass through the detectors in a store or by unlocking a door.

In a passive system, when the two are passed close to each other, the reader’s radio signal powers the circuit in the tag or card just enough for them to exchange data. Active systems have a powered reader and a powered tag and can read tags accurately from much farther away. Active systems are very expensive and used for more sophisticated applications, so we’ll be using a passive RFID system: the Mifare RFID-RC522 reader, which comes with a blank card and key fob, like those shown in [Figure 23-2](ch23.xhtml#ch23fig2). The reader operates at 13.56 MHz, which means it can identify the card or fob, each of which is powered by the reader, only if it is less than a few inches away. It’s important to keep this in mind when positioning your reader.

**FIGURE 23-2:**
RFID reader with card and key fob

![image](../images/f23-02.jpg)

We’ll create an RFID-controlled servo. When you pass your card in front of the RFID reader, it reads the card. If the module recognizes the card and the card has access rights, the green LED lights up, a tune plays, and the servomotor moves 180 degrees. If the module does not recognize the card, the red LED lights up, a different tune plays, and the servo does not move.

[Table 23-1](ch23.xhtml#ch23tab1) describes the various functions of the RFID reader.

**TABLE 23-1:**
Functions of the RFID reader pins

| **RFID** | **DETAIL** | **NOTES** |
| --- | --- | --- |
| 3.3V | 3.3 volts | The module can use only this amount of voltage. |
| RST | Reset | Will clear the module to initial state. |
| GND | Ground | Connects to the Arduino GND pin. |
| IRQ | Interrupt Request | Not used in this project. |
| MISO | Master In Slave Out | Sometimes referred to as “data in.” |
| MOSI | Master Out Slave In | Sometimes referred to as “data out.” |
| SCK | Serial Clock | Output from master. This creates a pulse that synchronizes data, usually set by the master. |
| SDA/SS | Serial Data/Slave Select | Modules will have either SDA or SS, although they are the same. This is how the Arduino and module share data and communicate. |
| Pin 16 | VCC | Positive power. |

### **THE BUILD**

1.  You may need to set up the module by soldering the header pins to it first. Snap off a strip of eight header pins. Solder one header pin to each point. Make sure to hold the solder iron in place for only a few seconds so you don’t damage the circuits. See the “[Quick Soldering Guide](ch00.xhtml#ch00lev1sec07)” on [page 18](ch00.xhtml#page_18) for a primer on soldering.

2.  Place your RFID module into a breadboard as shown in [Figure 23-3](ch23.xhtml#ch23fig3), and then connect the RFID pins to the Arduino pins as indicated in the following table. Remember to connect the RFID board to 3.3V power on the Arduino (not +5V), or you will damage the module.

    **FIGURE 23-3:**
    Placing the RFID module into the breadboard

    ![image](../images/f23-03.jpg)

    | **RFID** | **ARDUINO** |
    | --- | --- |
    | 3.3V | 3.3V |
    | RST | Pin 5 |
    | GND | GND |
    | IRQ | Not used |
    | MISO | Pin 12 |
    | MOSI | Pin 11 |
    | SCK | Pin 13 |
    | SDA | Pin 10 |

3.  Now we need to check that the RFID module is working. Download the RFID library from *[http://www.nostarch.com/arduinohandbook/](http://www.nostarch.com/arduinohandbook/)* and save it in your *libraries* directory (see “[Libraries](ch00.xhtml#ch00lev2sec07)” on [page 7](ch00.xhtml#page_7) for details on downloading libraries). Upload the following test sketch for the RFID reader. Keep the USB cable from your PC connected to the Arduino.

    ```
    // RFID Library Created by Miguel Balboa (circuitito.com)
    #include <SPI.h>
    #include <RFID.h>
    #define SS_PIN 10
    #define RST_PIN 9
    RFID rfid(SS_PIN, RST_PIN);

    // Setup variables
    int serNum0;
    int serNum1;
    int serNum2;
    int serNum3;
    int serNum4;

    void setup() {
      Serial.begin(9600);
      SPI.begin();
      rfid.init();
    }

    void loop() { // This loop looks for a card(s) to read
      if (rfid.isCard()) {
        if (rfid.readCardSerial()) {
          if (rfid.serNum[0] != serNum0
              && rfid.serNum[1] != serNum1
              && rfid.serNum[2] != serNum2
              && rfid.serNum[3] != serNum3
              && rfid.serNum[4] != serNum4
             ) {
            // When a card is found, the following code will run
            Serial.println(" ");
            Serial.println("Card found");
            serNum0 = rfid.serNum[0];
            serNum1 = rfid.serNum[1];
            serNum2 = rfid.serNum[2];
            serNum3 = rfid.serNum[3];
            serNum4 = rfid.serNum[4];

            // Print the card ID to the Serial Monitor of the IDE
            Serial.println("Cardnumber:");
            Serial.print("Dec: ");
            Serial.print(rfid.serNum[0], DEC);
            Serial.print(", ");
            Serial.print(rfid.serNum[1], DEC);
            Serial.print(", ");
            Serial.print(rfid.serNum[2], DEC);
            Serial.print(", ");
            Serial.print(rfid.serNum[3], DEC);
            Serial.print(", ");
            Serial.print(rfid.serNum[4], DEC);
            Serial.println(" ");
            Serial.print("Hex: ");
            Serial.print(rfid.serNum[0], HEX);
            Serial.print(", ");
            Serial.print(rfid.serNum[1], HEX);
            Serial.print(", ");
            Serial.print(rfid.serNum[2], HEX);
            Serial.print(", ");
            Serial.print(rfid.serNum[3], HEX);
            Serial.print(", ");
            Serial.print(rfid.serNum[4], HEX);
            Serial.println(" ");

          } else {
            // If the ID matches, write a dot to the Serial Monitor
            Serial.print(".");
          }
        }
      }
      rfid.halt();
    }
    ```

4.  Open the Arduino Serial Monitor in your IDE.

5.  Pass either your card or key fob in front of the RFID module. The unique number should appear on the Serial Monitor, as shown in [Figure 23-4](ch23.xhtml#ch23fig4). Write down this number, because you’ll need it later. In this case, my card number is 4D 55 AD D3 66.

    **FIGURE 23-4:**
    The RFID number represented in hexadecimal on the screen

    ![image](../images/f23-04.jpg)
6.  Insert the two LEDs into the breadboard, with the shorter, negative wires connected to the GND rail. Connect the longer, positive wire on the red LED to Arduino pin 3 via a 220-ohm resistor. Connect the positive leg of the green LED to pin 2 via another 220-ohm resistor.

    | **LEDS** | **ARDUINO** |
    | --- | --- |
    | Negative legs | GND |
    | Positive leg (red) | Pin 3 via 220-ohm resistor |
    | Positive leg (green) | Pin 2 via 220-ohm resistor |

7.  Connect the servo to the Arduino by attaching the red wire to +5V, the brown (or black) wire to GND, and the yellow wire to Arduino pin 9.

    | **SERVO** | **ARDUINO** |
    | --- | --- |
    | Red wire | +5V |
    | Black wire | GND |
    | Yellow wire | Pin 9 |

8.  Connect the piezo buzzer to the Arduino by attaching the red wire to Arduino pin 8 and the black wire to GND. Your build should now look something like [Figure 23-5](ch23.xhtml#ch23fig5).

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Red wire | Pin 8 |
    | Black wire | GND |

    **FIGURE 23-5:**
    Completed RFID project

    ![image](../images/f23-05.jpg)
9.  Open the project code in your Arduino IDE and change the following line to match the hex number you found for your card or key fob in step 5 using the RFID reader. Leave the `0x` as it appears, but fill in the rest with your number.

    ```
    byte card[5] = {0x4D,0x55,0xAD,0xD3,0x66};
    ```

10.  Confirm that your setup matches the circuit diagram in [Figure 23-6](ch23.xhtml#ch23fig6), and then upload the code from “[The Sketch](ch23.xhtml#ch23lev1sec03)” on [page 203](ch23.xhtml#page_203) to your Arduino.

    **FIGURE 23-6:**
    Circuit diagram for the wireless ID card entry system

    ![image](../images/f23-06.jpg)

### **THE SKETCH**

The sketch begins by calling on the SPI, RFID, Servo, Pitches, and Wire libraries to control communication between the Arduino, RFID module, and servo. Two melodies are defined, one for a positive reading on your card and the other for a negative reading. The green LED is set to Arduino pin 2, the red LED to pin 3, the piezo buzzer to pin 8, and the servo to pin 9.

The following line is where you add your card’s hex value:

```
byte card[5] = {0x4D,0x55,0xAD,0xD3,0x66};
```

Pass your card in front of the reader. If the hex code on the card matches that in your sketch, the green LED lights up, a tune plays, and the servo moves. The reader rejects all other cards unless you add their number to the code at ➊. If a card is rejected, the red LED lights up and a different tune plays, but the servo does not move.

```
   #include <SPI.h>
   #include <RFID.h>
   #include <Servo.h>
   #include "pitches.h"
   #include <Wire.h>

   RFID rfid(10, 5); // Define the RFID

   // Replace this with the code from your card in hex form
➊ byte card[5] = {0x4D,0x55,0xAD,0xD3,0x66};
   // List any other codes for cards with access here

   byte serNum[5];
   byte data[5];

   // Define the melodies for successful access and denied access
   int access_melody[] = {NOTE_G4, 0, NOTE_A4, 0, NOTE_B4, 0, NOTE_A4,
   0, NOTE_B4, 0, NOTE_C5, 0};
   int access_noteDurations[] = {8, 8, 8, 8, 8, 4, 8, 8, 8, 8, 8, 4};
   int fail_melody[] = {NOTE_G2, 0, NOTE_F2, 0, NOTE_D2, 0};
   int fail_noteDurations[] = {8, 8, 8, 8, 8, 4};

   int LED_access = 2;   // Pin connected to green LED
   int LED_intruder = 3; // Pin connected to red LED
   int speaker_pin = 8;  // Pin connected to piezo buzzer
   int servoPin = 9;     // Pin connected to servo

   Servo doorLock; // Define the servomotor

   void setup() {
     doorLock.attach(servoPin); // Set servo as a pin
     Serial.begin(9600); // Start serial communication
     SPI.begin(); // Start serial communication between the RFID and PC
     rfid.init(); // Initialize the RFID
     Serial.println("Arduino card reader");
     delay(1000);
     pinMode(LED_access, OUTPUT);
     pinMode(LED_intruder, OUTPUT);
     pinMode(speaker_pin, OUTPUT);
     pinMode(servoPin, OUTPUT);
   }

   void loop() { // Create a variable for each user
     boolean card_card = true; // Define your card
     if (rfid.isCard()) {
       if (rfid.readCardSerial()) {
         delay(1000);
         data[0] = rfid.serNum[0];
         data[1] = rfid.serNum[1];
         data[2] = rfid.serNum[2];
         data[3] = rfid.serNum[3];
         data[4] = rfid.serNum[4];
       }
       Serial.print("Card found - code:");
       for (int i = 0; i < 5; i++) {
         // If it is not your card, the card is considered false
         if (data[i] != card[i]) card_card = false;
       }
       Serial.println();
       if (card_card) { // A card with access permission is found
         Serial.println("Hello!"); // Print to Serial Monitor
         for (int i = 0; i < 12; i++) { // Play welcome music
           int access_noteDuration = 1000 / access_noteDurations[i];
           tone(speaker_pin, access_melody[i], access_noteDuration);
           int access_pauseBetweenNotes = access_noteDuration * 1.30;
           delay(access_pauseBetweenNotes);
           noTone(speaker_pin);
         }
       }
       else { // If the card is not recognized
         // Print message to Serial Monitor
         Serial.println("Card not recognized! Contact administrator!");
         digitalWrite(LED_intruder, HIGH); // Turn on red LED
         for (int i = 0; i < 6; i++) { // Play intruder melody
           int fail_noteDuration = 1000 / fail_noteDurations[i];
           tone(speaker_pin, fail_melody[i], fail_noteDuration);
           int fail_pauseBetweenNotes = fail_noteDuration * 1.30;
           delay(fail_pauseBetweenNotes);
           noTone(speaker_pin);
         }
         delay(1000);
         digitalWrite(LED_intruder, LOW); // Turn off red LED
       }
    if (card_card) { // Add other users with access here
         Serial.println("Access granted.......Welcome!");
         digitalWrite(LED_access, HIGH); // Turn on green LED
         doorLock.write(180); // Turn servo 180 degrees
         delay(5000); // Wait for 5 seconds
         doorLock.write(0); // Turn servo back to 0 degrees
         digitalWrite(LED_access, LOW); // Turn off green LED
       }
       Serial.println();
       delay(500);
       rfid.halt();
     }
   }
```
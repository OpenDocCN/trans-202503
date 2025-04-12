# **PART 1**
![image](../images/common-01.jpg)
**LEDS**

## PROJECT 1: PUSHBUTTON-CONTROLLED LED

**IN THIS PROJECT, YOU’LL ADD A PUSHBUTTON SWITCH TO AN LED CIRCUIT TO CONTROL WHEN THE LED IS LIT.**

![image](../images/f0022-01.jpg)![image](../images/f0023-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• LED

• Momentary tactile four-pin pushbutton

• 10k-ohm resistor

• 220-ohm resistor

This project will take you through the basics of switches, which you’ll be using a lot throughout this book. Almost all electrical items use switches to turn an element on or off. There are many types of switches, and the one you’ll use now is a pushbutton ([Figure 1-1](ch01.xhtml#ch1fig1)).

**FIGURE 1-1:**
A pushbutton

![image](../images/f01-01.jpg)

### **HOW IT WORKS**

When pressed, a pushbutton completes a circuit, turning it on. As soon as the button is released, the connection will spring back and break that circuit, turning it off. The pushbutton switch is also known as a *momentary* or *normally open* switch, and is used in, for example, computer keyboards. This is in contrast to a *toggle switch*, which stays either on or off until you toggle it to the other position, like a light switch.

This type of pushbutton has four pins, but you generally use only two at a time for connection. You’ll use the top connections in this project, although the two unused pins at the bottom would do the same job. As [Figure 1-2](ch01.xhtml#ch1fig2) shows, the pins work in a circuit. Pins A and C are always connected, as are pins B and D. When the button is pressed, the circuit is complete.

**FIGURE 1-2:**
A pushbutton’s incomplete circuit

![image](../images/f01-02.jpg)

### **THE BUILD**

1.  Place your pushbutton in a breadboard, as shown in [Figure 1-3](ch01.xhtml#ch1fig3).

    **FIGURE 1-3:**
    Placing your pushbutton

    ![image](../images/f01-03.jpg)
2.  Connect pin A to one leg of a 10k-ohm resistor, and connect that same resistor leg to Arduino pin 2\. Connect the other resistor leg to the GND rail, and connect the GND rail to the Arduino’s GND. Connect pin B on the switch to the +5V rail, and connect this rail to +5V on the Arduino.

    | **PUSHBUTTON** | **ARDUINO** |
    | --- | --- |
    | Pin A | GND and pin 2 via 10k-ohm resistor |
    | Pin B | +5V |

3.  Add the LED to your breadboard, connecting the longer, positive leg to Arduino pin 13 via a 220-ohm resistor and the shorter leg to GND.

    | **LED** | **ARDUINO** |
    | --- | --- |
    | Positive leg | Pin 13 via 220-ohm resistor |
    | Negative leg | GND |

4.  Confirm that your setup matches the circuit diagram shown in [Figure 1-4](ch01.xhtml#ch1fig4), and then upload the code in “[The Sketch](ch01.xhtml#ch01lev1sec03)” on [page 27](ch01.xhtml#page_27).

    **FIGURE 1-4:**
    Circuit diagram for the pushbutton-controlled LED

    ![image](../images/f01-04.jpg)

### **THE SKETCH**

In this sketch, you assign a pin for the pushbutton and set it as `INPUT`, and a pin for the LED and set it as `OUTPUT`. The code tells the Arduino to turn the LED on as long as the button is being pressed (completing the circuit), and to keep the LED off when the button is not being pressed. When the button is released, the circuit breaks and the LED will turn off again.

```
/* by DojoDave <http://www.0j0.org>
   modified 30 Aug 2011 by Tom Igoe
   This example code is in the public domain.
   http://www.arduino.cc/en/Tutorial/Button
*/

const int buttonPin = 2;      // Pin connected to pushbutton
const int ledPin = 13;        // Pin connected to LED
int buttonState = 0;          // Give pushbutton a value

void setup() {
  pinMode(ledPin, OUTPUT);    // Set LED pin as output
  pinMode(buttonPin, INPUT);  // Set pushbutton pin as input
}

void loop() {
  buttonState = digitalRead(buttonPin); // Read input from pin 2
  if (buttonState == HIGH) { // If pushbutton is pressed, set as HIGH
    digitalWrite(ledPin, HIGH); // Turn on LED
  }
  else {
    digitalWrite(ledPin, LOW);  // Otherwise, turn off LED
  }
}
```

## PROJECT 2: LIGHT DIMMER

**IN THIS PROJECT, YOU’LL CREATE A DIMMER SWITCH BY ADDING A POTENTIOMETER TO CONTROL THE BRIGHTNESS OF AN LED.**

![image](../images/f0028-01.jpg)![image](../images/f0029-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• LED

• 50k-ohm potentiometer

• 470-ohm resistor

A *potentiometer* is a variable resistor with a knob that allows you to alter the resistance of the potentiometer as you turn it. It is commonly used in electrical devices such as volume controls on audio equipment. This project uses a 50k-ohm potentiometer.

### **HOW IT WORKS**

The potentiometer manipulates a continuous *analog* signal, which represents physical measurements. Humans perceive the world in analog; everything we see and hear is a continuous transmission of information to our senses. This continuous stream is what defines analog data. Digital information, on the other hand, estimates analog data using only numbers. To approximate the continuous analog data from the potentiometer, the Arduino must represent the signal as a series of discrete numbers—in this case, voltages. The center pin of the potentiometer sends the signal to an Arduino analog IN—any pin from A0 to A5—to read the value.

The LED is actually being switched on and off, but it happens so quickly that our eyes compensate and we see a continuously lit LED at varying light levels. This is known as *persistence of vision*.

To create persistence of vision, the Arduino uses a technique called *pulse width modulation (PWM)*. The Arduino creates a pulse by switching the power on and off very quickly. The duration that the power is on or off (known as the *pulse width*) in the cycle determines the average output, and by varying this pulse width the pattern can simulate voltages between full on (5 volts) and off (0 volts). If the signal from the Arduino is on for half the time and off for half, the average output will be 2.5 volts, halfway between 0 and 5\. If the signal is on for 80 percent and off for 20 percent, then the average voltage is 4 volts, and so on. You can vary the signal, which in turn varies the pulse width, by turning the potentiometer left or right, increasing or decreasing the resistance.

Using this technique, you can change the voltage sent to the LED and make it dimmer or brighter to match the analog signal from the potentiometer. Only pins 3, 5, 6, 9, 10, or 11 on the Arduino can use PWM. [Figure 2-1](ch02.xhtml#ch2fig1) gives examples of how PWM would look as a waveform.

**FIGURE 2-1:**
Pulse width modulation as a waveform

![image](../images/f02-01.jpg)

### **THE BUILD**

1.  Insert the potentiometer into your breadboard and connect the center pin to the Arduino’s A0 pin. Connect one of the outer pins to the +5V rail of the breadboard and the other outer pin to GND on the breadboard (it doesn’t actually matter which way around the outer potentiometer pins are connected; these instructions just reflect the diagrams in this project), as shown in [Figure 2-2](ch02.xhtml#ch2fig2).

    **FIGURE 2-2:**
    Connecting the potentiometer to the Arduino

    ![image](../images/f02-02.jpg)

    | **POTENTIOMETER** | **ARDUINO** |
    | --- | --- |
    | Left pin | +5V |
    | Center pin | A0 |
    | Right pin | GND |

2.  Insert the LED into the breadboard. Attach the positive leg (the longer leg) to pin 9 of the Arduino via the 470-ohm resistor, and the negative leg to GND, as shown in [Figure 2-3](ch02.xhtml#ch2fig3).

    | **LED** | **ARDUINO** |
    | --- | --- |
    | Positive leg | Pin 9 |
    | Negative leg | GND via 470-ohm resistor |

    **FIGURE 2-3:**
    Circuit diagram for the light dimmer

    ![image](../images/f02-03.jpg)
3.  Upload the code in “[The Sketch](ch01.xhtml#ch01lev1sec03)” below.

4.  Turn the potentiometer to control the brightness of the LED.

This project has many potential uses: you can cluster a number of LEDs together to create an adjustable flashlight, a night-light, a display case light, or anything else that uses dimming lights.

### **THE SKETCH**

This sketch works by setting pin A0 as your potentiometer and pin 9 as an `OUTPUT` to power the LED. You then run a loop that continually reads the value from the potentiometer and sends that value as voltage to the LED. The voltage value is between 0–5 volts, and the brightness of the LED will vary accordingly.

```
/* http://arduino.cc/en/Reference/AnalogWrite by Tom Igoe
   from http:itp.nyu.edu/physcomp/Labs/AnalogIn */

int potPin = A0; // Analog input pin connected to the potentiometer
int potValue = 0; // Value that will be read from the potentiometer
int led = 9; // Pin 9 (connected to the LED) is capable of PWM

// Runs once at beginning of the program
void setup() {
  pinMode(led, OUTPUT); // Set pin 9 to output
}

// Loops continuously
void loop() {
  potValue = analogRead(potPin); // Read potentiometer value
                                 // from A0 pin
  analogWrite(led, potValue/4);  // Send potentiometer value to LED
                                 // to control brightness with PWM
  delay(10);                     // Wait for 10 ms
}
```

## PROJECT 3: BAR GRAPH

**IN THIS PROJECT, YOU’LL COMBINE WHAT YOU’VE LEARNED IN THE PREVIOUS LED PROJECTS TO CREATE AN LED BAR GRAPH THAT YOU CAN CONTROL WITH A POTENTIOMETER.**

![image](../images/f0034-01.jpg)![image](../images/f0035-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 9 LEDs

• 50k-ohm potentiometer

• 9 220-ohm resistors

### **HOW IT WORKS**

A bar graph is a series of LEDs in a line, similar to what you might see on an audio display. It’s made up of a row of LEDs with an analog input, like a potentiometer or microphone. In this project, you use the analog signal from the potentiometer to control which LEDs are lit. When you turn the potentiometer one way, the LEDs light up one at a time in sequence, as shown in [Figure 3-1](ch03.xhtml#ch3fig1)(a), until they are all on, shown in [Figure 3-1](ch03.xhtml#ch3fig1)(b). When you turn it the other way, they turn off in sequence, as shown in [Figure 3-1](ch03.xhtml#ch3fig1)(c).

**FIGURE 3-1:**
The LEDs light up and turn off in sequence as you turn the potentiometer.

![image](../images/f03-01.jpg)

### **THE BUILD**

1.  Insert the LEDs into the breadboard with their shorter, negative legs in the GND rail. Connect this rail to Arduino GND using a jumper wire.

2.  Insert a 220-ohm resistor for each LED into the breadboard, with one resistor leg connected to the positive LED leg. Connect the other legs of the resistors to digital pins 2–10 in sequence, as shown in [Figure 3-2](ch03.xhtml#ch3fig2). It’s important that the resistors bridge the break in the breadboard as shown.

    | **LEDS** | **ARDUINO** |
    | --- | --- |
    | Positive legs | Pins 2–10 via 220-ohm resistor |
    | Negative legs | GND |

    **FIGURE 3-2:**
    Circuit diagram for the bar graph

    ![image](../images/f03-02.jpg)

    **NOTE**

    *As mentioned in [Project 2](ch02.xhtml#ch02), it doesn’t actually matter which way the outer potentiometer pins are connected, but I’ve given instructions here to reflect the images.*

3.  Place the potentiometer in the breadboard and connect the center pin to Arduino A0\. Connect the right outer pin to +5V and the left potentiometer pin to GND.

    | **POTENTIOMETER** | **ARDUINO** |
    | --- | --- |
    | Left pin | GND |
    | Center pin | A0 |
    | Right pin | +5V |

4.  Upload the code in “[The Sketch](ch03.xhtml#ch03lev1sec03)” below.

### **THE SKETCH**

The sketch first reads the input from the potentiometer. It maps the input value to the output range, in this case nine LEDs. Then it sets up a `for` loop over the outputs. If the output number of the LED in the series is lower than the mapped input range, the LED turns on; if not, it turns off. See? Simple! If you turn the potentiometer to the right, the LEDs light up in sequence. Turn it to the left, and they turn off in sequence.

```
/* By Tom Igoe. This example code is in the public domain.
   http://www.arduino.cc/en/Tutorial/BarGraph */

const int analogPin = A0; // Pin connected to the potentiometer
const int ledCount = 9;   // Number of LEDs
int ledPins[] = {2,3,4,5,6,7,8,9,10}; // Pins connected to the LEDs

void setup() {
  for (int thisLed = 0; thisLed < ledCount; thisLed++) {
    pinMode(ledPins[thisLed], OUTPUT); // Set the LED pins as output
  }
}

// Start a loop
void loop() {
  int sensorReading = analogRead(analogPin); // Analog input
  int ledLevel = map(sensorReading, 0, 1023, 0, ledCount);
  for (int thisLed = 0; thisLed < ledCount; thisLed++) {
    if (thisLed < ledLevel) { // Turn on LEDs in sequence
      digitalWrite(ledPins[thisLed], HIGH);
    }
    else { // Turn off LEDs in sequence
      digitalWrite(ledPins[thisLed], LOW);
    }
  }
}
```

## PROJECT 4: DISCO STROBE LIGHT

**IN THIS PROJECT, YOU’LL APPLY THE SKILLS YOU LEARNED IN [PROJECT 3](ch03.xhtml#ch03) TO MAKE A STROBE LIGHT WITH ADJUSTABLE SPEED SETTINGS.**

![image](../images/f0039-01.jpg)![image](../images/f0040-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 2 blue LEDs

• 2 red LEDs

• 50k-ohm potentiometer

• 4 220-ohm resistors

### **HOW IT WORKS**

Turning the potentiometer up or down changes the speed of the flashing lights, creating a strobe effect. You can use red and blue LEDs for a flashing police light effect (see [Figure 4-1](ch04.xhtml#ch4fig1)). Connect the LEDs of the same color to the same Arduino pin so they’ll always light together. If you build a casing to house your LEDs, you’ll have your own mobile strobe unit. You can add up to 10 LEDs; just update the sketch to include your output pins and the new number of LEDs.

**FIGURE 4-1:**
Red and blue LEDs mimic the lights of a police car.

![image](../images/f04-01.jpg)

### **THE BUILD**

1.  Place your LEDs into the breadboard with the short, negative legs in the GND rail, and then connect this rail to Arduino GND.

    **NOTE**

    *Remember to add power to the breadboard.*

2.  Insert the resistors into the board, connecting them to the longer, positive legs of the LEDs. Use jumper wires to connect the two red LEDs together and the two blue LEDs together via the resistors, as shown in [Figure 4-2](ch04.xhtml#ch4fig2); this allows the LEDs of the same color to be controlled by a single pin.

    **FIGURE 4-2:**
    Connecting LEDs with jumper wires

    ![image](../images/f04-02.jpg)
3.  Connect the red LEDs to Arduino pin 12 and the blue LEDs to Arduino pin 11.

    | **LEDS** | **ARDUINO** |
    | --- | --- |
    | Negative legs | GND |
    | Positive leg (red) | Pin 12 |
    | Positive leg (blue) | Pin 11 |

4.  Place the potentiometer in the breadboard and connect the center pin to Arduino A0, the left pin to GND, and the right pin to +5V.

    | **POTENTIOMETER** | **ARDUINO** |
    | --- | --- |
    | Left pin | GND |
    | Center pin | A0 |
    | Right pin | +5V |

5.  Confirm that your setup matches that of [Figure 4-3](ch04.xhtml#ch4fig3), and then upload the code in “[The Sketch](ch04.xhtml#ch04lev1sec03)” on [page 43](ch04.xhtml#page_43).

    **FIGURE 4-3:**
    Circuit diagram for the disco strobe light

    ![image](../images/f04-03.jpg)

### **THE SKETCH**

The sketch works by setting the analog signal from the potentiometer to the Arduino as an input and the pins connected to the LEDs as outputs. The Arduino reads the analog input from the potentiometer and uses this value as the *delay value*—the amount of time that passes before the LEDs change state (either on or off). This means that the LEDs are on and off for the duration of the potentiometer value, so changing this value alters the speed of the flashing. The sketch cycles through the LEDs to produce a strobe effect.

```
const int analogInPin = A0; // Analog input pin connected to the
                            // potentiometer
int sensorValue = 0;        // Value read from the potentiometer
int timer = 0;              // Delay value

// Set digital pins 12 and 11 as outputs
void setup() {
  pinMode(12, OUTPUT);
  pinMode(11, OUTPUT);
}

// Start a loop to turn LEDs on and off with a delay in between
void loop() {
  sensorValue = analogRead(analogInPin); // Read value from the
                                         // potentiometer
  timer = map(sensorValue, 0, 1023, 10, 500); // Delay 10 to 500 ms
  digitalWrite(12, HIGH); // LED turns on
  delay(timer);           // Delay depending on potentiometer value
  digitalWrite(12, LOW);  // LED turns off
  delay(timer);
  digitalWrite(12, HIGH);
  delay(timer);
  digitalWrite(12, LOW);
  digitalWrite(11, HIGH);
  delay(timer);
  digitalWrite(11, LOW);
  delay(timer);
  digitalWrite(11, HIGH);
  delay(timer);
  digitalWrite(11, LOW);
}
```

## PROJECT 5: PLANT MONITOR

**IN THIS PROJECT I’LL INTRODUCE A NEW TYPE OF ANALOG SENSOR THAT DETECTS MOISTURE LEVELS. YOU’LL SET UP A LIGHT AND SOUND ALARM SYSTEM TO TELL YOU WHEN YOUR PLANT NEEDS WATERING.**

![image](../images/f0045-01.jpg)![image](../images/f0046-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Jumper wires

• LED

• HL-69 hygrometer soil moisture sensor

• Piezo buzzer

### **HOW IT WORKS**

You’ll use an HL-69 moisture sensor, readily available online for a few dollars or from some of the retailers listed in [Appendix A](app01.xhtml#app01). The prongs of the sensor detect the moisture level in the surrounding soil by passing current through the soil and measuring the resistance. Damp soil conducts electricity easily, so it provides lower resistance, while dry soil conducts poorly and has a higher resistance.

The sensor consists of two parts, as shown in [Figure 5-1](ch05.xhtml#ch5fig1): the actual prong sensor (a) and the controller (b). The two pins on the sensor need to connect to the two separate pins on the controller (connecting wires are usually supplied). The other side of the controller has four pins, three of which connect to the Arduino.

**FIGURE 5-1:**
The HL-69 moisture sensor prong (a) and controller (b)

![image](../images/f05-01.jpg)

The four pins are, from left to right, AO (analog out), DO (digital out), GND, and VCC (see [Figure 5-2](ch05.xhtml#ch5fig2)). You can read the values from the controller through the IDE when it’s connected to your computer. This project doesn’t use a breadboard, so the connections are all made directly to the Arduino.

**FIGURE 5-2:**
The pins are labeled on the underside of the module

![image](../images/f05-02.jpg)

Lower readings indicate that more moisture is being detected, and higher readings indicate dryness. If your reading is above 900, your plant is seriously thirsty. If your plant gets too thirsty, the LED will light and the piezo buzzer will sound. *Piezos* are inexpensive buzzers and are explained more in [Project 7](ch07.xhtml#ch07).

### **THE BUILD**

1.  Connect the sensor’s two pins to the + and – pins on the controller using the provided connecting wires, as shown in [Figure 5-3](ch05.xhtml#ch5fig3).

    **FIGURE 5-3:**
    Connecting the sensor to the controller

    ![image](../images/f05-03.jpg)
2.  Connect the three prongs from the controller to +5V, GND, and Arduino A0 directly on the Arduino, as shown in the following table. The DO pin is not used.

    | **SENSOR CONTROLLER** | **ARDUINO** |
    | --- | --- |
    | VCC | +5V |
    | GND | GND |
    | A0 | A0 |
    | DO | Not used |

3.  Connect an LED directly to the Arduino with the shorter, negative leg in GND and the longer, positive leg in Arduino pin 13, as shown in [Figure 5-4](ch05.xhtml#ch5fig4).

    **FIGURE 5-4:**
    Connecting the LED to the Arduino

    ![image](../images/f05-04.jpg)

    | **LED** | **ARDUINO** |
    | --- | --- |
    | Positive leg | Pin 13 |
    | Negative leg | GND |

4.  Connect the piezo buzzer’s black wire to GND and its red wire to Arduino pin 11.

    | **PIEZO** | **ARDUINO** |
    | --- | --- |
    | Red wire | Pin 11 |
    | Black wire | GND |

5.  Check that your setup matches that of [Figure 5-5](ch05.xhtml#ch5fig5), and then upload the code in “[The Sketch](ch05.xhtml#ch05lev1sec03)” on [page 51](ch05.xhtml#page_51).

    **FIGURE 5-5:**
    Circuit diagram for the plant monitor

    ![image](../images/f05-05.jpg)
6.  Connect the Arduino to your computer using the USB cable. Open the Serial Monitor in your IDE to see the values from the sensor—this will also help you to calibrate your plant monitor. The IDE will display the value of the sensor’s reading. My value was 1000 with the sensor dry and not inserted in the soil, so I know this is the highest, and driest, value. To calibrate this value, turn the potentiometer on the controller clockwise to increase the resistance and counterclockwise to decrease it (see [Figure 5-5](ch05.xhtml#ch5fig5)).

    When the sensor is inserted into moist soil, the value will drop to about `400`. As the soil dries out, the sensor value rises; when it reaches `900`, the LED will light and the buzzer will sound.

    **FIGURE 5-6:**
    Turn the potentiometer to calibrate your plant monitor.

    ![image](../images/f05-06.jpg)

### **THE SKETCH**

The sketch first defines Arduino pin A0 so that it reads the moisture sensor value. It then defines Arduino pin 11 as output for the buzzer, and pin 13 as output for the LED. Use the `Serial.Println()` function to send the reading from the sensor to the IDE, in order to see the value on the screen.

Change the value in the line

```
if(analogRead(0) > 900){
```

depending on the reading from the sensor when it is dry (here it’s 900). When the soil is moist, this value will be below 900, so the LED and buzzer will remain off. When the value rises above 900, it means the soil is drying out, and the buzzer and LED will alert you to water your plant.

```
const int moistureAO = 0;
int AO = 0;       // Pin connected to A0 on the controller
int tmp = 0;      // Value of the analog pin
int buzzPin = 11; // Pin connected to the piezo buzzer
int LED = 13;     // Pin connected to the LED

void setup () {
  Serial.begin(9600); // Send Arduino reading to IDE
  Serial.println("Soil moisture sensor");
  pinMode(moistureAO, INPUT);
  pinMode(buzzPin, OUTPUT); // Set pin as output
  pinMode(LED, OUTPUT);     // Set pin as output
}

void loop () {
  tmp = analogRead( moistureAO );
  if ( tmp != AO ) {
    AO = tmp;
    Serial.print("A = "); // Show the resistance value of the sensor
                          // in the IDE
    Serial.println(AO);
  }
  delay (1000);
  if (analogRead(0) > 900) { // If the reading is higher than 900,
    digitalWrite(buzzPin, HIGH); // the buzzer will sound
    digitalWrite(LED, HIGH);     // and the LED will light
    delay(1000); // Wait for 1 second
    digitalWrite(buzzPin, LOW);
    digitalWrite(LED, HIGH);
  }
  else {
    digitalWrite(buzzPin, LOW); // If the reading is below 900,
                                // the buzzer and LED stay off
    digitalWrite(LED, LOW);
  }
}
```

## PROJECT 6: GHOST DETECTOR

**WHO WOULDN’T WANT TO MAKE A GHOST DETECTOR? THIS IS A REALLY SIMPLE PROJECT THAT DOESN’T TAKE LONG TO PUT TOGETHER, SO YOU CAN START DETECTING GHOSTS RIGHT AWAY.**

![image](../images/f0053-01.jpg)![image](../images/f0054-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 3 red LEDs

• 1 yellow LED

• 6 green LEDs

• 10 220-ohm resistors

• 20-centimeter length of single-core wire

• 1M-ohm resistor

### **HOW IT WORKS**

Okay, so I might be stretching things a bit by calling this project a ghost detector. This project actually detects *electromagnetic fields*, but many people believe this is how to tell if there are ghosts or spirits around.

In this project, you’ll set up a ghost-detecting antenna and LED bar graph system to tell whether there is a high level of electromagnetic activity in the vicinity. A length of bare wire acts as an antenna to pick up an electromagnetic field within a radius of two meters. Depending on the strength of the signal, the LEDs will light in sequence: the stronger the signal, the more LEDs will light. Power up the Arduino, and point your detector into a room to pick up any unusual presences. Be aware that electrical appliances such as televisions will cause the detector to dance around because of the signal they emit.

### **THE BUILD**

1.  Place the LEDs into the breadboard with the legs on either side of the center divide (see “[Breadboards](ch00.xhtml#ch00lev2sec03)” on [page 4](ch00.xhtml#page_4) for more on the layout of the breadboard), as shown in [Figure 6-1](ch06.xhtml#ch6fig1). I started with a yellow LED, then used six green and three red LEDs to create a scale from left to right. You can use any color LEDs and position them in the sequence you prefer.

    **FIGURE 6-1:**
    Placing the LEDs

    ![image](../images/f06-01.jpg)

    **ELECTROMAGNETIC FIELDS**

    *Electric fields* are created by differences in voltage: the higher the voltage, the stronger the resultant field. *Magnetic fields* are created when electric current flows: the greater the current, the stronger the magnetic field. An *electromagnetic field (EMF)* can be thought of as a combination of the two.

    ![image](../images/f0056-01.jpg)

    Electromagnetic fields are present everywhere in the environment but are invisible to the human eye. Electric fields are produced by the local buildup of electric charges in the atmosphere and associated with thunderstorms. The earth constantly emits a magnetic field. It is used by birds and fish for navigation and causes a compass needle to orient to the north.

2.  Connect one leg of a 220-ohm resistor to each negative LED leg, and insert the other resistor leg in the GND rail of the breadboard (see [Figure 6-2](ch06.xhtml#ch6fig2)). Connect each positive LED leg to digital pins 2 through 11 in turn.

    | **LEDS** | **ARDUINO** |
    | --- | --- |
    | Positive legs | Pins 2–11 |
    | Negative legs | GND via 220-ohm resistors |

    **FIGURE 6-2:**
    Connecting the LEDs to the breadboard

    ![image](../images/f06-02.jpg)
3.  Take the 20-centimeter length of single-core wire and use a wire stripper to strip about 1 centimeter of the insulation from one end. Attach this end to Arduino pin A5\. Strip about 7 centimeters from the other end—this open, bare wire end is your antenna and will pick up the electromagnetic signal (see [Figure 6-3](ch06.xhtml#ch6fig3)).

    **FIGURE 6-3:**
    Stripping wire to create an antenna

    ![image](../images/f06-03.jpg)
4.  Connect one leg of the 1M-ohm resistor directly to GND on the Arduino and the other leg to Arduino pin A5; this will increase the sensitivity of your device.

5.  Check that your setup matches that of [Figure 6-4](ch06.xhtml#ch6fig4), and then upload the code in “[The Sketch](ch06.xhtml#ch06lev1sec03)” on [page 59](ch06.xhtml#page_59).

    **FIGURE 6-4:**
    Circuit diagram for the ghost detector

    ![image](../images/f06-04.jpg)

### **THE SKETCH**

The bare wire picks up the signal from electromagnetic fields in the atmosphere and sends a value between 0 and 1023 to the Arduino. The sketch evaluates the reading from the analog pin to determine how many LEDs are switched on or off in sequence to indicate the strength of the electromagnetic signal. For example, 1023 would be the highest value, so all LEDs would be lit; a reading of 550 would light five LEDs. The sketch loops to continuously read the analog input, and the LED lights constantly move to show the reading. If you find that the EMF readings set off your LED sequence to the maximum level every time, reduce the `senseLimit` value to compensate. The sketch takes an average of 25 number readings each time it loops through, and uses the average from those readings to mitigate big fluctuations that may cause the LEDs to light up too quickly.

**NOTE**

*Once you’ve completed the ghost detector, try adding some sounds that beep at increasing speeds or volumes depending on the reading. Build a casing for the project to have your own handheld sensor to take on ghost-hunting endeavors. You can also experiment by trying various types and thicknesses of wire, and by taking away the resistor for different levels of sensitivity.*

```
// Code by James Newbould used with kind permission
#define NUMREADINGS 25 // Raise number to increase data smoothing
int senseLimit = 1023; // Raise number to decrease sensitivity of
                       // the antenna (up to 1023 max)
int probePin = 5; // Set analog pin 5 as the antenna pin
int val = 0;      // Reading from probePin

// Pin connections to LED bar graph with resistors in series
int LED1 = 11;
int LED2 = 10;
int LED3 = 9;
int LED4 = 8;
int LED5 = 7;
int LED6 = 6;
int LED7 = 5;
int LED8 = 4;
int LED9 = 3;
int LED10 = 2;
int readings[NUMREADINGS]; // Readings from the analog input
int index = 0;             // Index of the current reading
int total = 0;             // Running total
int average = 0;           // Final average of the probe reading

void setup() {
  pinMode(2, OUTPUT); // Set LED bar graph pins as outputs
  pinMode(3, OUTPUT);
  pinMode(4, OUTPUT);
  pinMode(5, OUTPUT);
  pinMode(6, OUTPUT);
  pinMode(7, OUTPUT);
  pinMode(8, OUTPUT);
  pinMode(9, OUTPUT);
  pinMode(10, OUTPUT);
  pinMode(11, OUTPUT);
 Serial.pinMode(9600); // Initiate serial connection with IDE for
                        // debugging and so on
  for (int i = 0; i < NUMREADINGS; i++)
    readings[i] = 0; // Initialize all readings to 0
}

void loop() {
  val = analogRead(probePin); // Take a reading from probe
  if (val >= 1) {             // If the reading isn't zero, proceed
    val = constrain(val, 1, senseLimit); // If the reading is
                                         // higher than the current
                                         // senseLimit value, update
                                         // senseLimit value with
                                         // higher reading
    val = map(val, 1, senseLimit, 1, 1023); // Remap the constrained
                                            // value within a 1 to
                                            // 1023 range
    total -= readings[index]; // Subtract the last reading
    readings[index] = val;    // Read from the sensor
    total += readings[index]; // Add the reading to the total
    index = (index + 1);      // Advance to the next index
    if (index >= NUMREADINGS) // If we're at the end of the array
      index = 0;              // loop around to the beginning
    average = total / NUMREADINGS; // Calculate the average reading
    if (average > 50) { // If the average reading is higher than 50
      digitalWrite(LED1, HIGH); // turn on the first LED
    }
    else {                        // If it's not
      digitalWrite(LED1, LOW);    // turn off that LED
    }
    if (average > 150) {          // And so on
      digitalWrite(LED2, HIGH);
    }
    else {
      digitalWrite(LED2, LOW);
    }
    if (average > 250) {
      digitalWrite(LED3, HIGH);
    }
    else {
      digitalWrite(LED3, LOW);
    }
    if (average > 350) {
      digitalWrite(LED4, HIGH);
    }
    else {
      digitalWrite(LED4, LOW);
    }
    if (average > 450) {
      digitalWrite(LED5, HIGH);
    }
    else {
      digitalWrite(LED5, LOW);
    }
    if (average > 550) {
      digitalWrite(LED6, HIGH);
    }
    else {
      digitalWrite(LED6, LOW);
    }
    if (average > 650) {
      digitalWrite(LED7, HIGH);
    }
    else {
      digitalWrite(LED7, LOW);
    }
    if (average > 750) {
      digitalWrite(LED8, HIGH);
    }
    else {
      digitalWrite(LED8, LOW);
    }
    if (average > 850) {
      digitalWrite(LED9, HIGH);
    }
    else {
      digitalWrite(LED9, LOW);
    }
    if (average > 950) {
      digitalWrite(LED10, HIGH);
    }
    else {
      digitalWrite(LED10, LOW);
    }
    Serial.println(val);   // Use output to aid in calibrating
  }
}
```
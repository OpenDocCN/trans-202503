# **PART 3**
![image](../images/common-01.jpg)
**SERVOS**

## PROJECT 10: JOYSTICK-CONTROLLED LASER

**IN THIS PROJECT WE CREATE A JOYSTICK-CONTROLLED LASER BY CONNECTING TWO SERVOS TO A JOYSTICK AND USING THIS SETUP AS A PAN-AND-TILT CONTROLLER FOR A LASER POINTER.**

![image](../images/f0086-01.jpg)![image](../images/f0087-01.jpg)

**PARTS REQUIRED**

• Arduino

• Breadboard

• Jumper wires

• 2 Tower Pro SG90 9g servomotors

• Analog five-pin, two-axis joystick module

• Pan-and-tilt housing module

**LIBRARIES REQUIRED**

• Servo

### **HOW IT WORKS**

Servos are small motors that can precisely angle their arms to positions between 0 and 180 degrees. In this project we’ll place the servos into a tilt-and-pan mount. The tilt-and-pan mount is a worthy investment, as it makes it much easier to attach the laser to the servo. Here we’re controlling a laser, but you could easily replace the laser with a webcam or another small device. We use two servos: one for left and right movement, and the other for up and down movement. As you might remember, servomotors have three wires, shown in [Figure 10-1](ch10.xhtml#ch10fig1): positive power (red), negative power or ground (black or brown), and signal (typically yellow, orange, or white).

**FIGURE 10-1:**
Servos have three wires.

![image](../images/f10-01.jpg)

Before we begin building, you need to know a little about how a joystick works. The joystick shown in [Figure 10-2](ch10.xhtml#ch10fig2) is basically two potentiometers and a button that allow us to measure the movement of the stick in two dimensions.

**FIGURE 10-2:**
This joystick has two potentiometers and a button for measuring movement.

![image](../images/f10-02.jpg)

Potentiometers are variable resistors and act as sensors that provide us with a voltage that varies depending on the rotation of the device around its shaft. So as you move the joystick around its center, its resistance—and therefore its output—varies. The outputs from the potentiometers are analog, so they can have a value only between 0 and 1,023 when read by the analog pin of the Arduino. This number sends a pulse to the Arduino, which in turn tells the servos how far to move. (See [Project 2](ch02.xhtml#ch02) for more on potentiometers.)

A joystick typically has five pins: VRx (the x-axis signal), VRy (the y-axis signal), SW (a pushbutton we won’t be using in this project), and GND and +5V for power.

When the x-axis of the joystick is moved to the left or right, the corresponding servo will move in that direction; when the y-axis of the joystick is moved up or down, the other servo will move up or down.

### **THE BUILD**

1.  Connect both servos’ red wires to the + 5V rail, and their brown wires to GND on the breadboard.

2.  Connect one of the servo’s yellow signal wires directly to Arduino pin 9, and the other servo’s signal wire directly to Arduino pin 10, as shown in the circuit diagram in [Figure 10-4](ch10.xhtml#ch10fig4).

    | **SERVOS** | **ARDUINO** |
    | --- | --- |
    | Red wires | +5V |
    | Brown wires | GND |
    | Yellow wire 1 | Pin 9 |
    | Yellow wire 2 | Pin 10 |

3.  Connect the GND from the joystick module to the Arduino GND rail, and +5V to the Arduino +5V rail. Connect the VRx pin directly to Arduino A0, and the VRy pin directly to Arduino A1\. Again, the SW switch connection is not used in this project.

    | **JOYSTICK** | **ARDUINO** |
    | --- | --- |
    | +5V | +5V |
    | GND | GND |
    | VRx | A0 |
    | VRy | A1 |
    | SW | Not used |

4.  Connect the breadboard rails to Arduino GND and +5V, and then check that your setup matches that of [Figure 10-3](ch10.xhtml#ch10fig3).

    **FIGURE 10-3:**
    The circuit diagram for the joystick-controlled laser. Note that the joystick in this diagram is a different brand than the one used in the project, but the connections are the same, so the instructions in the project will work fine.

    ![image](../images/f10-03.jpg)

### **MOUNTING THE LASER**

For this project, I’ve attached the servos to a pan-and-tilt housing module; you should be able to find this housing or a similar one for a relatively reasonable price on eBay by searching for “Arduino pan-and-tilt servo kit.” You may have to assemble it yourself, but this is simple to do with the included instructions.

Attach a laser diode to the top of the module; I recommend using a glue gun for a permanent fixture, but you can use tape if you want something more temporary. Now you can control the laser using the joystick. The servos will clip into the tilt-and-pan module as shown in [Figure 10-5](ch10.xhtml#ch10fig5).

**FIGURE 10-4:**
Clipping the servos into the pan-and-tilt module

![image](../images/f10-04.jpg)

Moving the joystick left and right will move the x-axis servo, and moving the joystick up and down will move the y-axis servo. The complete assembly is shown in Figure 10-6.

**FIGURE 10-5:**
The complete assembly

![image](../images/f10-05.jpg)

### **THE SKETCH**

The sketch first calls on the Servo library and then defines the two servos as `tilt` and `pan`. The joystick x-axis is attached to Arduino pin A0 and the y-axis to Arduino A1, and these are our `INPUT`. The x- and y-axes are then set as variables for movement. The `tilt` servo is attached to Arduino pin 9 and `pan` is attached to Arduino pin 10, and these are our `OUTPUT`. The Arduino then reads the `INPUT` from the joystick and changes this voltage to `OUTPUT`, moving the servos according to which direction is chosen.

```
// Used with kind permission from http://learn.explorelabs.com/
// Creative Commons 4.0 Share Alike (CC by SA 4.0) license

#include <Servo.h>
Servo tilt, pan;  // Create servo object
int joyX = A0;    // Analog pin connected to x-axis servo
int joyY = A1;    // Analog pin connected to y-axis servo
int x, y;         // Variables to read values

void setup() {
  tilt.attach(9); // Attach tilt servo on pin 9 to the servo object
  pan.attach(10); // Attach pan servo on pin 10 to the servo object
}

void loop() {
  x = joyX; // Read value of x-axis (between 0 and 1023)
  y = joyY; // Read value of y-axis (between 0 and 1023)
  x = map(analogRead(joyX), 0, 1023, 900, 2100); // Scale it to use
                                                 // with servo between
                                                 // 900 to 2100
                                                 // microseconds
  y = map(analogRead(joyY), 0, 1023, 900, 2100);
  tilt.write(x); // Set servo position according to scaled value
  pan.write(y);
  delay(15);     // Wait for servos to get to new position
}
```

## PROJECT 11: REMOTE CONTROL SERVO

**IN THIS PROJECT, WE’LL USE THE ARDUINO TO EXAMINE AND DECODE SIGNALS FROM A REMOTE CONTROL, AND THEN USE THESE CODES TO CONTROL A SERVO.**

![image](../images/f0093-01.jpg)![image](../images/f0094-01.jpg)

**PARTS REQUIRED**

• Arduino board

• Breadboard

• Jumper wires

• 38 kHz IR receiver

• Remote control

• 2 Tower Pro SG90 9g servomotors

• Pan-and-tilt housing module

**LIBRARIES REQUIRED**

• Servo

• IRremote

### **HOW IT WORKS**

First we’ll decode the remote control using an IR receiver. An IR receiver has three pins: OUT, GND, and VCC (shown left to right in [Figure 11-1](ch11.xhtml#ch11fig1)). Check the data sheet for the receiver you bought to make sure it matches this pin layout. In rare cases you might find that your receiver’s pin layout differs, but you should still be able to use the pinout to wire it up.

**FIGURE 11-1:**
IR receiver—from left to right, the pins are OUT, GND, and VCC

![image](../images/f11-01.jpg)

You will also need a remote control. You can use any kind of remote, including a TV remote, but it is best to use an old one that you no longer need. When you press a button on the remote, it sends out a digital value that is picked up by the receiver. This value is different for each button. We’ll decode the values for each button with the Arduino and then assign them to Arduino pins in the sketch to control the output—in this case, a servo.

By personalizing the sketch with the values you decode, you can connect certain buttons to certain instructions and use your remote to control the servos. If you already built the pan-and-tilt housing model from [Project 10](ch10.xhtml#ch10), you can reuse that here. Otherwise, flip to [Project 10](ch10.xhtml#ch10) for instructions on setting it up.

We’ll assign a button to the directional movement of the servos in the tilt-and-pan housing, so in total four buttons will control all movement: left and right for the x-axis servo, and up and down for the y-axis servo. Short button presses will move the servos in small increments, and extended presses will move the servo continuously until the maximum or minimum value is reached.

### **THE SETUP**

1.  Download the IRremote library from *[http://www.nostarch.com/arduinohandbook/](http://www.nostarch.com/arduinohandbook/)* and add it to your libraries folder, as shown in “[Libraries](ch00.xhtml#ch00lev2sec07)” on [page 7](ch00.xhtml#page_7).

2.  Insert the IR receiver into a breadboard. Connect the OUT pin on the receiver to Arduino pin 11, GND to Arduino GND, and VCC to Arduino +5V. Again, with some versions of the 38 kHz receiver, the pin order may differ from what’s shown here, so check the data sheet corresponding to your component.

    | **IR RECEIVER** | **ARDUINO** |
    | --- | --- |
    | OUT | Pin 11 |
    | GND | GND |
    | VCC | +5V |

3.  Now upload and run the following code.

    ```
    /* Copyright 2009 Ken Shirriff
       Used with kind permission
       http://arcfn.com
    */

    #include <IRremote.h> // Use library
    int receiver = 11;    // Pin connected to receiver

    IRrecv irrecv(receiver);
    decode_results results;
    void setup() {
      Serial.begin(9600);  // Show keypresses in IDE
      irrecv.enableIRIn(); // Start up receiver
    }

    void loop() {
      if (irrecv.decode(&results)) { // If there's an input, decode value
        Serial.println(results.value, HEX); // Display button value
                                            // on Serial Monitor in
                                            // hexadecimal format
        irrecv.resume(); // Receive next value
      }
    }
    ```

    The sketch first calls on the IRremote library, which reads from the IR receiver and sends the corresponding data to the Arduino. The IR receiver is assigned to pin 11 on the Arduino, and the sketch begins communicating with the Arduino IDE so that when a button is pressed the input is displayed in the Serial Monitor in real time. The sketch continues in a loop, looking for button presses, and shows the corresponding value to the IDE.

4.  Open the Serial Monitor in your IDE.

5.  Point your remote toward the receiver and try pressing different buttons. They will appear in the Serial Monitor decoded into letters and numbers in a format known as hexadecimal (HEX), as shown in [Figure 11-2](ch11.xhtml#ch11fig2). Try short, sharp presses to get the best results. If you press a button for too long, the Serial Monitor will show *F*s for as long as you hold the button.

    **FIGURE 11-2:**
    When a button on the remote is pressed, the HEX code for that button is displayed in the Arduino IDE Serial Monitor.

    ![image](../images/f11-02.jpg)

    Write down the numbers that appear and the buttons they correspond to. You will need these numbers later.

Now that we’ve decoded the button signals from the remote control, we can use them to control two servos.

### **THE BUILD**

1.  Using your breadboard setup from step 2 on [page 96](ch11.xhtml#page_96), with the receiver already connected, attach your servos to the Arduino by connecting the brown wire on each to GND, and the red wire to +5V. Then, connect the yellow control wire for the first servo to Arduino pin 10, and the yellow control wire for the second servo to Arduino pin 9.

    | **SERVOS** | **ARDUINO** |
    | --- | --- |
    | Red wires | +5V |
    | Brown wires | GND |
    | Yellow wire (servo 1) | Pin 10 |
    | Yellow wire (servo 2) | Pin 9 |

2.  Remember to attach power to your breadboard.

3.  Check that your setup matches the circuit diagram in [Figure 11-3](ch11.xhtml#ch11fig3), and then upload the code in “[The Sketch](ch11.xhtml#ch11lev1sec04)” on [page 99](ch11.xhtml#page_99).

    **FIGURE 11-3:**
    The circuit diagram for the remote control servo

    ![image](../images/f11-03.jpg)

### **THE SKETCH**

Make sure you use the values that you decoded in step 3 of “[The Setup](ch11.xhtml#ch11lev1sec02)” on [page 96](ch11.xhtml#page_96) in place of the values included here when completing the sketch. When you’re changing the value in the sketch to match your own codes, keep the 0x and add your HEX code after it. For example, for the first button I decoded, the HEX code is FFA05F, which looks like this in the sketch:

```
unsigned long Value1 = 0xFFA05F;
```

In this project we’re controlling servos, but you could adapt the code slightly to remotely control anything that needs to be set to `HIGH`, such as an LED or piezo buzzer.

The sketch calls on the IRremote library to read from the receiver and the Servo library to move the motors. The first two buttons are assigned to the x-axis servo to move the angle to a maximum of 70 degrees for left pan or 160 degrees for right. The third and fourth buttons are assigned to the y-axis servo to control the up and down tilt movement.

If you want to adapt this to other output, change the code:

```
servo.write
```

to:

```
digitalWrite(pin, HIGH)
```

Enter the sketch as follows:

```
/* IR Library Copyright Ken Shirriff
   Used with kind permission
   http://arcfn.com
 */

#include <Servo.h>    // Include the Servo library
#include <IRremote.h> // Include the IRremote library

unsigned long Value1 = 0xFFA05F; // Change this to your value
unsigned long Value2 = 0xFF50AF; // Change this to your value
unsigned long Value3 = 0xFF807F; // Change this to your value
unsigned long Value4 = 0xFF609F; // Change this to your value

int RECV_PIN = 11;
IRrecv irrecv(RECV_PIN);
decode_results results;
Servo servo1;
Servo servo2;

void setup() {         // Set up routine
  Serial.begin(9600);
  irrecv.enableIRIn(); // Start the IR receiver
  servo1.attach(10);   // Pin connected to servo 1
  servo2.attach(9);    // Pin connected to servo 2
}

void loop() { // Loop routine runs forever
  if (irrecv.decode(&results)) {
    Serial.println(results.value, HEX);
    irrecv.resume(); // Receive the next value
  }
  if (results.value == Value1) { // If remote code matches value 1,
                                 // then move the servo
    servo1.write(160);
  }
  else if (results.value == Value2) { // If remote code matches
                                      // value 2, then move the
                                      // servo, and so on
    servo1.write(70);
  }
  else if (results.value == Value3) {
    servo2.write(70);
  }
  else if (results.value == Value4) {
    servo2.write(160);
  }
}
```
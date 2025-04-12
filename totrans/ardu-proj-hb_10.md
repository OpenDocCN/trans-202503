## APPENDIX B: ARDUINO PIN REFERENCE

**WITHOUT GOING INTO TOO MUCH DETAIL, THIS APPENDIX GIVES YOU A REFERENCE TO THE PINS ON THE ARDUINO UNO, THEIR TECHNICAL NAMES, AND THEIR FUNCTIONS. THE PINS ARE EXPLAINED IN MORE DETAIL IN THE PROJECTS IN WHICH THEY’RE USED, SO THE INFORMATION HERE WILL PROBABLY MAKE MORE SENSE ONCE YOU’VE BUILT A FEW PROJECTS.**

| **ARDUINO PIN** | **FUNCTION AND LABEL** | **ADDITIONAL FUNCTION** |
| --- | --- | --- |
| 0 | RX—Used to receive TTL serial data |  |
| 1 | TX—Used to transmit TTL serial data |  |
| 2 | External interrupt |  |
| 3 | External interrupt | Pulse width modulation |
| 4 | XCK/TO—External Clock Input/Output (Timer/Counter 0) |  |
| 5 | T1 (Timer/Counter 1) | Pulse width modulation |
| 6 | AIN0—Analog comparator positive input | Pulse width modulation |
| 7 | AIN1—Analog comparator negative input |  |
| 8 | ICP1—Input capture |  |
| 9 | OC1A—Timer register | Pulse width modulation |
| 10 | SS—Slave Select (serial data) used in SPI communication | Pulse width modulation |
| 11 | MOSI—Master Out Slave In (data in) used in SPI communication | Pulse width modulation |
| 12 | MISO—Master In Slave Out (data out) used in SPI communication |  |
| 13 | SCK—Serial Clock (output from master) used in SPI communication |  |
| AREF | Reference voltage for analog inputs |  |
| A0 | Analog input can give 1,024 different values. |  |
| A1 | Analog input can give 1,024 different values. |  |
| A2 | Analog input can give 1,024 different values. |  |
| A3 | Analog input can give 1,024 different values. |  |
| A4 | Analog input can give 1,024 different values. | SDA (serial data line) pin supports TWI (two-wire interface) using the Wire library for I2C components. |
| A5 | Analog input can give 1,024 different values. | SCL (serial clock line) pin supports TWI using the Wire library for I2C components. |
| RESET | Can be used to reset the microcontroller |  |
| 3.3V | 3.3 volt output used for low voltage components. This is the only 3.3V source. The digital and analog pins operate at 5V. |  |
| 5V | Standard +5V output |  |
| GND | Ground/negative power |  |
| Vin | 9V power can be input here or accessed if using power jack. |  |

**Serial: 0 (RX) and 1 (TX)** These pins are used to receive (RX) and transmit (TX) transistor-transistor logic (TTL) serial data. We use the TX pin in the rocket launcher in [Project 17](ch17.xhtml#ch17).

**External interrupts: 2 and 3** These pins can be configured to trigger an interrupt on a low value, a *rising* or *falling edge* (a signal going from low to high or high to low, respectively), or a change in value. An *interrupt* is a signal that tells the Arduino to stop and carry out another function when the pins have detected an external event, such a pushbutton being pressed.

**PWM: 3, 5, 6, 9, 10, and 11** These pins can be used with pulse width modulation through the `analogWrite()` function. There’s more information on this in [Project 2](ch02.xhtml#ch02).

**SPI: 10 (SS), 11 (MOSI), 12 (MISO), 13 (SCK)** These pins support SPI communication using the SPI library and are used a number of times in this book. We use SPI communication for the electronic die in [Project 16](ch16.xhtml#ch16) so that the Arduino can send and receive data from the shift register used to control the seven-segment LED.

**LED: 13** There is a built-in LED connected to digital pin 13\. When the pin is `HIGH`, the LED is on; when the pin is `LOW`, it’s off. The built-in LED on pin 13 is used to show when the onboard ATmega328p bootloader is running, usually when the Arduino is starting up.

**AREF** This is the reference voltage for the analog inputs; it’s used with `analogReference()`. We can input from 0 to 5V, so if your sensor requires a lower voltage than 5V, you can use this pin to increase the resolution for a more accurate reading.

**Analog inputs: A0–A5** The Uno has six analog inputs, each of which provides 1,024 different values.

**TWI: A4 and A5** These pins support *TWI (two-wire interface)* communication using the Wire library. This is used to control and communicate with an I2C device, such as a serial LCD screen, using only two wires.

**RESET** Set this to `LOW` to reset the microcontroller. This is typically used to add a reset button.

Don’t worry if this information doesn’t mean much to you right now. You might find it useful in your future Arduino endeavors, and you can reference it as you progress through the projects in the book.

*Arduino Project Handbook* is set in Helvetica Neue, Montserrat, True North, and TheSansMono Condensed. The book was printed and bound by Versa Printing in East Peoria, Illinois. The paper is 60# Evergreen Skyland.

The book uses a layflat binding, in which the pages are bound together with a cold-set, flexible glue and the first and last pages of the resulting book block are attached to the cover. The cover is not actually glued to the book’s spine, and when open, the book lies flat and the spine doesn’t crack.

![image](../images/f0249-01.jpg)
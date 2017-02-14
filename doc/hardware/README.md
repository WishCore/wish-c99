The MISTESP 2015 board
----

This file describes the evaluation and test board named MISTESP 2015.

The board was initially named ESP8266-CT-EVB, hence the name. The board
is designed using Eagle. The design rule checks have been slightly
modified so that they match those requreid by Prinel.

The Gerber files which were sent to Prinel for menufacturing are in the file mist-esp-manufacture-20151218.zip. Please see the file README.txt for information about the CAM job names used to create the Gerber files.

Possible hardware configurations
----

See the circuit diagram ESP8266-CT-EVB.pdf.

Powering options

* +12VDC, which is stepped down to ca. 3.2 V with LM317 regulator
* For battery powered applications, the board can be  alternatively powered with, 3.6V Lithium AA sized (non-rechargable) battery, such as the EVE ER14505


Serial communications options

* RS485 transciever, with its associated +5V supply from 7805 regulator. Note that the UART pins must be jumped together with the lines to/from the RS485 transciever.
* RS485 termination can be controlled
* The UART pins of ESP82 are directly accessible

The following configurations are mutually excelusive:

* I2C bus master, or
* One-wire bus master, which doubles as
* DHT-11 RH/temperature sensor interface, as the hardware is actually the same as for one-wire.

Other features

* LED indicator
* Three push buttons: Reset, Flashing mode enable 
* Two S0 pulse inputs
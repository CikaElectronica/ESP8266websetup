# ESP8266WebSetup
Well... that...

###Quick start:
Spanish speakers: see CAN-104 at Cika website 
English speakers: well, learn spanish... or just flash and try the following example:
####E.g.:
```
AT+CWMODE_CUR=2
AT+WEBDEV=”My Shop”,”My product”
AT+WEBVER=”1.0”,”0.5”
AT+WEBSTART
```
Connect to the soft-AP
Point your browser to 192.168.4.1
```
AT+WEBSTS=somenumber
```
Choose your AP and connect, wait for some activity on the AT port 
and an IP to show on web browser screen
```
AT+WEBSTOP
AT+CWMODE_DEF=1
```
Now your module will always connect to that AP on startup.

##Disclaimer:
####English
This is mostly manufacturer code, his license prevails.
There is provision for upgrades, OTA upgrades, and SSL. We have NOT tested that and
WILL NOT test that. You are on your own, see the manufacturer's examples in the SDK
if this code does not do that.
####Español
Esto es mayormente código del fabricante. Su licencia es la que vale.
Si bien hay provisiones para hacer upgrades del firmware y conexión SSL, NO lo hemos
probado y NO vamos  a hacerlo. Estás por las tuyas, puedes revisar los ejemplos del
fabricante en su SDK si esa parte de este código no funciona.

##Contributing:
You are welcome to properly contribute proper code for bug fixes. That can be
in the form of attached patches or pull requests. PLEASE USE ENGLISH, so everyone
can read about.
You are welcome to contribute enhancements, however, we reserve the right to discuss
them. You are free to fork the repository and have your own.


This project specifically looks at botnets: how they work, why they're valuable 
and why it's so difficult to defeat them.

Welcome to SkyNet
=================
Almost every device with a CPU in it has been connected to the internet. Whilst 
this is a stunning advance for hummanity, the security for these devices has come 
as an atferthought or not at all. Millions of computers and devices, all with 
valuable information and processing power are left vunerable to attack.

It is important to note that his project is intented for learning purposes only, 
it is not an operational botnet nor do we intend to create one. It has been 
created to help gain an understanding in how practical a massive cyber attack is 
and how complex it can be to defend against it.

Please note, that the premise of this project has been taken from the UTS subject 
'Fundamentals of Security'.

Project Part 1: Security Essentials
===================================
Part one of the project aims to secure the channel through which the bots (of the
botnet) communicate. Using the exchange of a shared secret through Diffie-Hellman,
messages sent between the bots are encrypted using a symmetric AES cipher. Further,
methods to prevent replay attacks and ensure message integrity have been implemented
within the code. The files implementing the aforementioned methods include; lib/comms.py,
and dh/_init_.py. Some use cases of the code can be found below.

Solo Bot Operation: Mining, Harvesting and Downloading files
-----------------------------------------------------------
```
bot1@botnet[code]$ python3.2 bot.py
Listening on port 1337
Waiting for connection...
Enter command: mine
Mined and found Bitcoin address: 3pWw3v08MJO7lDyzXXQ68e0i5enL
Enter command: harvest
Found user pass: ('Bob', 'pmiMFK')
Enter command: download hello.signed
Stored the received file as hello.signed
Enter command: list 
Files stored by this bot: hello.signed 
Valuables stored by this bot: ['Bitcoin: 3pWw3v08MJO7lDyzXXQ68e0i5enL', 'Username/Password: Bob pmiMFK'] 
Enter command: upload secrets 
Saved valuables to pastebot.net/secrets for the botnet master 
Enter command: exit 
```

P2P Bot Communication: Exchanging Files
---------------------------------------
#### Bot 1
```
bot1@botnet[code]$ python3.2 bot.py 
Listening on port 1337 
Waiting for connection... 
Enter command: download hello.signed 
Stored the received file as hello.signed 
Enter command: list 
Files stored by this bot: hello.signed 
Valuables stored by this bot: [] 
Enter command: p2p upload hello.signed 
Finding another bot... 
Found bot on port 1337 
Sending hello.signed via P2P 
```
#### Bot 2
```
bot2@botnet[code]$ python3.2 bot.py 
Port 1338 not available 
Listening on port 1337 
Waiting for connection... 
Enter command: list 
Files stored by this bot: 
Valuables stored by this bot: [] 
Accepted a connection from ('127.0.0.1', 36381)... 
Waiting for connection... 
Receiving hello.signed via P2P 
Stored the received file as hello.signed 
Enter command: list 
Files stored by this bot: hello.signed 
Valuables stored by this bot: [] 
```

P2P Bot Communication: Echo
--------------------------------------------
(Note: Requires two bots running at the same time)

```
bot1@botnet[code]$ python3.2 bot.py 
Port 1337 not available
Listening on port 1338
Waiting for connection...
Enter command: p2p echo
Original data: b'ECHO'
Encrypted Data: b'\x00\xfe\xdd^\xb8\x98 ...'
Sending packet of length 96
Echo> Hi there!
Original data: b'Hi there!'
Encrypted Data: b'Q\x18\xf1\xb8|\x86\x ...'
Sending packet of length 112
Receiving packet of length 112
Encrypted Data: b'\x9bi\xbcw#o ...
Original data: b'Hi there!'
Echo> exit
Original data: b'exit'
Encrypted Data: b'_\xa5P\xcc\xf3\xdc ...'
Sending packet of length 96
Receiving packet of length 96
Encrypted Data: b'\xd4\x1f.:\xcd\xea ...'
Original data: b'exit'
Enter command: exit
```

Project Part 2: Protecting the castle
=====================================
Part two of the project implements authentication procedures (signing) for 
verifying updates from the master and ensuring that valuable secrets stored on 
‘pastebot.net’ are only accessible by the botnet master. The files enforcing these
security aspects include; lib/files.py, master_view.py and master_sign.py. 
Some use cases of the code can be found below.

Master Viewing Secrets
----------------------
#### Bot
```
bot1@botnet[code]$ python3.2 bot.py 
Listening on port 1337 
Waiting for connection... 
Enter command: mine 
Mining for Bitcoins... 
Mined and found Bitcoin address: 1kfRSGOKX8t2jPviL1DwQEu3Kd17l 
Enter command: mine 
Mining for Bitcoins... 
Mined and found Bitcoin address: 34PvZLVfodFkw0ipkCcbAl95HPcz40BKdD2 
Enter command: upload secrets 
Saved valuables to pastebot.net/secrets for the botnet master 
Enter command: exit 
```
#### Master
```
master@botnet[code]$ python3.2 master_view.py 
Which file in pastebot.net does the botnet master want to view? secrets 
Bitcoin: 1kfRSGOKX8t2jPviL1DwQEu3Kd17l 
Bitcoin: 34PvZLVfodFkw0ipkCcbAl95HPcz40BKdD2 
```

Master Signing Updates
----------------------
#### Master
```
master@botnet[code]$ python3.2 master_sign.py 
Which file in pastebot.net should be signed? hello.fbi 
Signed file written to pastebot.net/hello.fbi.signed 
```
#### Bot
```
bot1@botnet[code]$ python3.2 bot.py 
Listening on port 1337 
Waiting for connection... 
Enter command: download hello.fbi 
The file has not been signed by the botnet master 
Enter command: download hello.fbi.signed 
Stored the received file as hello.fbi.signed 
Enter command: list 
Files stored by this bot: hello.fbi.signed 
Valuables stored by this bot: [] 
Enter command: exit 
```

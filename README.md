Welcome to SkyNet
=================
Almost every device with a CPU in it has been connected to the internet. Whilst this is a 
stunning advance for hummanity, the security for these devices has come as an atferthought or not 
at all. Millions of computers and devices, all with valuable information and processing power 
are left vunerable to attack.

This project specifically looks at botnets: how they work, why they're valuable and why it's so 
difficult to defeat them.
Please note this project is intented for learning purposes only, it is not an operational botnet nor do 
we intend to create one. It has been created to help gain an understanding in how practical a massive cyber 
attack is and how complex it can be to defend against it.

Please note, that the premise of this project has been taken from the UTS subject 'Fundamentals of Security'.

Project Part 1: Security Essentials
==================================
Usage: Solo Bot Operation (Mining and Downloading files)
-------------------------------------------------------
```
**bot1@botnet[code]$** python3.2 bot.py
Listening on port 1337
Waiting for connection...
Enter command: mine
Mined and found Bitcoin address: 3pWw3v08MJO7lDyzXXQ68e0i5enL
Enter command: harvest
Found user pass: ('Bob', 'pmiMFK')
Enter command: download hello.signed
The given file doesn't exist on pastebot.net
Enter command: download hello.signed 
Stored the received file as hello.signed 
Enter command: download hello.fbi 
The file has not been signed by the botnet master 
Enter command: list 
Files stored by this bot: hello.signed 
Valuables stored by this bot: ['Bitcoin: 3pWw3v08MJO7lDyzXXQ68e0i5enL', 'Username/Password: Bob pmiMFK'] 
Enter command: upload valuables.txt 
Saved valuables to pastebot.net/valuables.txt for the botnet master 
Enter command: exit 
```
Usage: Peer to Peer Bot Communication (Upload)
----------------------------------------------
(Note: Requires two bots at the same time) 
#### Bot 1
```
**bot1@botnet[code]$** python3.2 bot.py 
Port 1337 not available 
Listening on port 1338 
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
**bot2@botnet[code]$** python3.2 bot.py 
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

Usage: Peer to Peer Bot Communication (Echo)
--------------------------------------------
(Note: Requires two bots at the same time) 
```
**bot1@botnet[code]$** python3.2 bot.py 
Listening on port 1337 
Waiting for connection... 
Enter command: p2p echo 
Finding another bot... 
Found bot on port 1338 
Shared hash: c2bd47c3ac55f104c052dca02eaa6c9de22e7637370584e5d2ba3c9c81bf2ab8 
Original data: b'ECHO' 
Encrypted data: b'!qpz' 
Sending packet of length 4 
Echo> Test 
Original data: b'Test' 
Encrypted data: b'0WKA' 
Sending packet of length 4 
Receiving packet of length 4 
Encrypted data: b'0WKA' 
Original data: b'Test' 
Echo> exit 
Original data: b'exit' 
Encrypted data: b'\x01JQA' 
Sending packet of length 4 
Receiving packet of length 4 
Encrypted data: b'\x01JQA' 
Original data: b'exit' 
Enter command: exit 
```

Project Part 2: Protecting the castle
=====================================
Usage: Bot upload and Master viewing secrets
--------------------------------------------
```
**bot1@botnet[code]$** python3.2 bot.py 
Listening on port 1337 
Waiting for connection... 
Enter command: mine 
Mining for Bitcoins... 
... 
Mined and found Bitcoin address: 1kfRSGOKX8t2jPviL1DwQEu3Kd17l 
Enter command: mine 
Mining for Bitcoins... 
... 
Mined and found Bitcoin address: 34PvZLVfodFkw0ipkCcbAl95HPcz40BKdD2 
Enter command: upload secrets 
Saved valuables to pastebot.net/secrets for the botnet master 
Enter command: exit 
master@botnet[code]$ python3.2 master_view.py 
Which file in pastebot.net does the botnet master want to view? secrets 
Bitcoin: 1kfRSGOKX8t2jPviL1DwQEu3Kd17l 
Bitcoin: 34PvZLVfodFkw0ipkCcbAl95HPcz40BKdD2 
```

Usage: Master signing updates and Bots downloading updates
----------------------------------------------------------
#### Master
```
**master@botnet[code]$** python3.2 master_sign.py 
Which file in pastebot.net should be signed? hello.fbi 
Signed file written to pastebot.net/hello.fbi.signed 
```
#### Bot
```
**bot1@botnet[code]$** python3.2 bot.py 
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

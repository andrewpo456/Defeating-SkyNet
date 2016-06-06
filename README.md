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
=================
Usage: Solo Bot Operation
bot1@botnet$ python3.2 bot.py <br />
Listening on port 1337 <br />
Waiting for connection... <br />
Enter command: mine <br />
Mined and found Bitcoin address: 3pWw3v08MJO7lDyzXXQ68e0i5enL <br />
Enter command: harvest <br />
Found user pass: ('Bob', 'pmiMFK') <br />
Enter command: download hello.signed <br />
The given file doesn't exist on pastebot.net <br />
Enter command: download hello.signed <br />
Stored the received file as hello.signed <br />
Enter command: download hello.fbi <br />
The file has not been signed by the botnet master <br />
Enter command: list <br />
Files stored by this bot: hello.signed <br />
Valuables stored by this bot: ['Bitcoin: 3pWw3v08MJO7lDyzXXQ68e0i5enL', 'Username/Password: Bob pmiMFK'] <br />
Enter command: upload valuables.txt <br />
Saved valuables to pastebot.net/valuables.txt for the botnet master <br />
Enter command: exit <br />

Usage: Peer to Peer Bot Communication (Upload) <br />
(Note: Requires two bots at the same time) <br />
============================
BOT #1 <br />
------
bot1@botnet$ python3.2 bot.py <br />
Port 1337 not available <br />
Listening on port 1338 <br />
Waiting for connection... <br />
Enter command: download hello.signed <br />
Stored the received file as hello.signed <br />
Enter command: list <br />
Files stored by this bot: hello.signed <br />
Valuables stored by this bot: [] <br />
Enter command: p2p upload hello.signed <br />
Finding another bot... <br />
Found bot on port 1337 <br />
Sending hello.signed via P2P <br />
------
BOT #2
------
bot2@botnet$ python3.2 bot.py <br />
Listening on port 1337 <br />
Waiting for connection... <br />
Enter command: list <br />
Files stored by this bot: <br />
Valuables stored by this bot: [] <br />
Accepted a connection from ('127.0.0.1', 36381)... <br />
Waiting for connection... <br />
Receiving hello.signed via P2P <br />
Stored the received file as hello.signed <br />
Enter command: list <br />
Files stored by this bot: hello.signed <br />
Valuables stored by this bot: [] <br />

Usage: Peer to Peer Bot Communication (Echo) <br />
(Note: Requires two bots at the same time) <br />
==========================
bot1@botnet$ python3.2 bot.py <br />
Listening on port 1337 <br />
Waiting for connection... <br />
Enter command: p2p echo <br />
Finding another bot... <br />
Found bot on port 1338 <br />
Shared hash: c2bd47c3ac55f104c052dca02eaa6c9de22e7637370584e5d2ba3c9c81bf2ab8 <br />
Original data: b'ECHO' <br />
Encrypted data: b'!qpz' <br />
Sending packet of length 4 <br />
Echo> Test <br />
Original data: b'Test' <br />
Encrypted data: b'0WKA' <br />
Sending packet of length 4 <br />
Receiving packet of length 4 <br />
Encrypted data: b'0WKA' <br />
Original data: b'Test' <br />
Echo> exit <br />
Original data: b'exit' <br />
Encrypted data: b'\x01JQA' <br />
Sending packet of length 4 <br />
Receiving packet of length 4 <br />
Encrypted data: b'\x01JQA' <br />
Original data: b'exit' <br />
Enter command: exit <br />

Project Part 2: Protecting the castle
=================
Usage: Bot upload and Master viewing secrets
======================================
bot1@botnet$ python3.2 bot.py <br />
Listening on port 1337 <br />
Waiting for connection... <br />
Enter command: mine <br />
Mining for Bitcoins... <br />
-
Mined and found Bitcoin address: 1kfRSGOKX8t2jPviL1DwQEu3Kd17l <br />
Enter command: mine <br />
Mining for Bitcoins... <br />
-
Mined and found Bitcoin address: 34PvZLVfodFkw0ipkCcbAl95HPcz40BKdD2 <br />
Enter command: upload secrets <br />
Saved valuables to pastebot.net/secrets for the botnet master <br />
Enter command: exit <br />
master@botnet$ python3.2 master_view.py <br />
Which file in pastebot.net does the botnet master want to view? secrets <br />
Bitcoin: 1kfRSGOKX8t2jPviL1DwQEu3Kd17l <br />
Bitcoin: 34PvZLVfodFkw0ipkCcbAl95HPcz40BKdD2 <br />

Usage: Master signing updates and Bots downloading updates
================================================
master@botnet$ python3.2 master_sign.py <br />
Which file in pastebot.net should be signed? hello.fbi <br />
Signed file written to pastebot.net/hello.fbi.signed <br />
bot1@botnet$ python3.2 bot.py <br />
Listening on port 1337 <br />
Waiting for connection... <br />
Enter command: download hello.fbi <br />
The file has not been signed by the botnet master <br />
Enter command: download hello.fbi.signed <br />
Stored the received file as hello.fbi.signed <br />
Enter command: list <br />
Files stored by this bot: hello.fbi.signed <br />
Valuables stored by this bot: [] <br />
Enter command: exit <br />

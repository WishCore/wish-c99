Notes regarding ANSI-C implementation of Wish
=============================================

Wish TCP transport description, protocol version 1
--------------------------------------------------

The handshake phase
^^^^^^^^^^^^^^^^^^^

The preamble
""""""""""""

When a Wish node wishes to open a connection to an other Wish node (the peer), it opens a plain TCP connection to the peer node (as a "client"). When the connection is accepted by the peer node, the client will send the characters "W." followed by the source and destination wuids. For example:
	
	W.bd6092dc5db3712234004a36535f08e45c29595d86084dedad3eecac536e97f9b5ed686846e858528fa25cb35cbfd48ce88a54cf8cfc75230f8c04e5d4430223

where the source identity would be

	b5ed686846e858528fa25cb35cbfd48ce88a54cf8cfc75230f8c04e5d4430223

and destination identity would be

	bd6092dc5db3712234004a36535f08e45c29595d86084dedad3eecac536e97f9

Note that implementations may ignore you if you specify invalid wuids.


Session key exchange
""""""""""""""""""""

The key exchange is performed using the Diffie-Hellman-Merkle key exchange. 

- Recovering the key and IV parts from session keys
- Two IVs, for both incoming and outgoing. The nonce part.

Opening WIsh connection
"""""""""""""""""""""""

- AES GCM decryption. Auth tag.
- Saving the remote host's hostid from BSON
- Incrementing the "in" nonce
- Create BSON with your own hostid.
- Encrypt, send ciphertext and auth tag
- Incrementing the "out" nonce

After these steps, the Wish connection is now open.

Handshake protocol improvements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Suggestions for future protocol levels are maintained in the "Wish" Hailer.

Wish connection open -phase
^^^^^^^^^^^^^^^^^^^^^^^^^^^

- decrypt & encrypt just like in the previous phase, and increment the respective nonces.

- BSON documents, which are encoded like this:

- The types of packets wish-core will send at first

ANSI-C implementation notes
---------------------------

RAM requirements
^^^^^^^^^^^^^^^^

-"static" RAM requirement per connection

-"dynamic" RAM rquirements when opening connection and handling messages



ESP8266 implementation notes
----------------------------

Security/correctness related
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Random numbers, the platform API os_random() is used. Provide other function? Check seeding

- Implement ED25519 signatures

- Currently there is a risk of deadlocking the TCP stack, if you send data with espconn_send two times without paying attention if the previous send was completed or not (manifested by the activation of send CB). This limitation should be accounted for in Wish stack design, other TCP implementations might have same characteristics. 
- On the ESP8266 port, the deadlocking should not be possible, as messages will not be processed if a previous send is still pending.

SDK related and other platform specifics
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- LD linker script was altered so that all functions are put to flash. Note that ISRs cannot be in flash, but on the other hand they will not be placed there either by this LD file (Why?)
- the ESP8266 "port" only has one connection.
- The ESP8266 uses the simple os task system provided by the "ETS" runtime. The data is fed into wishcore by the TCP receive callback, and the OS is notified so that is will invoke the message processor task. The message processor task will also be invoked by the send complete callback.

profiling
^^^^^^^^^

- Free heap at start: XXX bytes
- free heap, when System uptime 436 minutes: Free heap size 36592
- System uptime 484 minutes Free heap size 36592

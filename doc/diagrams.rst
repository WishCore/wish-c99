
Diagrams
========

Sequence diagrams can be rendered at https://www.websequencediagrams.com/

Remote friend request with verification
---------------------------------------

.. code-block:: text

    title Remote friend request with verification

    note over Alice: 
    Alice wants to befriend Bob, and has found a link on Bob's web page
    end note

    note over Bob:
    Bob knows Alice in person, and knows David's Wish identity
    end note

    Alice->Bob: Friend request

    Bob->David: Ask David if he knows Alice

    David->Bob: Yes, that is Alice form soccer practice (level of trust: verified key personally).

    Bob->Alice: Accepted your friend request


Remote friend request with verification
---------------------------------------


.. code-block:: text

    title Remote friend request with verification

    note over Alice: 
    Alice wants to befriend Bob, and has found a link on Bob's web page
    end note

    note over Bob:
    Bob knows Alice in person, and knows David's Wish identity
    end note

    Alice->Bob: Friend request (Certificate signed by David)

    Bob->Bob: Friend request from Alice signed by David, would you like to accept?

    Bob->Alice: Accepted your friend request






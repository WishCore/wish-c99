
WishApp API
===========

Creating a signature
--------------------

.. literalinclude:: example.js
   :language: javascript



.. code-block:: javascript

   var document: { 
       data: Buffer,
       meta?: Buffer,
       signatures?: { uid: Buffer, algo: string, signature: Buffer, claim?: Buffer }[] ] }

   identity.sign(uid, document)



Verifying signatures
--------------------

.. code-block:: javascript

   return: { 
      data: Buffer,
      meta?: Buffer,
      signatures: [{ 
        uid: Buffer,
        sign: bool | null, // bool: verification result, null: unable to verify signature
        claim?: Buffer }] }



# Wish Core

## Installing

## Running

## Releasing

## Application API

### Wish Cli

### Commands

#### Signatures

Creating a signature:

```javascript
var document: { 
    data: Buffer,
    meta?: Buffer,
    signatures?: { uid: Buffer, algo: string, signature: Buffer, claim?: Buffer }[] ] }

identity.sign(uid, document)
```



Verifying signatures:

```javascript
 return: { 
    data: Buffer,
    meta?: Buffer,
    signatures: [{ 
      uid: Buffer,
      sign: bool | null, // bool: verification result, null: unable to verify signature
      claim?: Buffer }] }
```


## Core Api


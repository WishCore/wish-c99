# Wish

Wish – A peer-to-peer identity based application development stack. Built to enable applications to communicate securely without unncessary third-parties.

While Wish is inspired by social networking it is also applicable in areas not commonly associated with social media, such as providing an identity layer for physical devices, providing trust management tools for companies, or publishing scientific research. Wish provides a generic social network stack for building any application utilizing these features.

Wish key features and APIs (not necessarily implemented)

* Create/manage identities
* Manage trust-relationships between identities
* Sign/verify signatures by identities
* Create peers (register protocol handler)
* Discover avaliable peers
* Send and receive data to/from other peers
* Manage and provide access control
* Manage connectivity

This is a C-language implementation based on the Wish (wish-core) reference implementation by André Kaustell.

## Applications

`wish-cli`: A node.js command line interface for accessing and managing a Wish Core. See: https://www.npmjs.com/package/@wishcore/wish-cli

`wish-core-api`: A native node.js addon to quickly build node.js applications using Wish. See https://www.npmjs.com/package/@wishcore/wish-sdk.

## Build

```sh
mkdir build
cd build 
cmake ..
make
```

## Acknowledgements

Part of this work has been carried out in the scope of the project Industrial Internet Standardized Interoperability (II-SI), co-funded by Tekes (Finnish Funding Agency for Innovation) contract number 5409/31/2014.

Part of this work has been carried out in the scope of the project Mist App/Wi-Fi, co-funded by Tekes (Finnish Funding Agency for Innovation) contract number  4524/31/2015.

Part of this work has been carried out in the scope of the project bIoTope which is co-funded by the European Commission under Horizon 2020 program, contract number H2020-ICT-2015/688203.
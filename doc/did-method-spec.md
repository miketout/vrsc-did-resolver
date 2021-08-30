# Verus (did:vrsc) DID Method Specification

## Author

- Forked from vrsc-did-resolver by Veramo core team: <https://github.com/decentralized-identity/vrsc-did-resolver>

- vrsc-did-resolver modifications by miketout (GitHub) & Verus Community Developers (https://verus.io/discord)

## Preface

The vrsc DID method specification conforms to the requirements specified in
the [DID specification](https://w3c.github.io/did-core/), currently published by the W3C Credentials Community Group. For more information about DIDs and DID method specifications, please see the [DID Primer](https://github.com/WebOfTrustInfo/rebooting-the-web-of-trust-fall2017/blob/master/topics-and-advance-readings/did-primer.md)

## Abstract

Decentralized Identifiers (DIDs, see [1]) are designed to be compatible with any distributed ledger or network. In the Verus project, VerusIDs provide decentralized, multisig, revocable, recoverable, provable identity along with self-sovereign, direct administration over cryptographic funds and identity control. In addition, Verus provides an interplanetary scale namspace, which enables self-resolving identity names that can be used on or off-chain. This resolver provides a mapping  between VerusID's native functions and data structures and W3C DID compliant methods and represenations. It also uses self-resolving DIDs to locate identity information on any blockchain or other type of system that is connected to any part of the multichain Verus network via the Verus Interchain Protocol (VIP).

The described DID method allows any VerusID to be exposed as a fully W3C compliant DID, capable of resolving to compliant DID documents, being used for Verifiable Credentials, Authentication, to sign content and make provable attestations, and to associate content references. Identities based on VerusID must be registered. While this is typically done on a blockchain that supports the VerusID protocol, it is possible to support VerusID on any centralized or decentralized system capable of managing its namespace and using a namespace that does not conflict with any originating from the Verus root namespace or any other registered root namespaces. 

VerusIDs on Verus or any other Public Blockchains as a Service blockchain maintain a core set of cryptographic control information and data references on the blockchain, as well as associations with any launched blockchain currencies or other blockchains. This information includes:

- "version" - the current VerusID protocol specific version of this VerusID. The version of IDs on mainnet as of December, 2019, is 1. The version which will be available on the network in the PBaaS release is 2. Any updates to a VerusID on the Verus network will also have the effect of upgrading its version automatically, if the older VerusID is an older version than that supported on the Verus or PBaaS network. Due to the nature of blockchain and VerusID permanence, all VerusID implementations that upgrade their version support are expected to have a well understood forward versioning transform. Additionally, if a blockchain updating its VerusID version is expected to maintain full identity interoperability with blockchains that do not update their VerusID version, it should provide for a well known downversioning transform to the version support required for its export of VerusIDs.
- "flags" - flags are both user and system controlled states, which are either set according to user actions, such as setting a time lock on the ID for funds access while continuing to enable staking/proving of funds without delegation, or when significant state changes, such as entering a revoked state, or activating either a currency or blockchain, occur relative to that identity.
- "primaryaddresses" - controlling blockchain addresses, which represent keys that define their supported algorithms based on their systemid and base58check version byte. For example, while these MUST not be identity IDs or DIDs, they may be either public key hash or compressed public key addresses at this time, each with its own address format. In the future, they may also be addresses containing keys for quantum resistant signatures, with the first expected to be Falcon512. Primaryaddresses allow any combination of valid address types to be used as one signer in a multisig identity.
If the controller(s) of a VerusID update(s) the ID to new primaryaddresses, all subsequent spends or use of funds by that identity MUST require a valid signature using the new addresses. This enables an update to the identity from ECDSA signatures to quantum resistant signatures, such as Falcon or others, protecting all funds under the identity's control by just changing the primary addresses.
- "minimumsignatures" - the minimum number of address signatures required to consider a set of cryptographic signatures enough to fully sign on behalf of this ID. At present, no distinction is made between the types of addresses in determining if there are the individual signers necessary for a valid signature.
- "name" - This is a 64 byte friendly name, which may include all valid characters, including Unicode/emoji characters, with the exception of the set of characters "\\/:*?\"<>|@". For protocols unable to handle extended characters, see "identityaddress".
- "parent" - parent is a base58check representation of an "i"-address, obtained by VDXF (Verus Data Exchange Format) specified hierarchical hashing of the namespace just above the "name". By applying the last stage of hierarchical hashing on the parent and name, the identityaddress is produced. "parent" is typically, but is not required to be, the systemid of the blockchain or system on which the ID was registered.
- "identityaddress" - this is a read only base58check value that begins with "i" and is calculated deterministically and assuming no hash collision, uniquely, from the name and the parent using the same VDXF hierarchical hashing algorithm.
- "systemid" - this is the unique i-address of the blockchain, system, or gateway on which an ID was defined.
- "contentmap" - this is a key/value mapping of 20 byte keys and 32 byte values, which are used as content references, keyed by VDXF key definitions.
- "revocationauthority" - the i-address of an ID, which holds revocation authority over this identity record. If not specified on registration, this is set to self. Once set to a value other than self, the value of this authority can only be changed by the authority itself. The revocation authority is a full fledged VerusID of its own and has the sole authority of revocation over the identity. It cannot spend, sign on behalf of, or change the state of the identity beyond modifying the value of the specified revocationauthority and actually revoking the ID. Once revoked, the revocation authority has no power over an identity record.
- "recoveryauthority" - the i-address of an ID, which holds recovery authority over this identity record. If not specified on registration, this is set to self, and if it is self, the ID SHALL NOT be revoked. Attempts to revoke the identity will be rejected by consensus. Once set to a value other than self, the value of this authority in an identity record can subsequently only be changed by the recovery authority itself. The recovery authority is a VerusID with sole authority and capability of being able to recover a revoked identity. It cannot spend, sign on behalf of, or change the state of the identity at all unless the identity is revoked. Once an identity is revoked, the recovery authority has absolute control over updating the identity to an unrevoked, new state with new information.
- "privateaddress" - this is a Sapling compatible zero knowledge address, which can be used on Verus or any PBaaS networks as a zero knowledge funds address. It can also be used as a message endpoint or in applications when a selectively private endpoint for funds, information, or permanent storage is required.
- "timelock" - this value has two possible meanings, depending on the flags value. Access to funds limitations on Verus or PBaaS blockchains are enforced by consensus rules.
  - If bit 1 (the value 2) of flags is set, then this identity is "funds locked", meaning that it cannot spend funds. It can stake funds on its network, the rewards of which may be directed to either itself, revocation, or recovery authorities, but in order to spend, the identity MUST first be unlocked, and then the number of blocks specified in "timelock" must pass.
  - If bit 1 of flags is not set, this value is the block height or time of the "systemid" system, after which the VerusID is no longer considered locked and may access its funds.

For a reference implementation of this DID method specification see [3].

### Identity Controller

By default, each identity is controlled by itself via primaryaddresses, except for the revocation and recovery authorities, which are controlled by those respective VerusID identities. In version 1 released on mainnet December 2019, the maximum number of primaryaddresses is 10. In version 2, which will be released in the PBaaS upgrade and which enables both timelock capabilities and increased multisig, the maximum number of primary addresses is 25 with a maximum number of signatures required of 13. For higher multisig applications, applications must use on-chain notarization and signature rollups.

## Target Systems

This vrsc-did-resolver supports all PBaaS mainnet and testnet chains which support the VerusID protocol.

- VRSC
- VRSCTEST
- All mainnet or testnet PBaaS chains

## THIS README IS NOT UPDATED PAST THIS POINT


## JSON-LD Context Definition

Since this DID method still supports `publicKeyHex` and `publicKeyBase64` encodings for verification methods, it
requires a valid JSON-LD context for those entries.
To enable JSON-LD processing, the `@context` used when constructing DID documents for `did:vrsc` should be:

```javascript
"@context": [
  "https://www.w3.org/ns/did/v1",
  "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld"
]
```

You will also need this `@context` if you need to use `EcdsaSecp256k1RecoveryMethod2020` in your apps.

## DID Method Name

The namestring that shall identify this DID method is: `vrsc`

A DID that uses this method MUST begin with the following prefix: `did:vrsc`. Per the DID specification, this string
MUST be in lowercase. The remainder of the DID, after the prefix, is specified below.

## Method Specific Identifier

The method specific identifier is represented as the Hex encoded secp256k1 public key (in compressed form),
or the corresponding Hex-encoded Ethereum address on the target network, prefixed with `0x`.

    vrsc-did = "did:vrsc:" vrsc-specific-identifier
    vrsc-specific-identifier = [ vrsc-network ":" ] ethereum-address / public-key-hex
    vrsc-network = "mainnet" / "ropsten" / "rinkeby" / "kovan" / network-chain-id
    network-chain-id = "0x" *HEXDIG
    ethereum-address = "0x" 40*HEXDIG
    public-key-hex = "0x" 66*HEXDIG

The `VerusID` or `public-key-hex` are case-insensitive.

Note, if no public Ethereum network was specified, it is assumed that the DID is anchored on the Ethereum mainnet by
default. This means the following DIDs will resolve to equivalent DID Documents:

    did:vrsc:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a
    did:vrsc:0x1:0xb9c5714089478a327f09197987f16f9e5d936e8a
    did:vrsc:0xb9c5714089478a327f09197987f16f9e5d936e8a

If the identifier is a `public-key-hex`:

- it MUST be represented in compressed form (see https://en.bitcoin.it/wiki/Secp256k1)
- the corresponding `blockchainAccountId` entry is also added to the default DID document, unless the `owner` has been
  changed to a different address.
- all Read, Update, and Delete operations MUST be made using the corresponding `blockchainAccountId` and MUST originate
  from the correct controller (ECR1056 `owner`) address.

## Relationship to ERC1056

The subject of a `did:vrsc` is mapped to an `identity` address in the ERC1056 contract. When dealing with public key
identifiers, the corresponding ethereum address is used.

The controller address of a `did:vrsc` is mapped to the `owner` of an `identity` in the ERC1056.
The controller address is not listed as the [DID `controller`](https://www.w3.org/TR/did-core/#did-controller) property
in the DID document. This is intentional, to simplify the verification burden required by the DID spec.
Rather, this address it is a concept specific to ERC1056 and defines the address that is allowed to perform Update and 
Delete operations on the registry on behalf of the `identity` address.
This address MUST be listed with the ID `${did}#controller` in the `verificationMethod` section and also referenced
in all other verification relationships listed in the DID document.
In addition to this, if the identifier is a public key, this public key MUST be listed with the ID `${did}#controllerKey`
in all locations where `#controller` appears.

## CRUD Operation Definitions

### Create (Register)

In order to create a `vrsc` DID, an Ethereum address, i.e., key pair, needs to be generated. At this point, no
interaction with the target Ethereum network is required. The registration is implicit as it is impossible to brute
force an Ethereum address, i.e., guessing the private key for a given public key on the Koblitz Curve
(secp256k1). The holder of the private key is the entity identified by the DID.

The minimal DID document for an Ethereum address on mainnet, e.g., `0xf3beac30c498d9e26865f34fcaa57dbb935b0d74` with no
transactions to the ERC1056 registry looks like this:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld"
  ],
  "id": "did:vrsc:0xb9c5714089478a327f09197987f16f9e5d936e8a",
  "verificationMethod": [
    {
      "id": "did:vrsc:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:vrsc:0xb9c5714089478a327f09197987f16f9e5d936e8a",
      "blockchainAccountId": "0xb9c5714089478a327f09197987f16f9e5d936e8a@eip155:1"
    }
  ],
  "authentication": ["did:vrsc:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller"],
  "assertionMethod": ["did:vrsc:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller"]
}
```

The minimal DID Document for a public key where there are no corresponding TXs to the ERC1056 registry looks like this:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld"
  ],
  "id": "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "verificationMethod": [
    {
      "id": "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798#controller",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "blockchainAccountId": "0xb9c5714089478a327f09197987f16f9e5d936e8a@eip155:1"
    },
    {
      "id": "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798#controllerKey",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "controller": "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "publicKeyHex": "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    }
  ],
  "authentication": [
    "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798#controller",
    "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798#controllerKey"
  ],
  "assertionMethod": [
    "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798#controller",
    "did:vrsc:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798#controllerKey"
  ]
}
```

### Read (Resolve)

The DID document is built by using read only functions and contract events on the ERC1056 registry.

Any value from the registry that returns an Ethereum address will be added to the `verificationMethod` array of the
DID document with type `EcdsaSecp256k1RecoveryMethod2020` and an `blockchainAccountId` attribute containing the address.

#### Controller Address

Each identity always has a controller address. By default, it is the same as the identity address, but check the read
only contract function `identityOwner(address identity)` on the deployed version of the ERC1056 contract.

The identity controller will always have a `verificationMethod` entry with the id set as the DID with the fragment
`#controller` appended.

An entry for the controller is also added to the `authentication` array of the DID document.

#### Enumerating Contract Events to build the DID Document

The ERC1056 contract publishes three types of events for each identity.

- `DIDOwnerChanged` (indicating a change of `controller`)
- `DIDDelegateChanged`
- `DIDAttributeChanged`

If a change has ever been made for an identity the block number is stored in the changed mapping.

The latest event can be efficiently looked up by checking for one of the 3 above events at that exact block.

Each ERC1056 event contains a `previousChange` value which contains the block number of the previous change (if any).

To see all changes in history for an identity use the following pseudo-code:

1. eth_call `changed(address identity)` on the ERC1056 contract to get the latest block where a change occurred.
2. If result is `null` return.
3. Filter for events for all the above types with the contracts address on the specified block.
4. If event has a previous change then go to 3

After building the history of events for an address, interpret each event to build the DID document like so: 

##### Controller changes (`DIDOwnerChanged`)

When the controller address of a `did:vrsc` is changed, a `DIDOwnerChanged` event is emitted.

```solidity
event DIDOwnerChanged(
  address indexed identity,
  address owner,
  uint previousChange
);
```

The event data MUST be used to update the `#controller` entry in the `verificationMethod` array.
When resolving DIDs with publicKey identifiers, if the controller(owner) address is different from the corresponding 
address of the publicKey, then the `#controllerKey` entry in the `verificationMethod` array MUST be omitted.  

##### Delegate Keys (`DIDDelegateChanged`)

Delegate keys are Ethereum addresses that can either be general signing keys or optionally also perform authentication.

They are also verifiable from Solidity (on-chain).

When a delegate is added or revoked, a `DIDDelegateChanged` event is published that MUST be used to update the DID
document.

```solidity
event DIDDelegateChanged(
  address indexed identity,
  bytes32 delegateType,
  address delegate,
  uint validTo,
  uint previousChange
);
```

The only 2 `delegateTypes` that are currently published in the DID document are:

- `veriKey` which adds a `EcdsaSecp256k1RecoveryMethod2020` to the `verificationMethod` section of the DID document with
  the `blockchainAccountId`(`ethereumAddress`) of the delegate.
- `sigAuth` which adds a `EcdsaSecp256k1RecoveryMethod2020` to the `verificationMethod` section of document and a
  corresponding entry to the `authentication` section.

Note, the `delegateType` is a `bytes32` type for Ethereum gas efficiency reasons and not a `string`. This restricts us
to 32 bytes, which is why we use the short-hand versions above.

Only events with a `validTo` (measured in seconds) greater or equal to the current time should be included in the DID
document. When resolving an older version (using `versionId` in the didURL query string), the `validTo` entry MUST be
compared to the timestamp of the block of `versionId` height.

Such valid delegates MUST be added to the `verificationMethod` array as `EcdsaSecp256k1RecoveryMethod2020` entries, with
`delegate` listed under `blockchainAccountId` and suffixed with `@eip155:<chainId>`

Example:
```json
{
  "id": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#delegate-1",
  "type": "EcdsaSecp256k1RecoveryMethod2020",
  "controller": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74",
  "blockchainAccountId": "0x12345678c498d9e26865f34fcaa57dbb935b0d74@eip155:1"
}
```

##### Non-Ethereum Attributes (`DIDAttributeChanged`)

Non-Ethereum keys, service endpoints etc. can be added using attributes. Attributes only exist on the blockchain as
contract events of type `DIDAttributeChanged` and can thus not be queried from within solidity code.

```solidity
event DIDAttributeChanged(
  address indexed identity,
  bytes32 name,
  bytes value,
  uint validTo,
  uint previousChange
);
```

Note, the name is a `bytes32` type for Ethereum gas efficiency reasons and not a `string`. This restricts us to 32
bytes, which is why we use the short-hand attribute versions explained below.

While any attribute can be stored, for the DID document we currently support adding to each of these sections of the DID
document:

- Public Keys (Verification Methods)
- Service Endpoints

###### Public Keys

The name of the attribute added to ERC1056 should follow this format:
`did/pub/(Secp256k1|RSA|Ed25519|X25519)/(veriKey|sigAuth|enc)/(hex|base64|base58)`

(Essentially `did/pub/<key algorithm>/<key purpose>/<encoding>`)
Please opt for the `base58` encoding since the other encodings are not spec compliant and will be removed in future
versions of the spec and reference resolver.

###### Key purposes

- `veriKey` adds a verification key to the `verificationMethod` section of document
- `sigAuth` adds a verification key to the `verificationMethod` section of document and adds an entry to the
  `authentication` section of document.
- `enc` adds a key agreement key to the `verificationMethod` section. This is used to perform a Diffie-Hellman
  key exchange and derive a secret key for encrypting messages to the DID that lists such a key.

> **Note** The `<encoding>` only refers to the key encoding in the resolved DID document.
> Attribute values sent to the ERC1056 registry should always be hex encodings of the raw public key data.

###### Example Hex encoded Secp256k1 Verification Key

A `DIDAttributeChanged` event for the identity `0xf3beac30c498d9e26865f34fcaa57dbb935b0d74` with the name
`did/pub/Secp256k1/veriKey/hex` and the value of `0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71`
generates a public key entry like the following:

```json
{
  "id": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#delegate-1",
  "type": "EcdsaSecp256k1VerificationKey2019",
  "controller": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74",
  "publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
}
```

###### Example Base58 encoded Ed25519 Verification Key

A `DIDAttributeChanged` event for the identity `0xf3beac30c498d9e26865f34fcaa57dbb935b0d74` with the name
`did/pub/Ed25519/veriKey/base58` and the value of `0xb97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71`
generates a public key entry like this:

```json
{
  "id": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#delegate-1",
  "type": "Ed25519VerificationKey2018",
  "controller": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74",
  "publicKeyBase58": "DV4G2kpBKjE6zxKor7Cj21iL9x9qyXb6emqjszBXcuhz"
}
```

###### Example Base64 encoded X25519 Encryption Key

A `DIDAttributeChanged` event for the identity `0xf3beac30c498d9e26865f34fcaa57dbb935b0d74` with the name
`did/pub/X25519/enc/base64` and the value of
`0x302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052`
generates a public key entry like this:

```json
{
  "id": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#delegate-1",
  "type": "X25519KeyAgreementKey2019",
  "controller": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74",
  "publicKeyBase64": "MCowBQYDK2VuAyEAEYVXd3/7B4d0NxpSsA/tdVYdz5deYcR1U+ZkphdmEFI="
}
```

###### Service Endpoints

The name of the attribute should follow this format:

`did/svc/[ServiceName]`

Example:

A `DIDAttributeChanged` event for the identity `0xf3beac30c498d9e26865f34fcaa57dbb935b0d74` with the name
`did/svc/HubService` and value of the URL `https://hubs.uport.me` hex encoded as
`0x68747470733a2f2f687562732e75706f72742e6d65` generates a service endpoint entry like the following:

```json
{
  "id": "did:vrsc:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#service-1",
  "type": "HubService",
  "serviceEndpoint": "https://hubs.uport.me"
}
```

#### `id` properties of entries

With the exception of `#controller` and `#controllerKey`, the `id` properties that appear throughout the DID document
MUST be stable across updates. This means that the same key material will be referenced by the same ID after an update.

* Attribute or delegate changes that result in `verificationMethod` entries MUST set the `id`
`${did}#delegate-${eventIndex}`.
* Attributes that result in `service` entries MUST set the `id` to `${did}#service-${eventIndex}`

where `eventIndex` is the index of the event that modifies that section of the DID document.

**Example**

* add key => `#delegate-1` is added
* add another key => `#delegate-2` is added
* add delegate => `#delegate-3` is added
* add service => `#service-1` ia added
* revoke first key => `#delegate-1` gets removed from the DID document; `#delegate-2` and `#delegte-3` remain.
* add another delegate => `#delegate-5` is added (earlier revocation is counted as an event)
* first delegate expires => `delegate-3` is removed, `#delegate-5` remains intact

### Update

The DID Document may be updated by invoking the relevant smart contract functions as defined by the ERC1056 standard.
This includes changes to the identity owner, adding delegates and adding additional attributes. Please find a detailed
description in the [ERC1056 documentation](https://github.com/ethereum/EIPs/issues/1056).

These functions will trigger the respective Ethereum events which are used to build the DID Document for a given
identity as described
in [Enumerating Contract Events to build the DID Document](#Enumerating-Contract-Events-to-build-the-DID-Document).

Some elements of the DID Document will be revoked automatically when their validity period expires. This includes the
delegates and additional attributes. Please find a detailed description in the
[ERC1056 documentation](https://github.com/ethereum/EIPs/issues/1056). All attribute and delegate functions will trigger
the respective Ethereum events which are used to build the DID Document for a given identity as described
in [Enumerating Contract Events to build the DID Document](#Enumerating-Contract-Events-to-build-the-DID-Document).

### Delete (Revoke)

Two cases need to be distinguished:

- In case no changes were written to ERC1056, nothing needs to be done, and the private key which belongs to the
  Ethereum address needs to be deleted from the storage medium used to protect the keys, e.g., mobile device.
- In case ERC1056 was utilized, the owner of the smart contract needs to be set to `0x0`. Although, `0x0`is a valid
  Ethereum address, this will indicate the identity has no owner which is a common approach for invalidation, e.g.,
  tokens. To detect if the owner is the null address, one must get the logs of the last change to the identity and
  inspect if the owner was set to the null address (`0x0000000000000000000000000000000000000000`). It is impossible
  to make any other changes to the DID document after such a change, therefore all preexisting keys and services are
  considered revoked.
  
If the intention is to revoke all the signatures corresponding to the DID, the second option MUST be used.

The DID resolution result for a deactivated DID has the following shape:

```json
{
  "didDocumentMetadata": {
    "deactivated": true
  },
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json"
  },
  "didDocument": {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "<the deactivated DID>",
    "verificationMethod": [],
    "authentication": []
  }
}
```

## Metadata

The `resolve` method returns an object with the following properties: `didDocument`, `didDocumentMetadata`,
`didResolutionMetadata`.

### DID Document Metadata

When resolving a DID document that has had updates, the latest update MUST be listed in the `didDocumentMetadata`.
* `versionId` MUST be the block number of the latest update.
* `updated` MUST be the ISO date string of the block time of the latest update (without sub-second resolution).

Example:
```json
{
  "didDocumentMetadata": {
    "versionId": "12090175",
    "updated": "2021-03-22T18:14:29Z"
  }
}
```

### DID Resolution Metadata

```json
{
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json"
  }
}
```

## Resolving DID URIs with query parameters.

### `versionId` query string parameter

This DID method supports resolving previous versions of the DID document by specifying a `versionId` parameter.

Example: `did:vrsc:0x26bf14321004e770e7a8b080b7a526d8eed8b388?versionId=12090175`

The `versionId` is the block number at which the DID resolution MUST be performed.
Only ERC1056 events prior to or contained in this block number are to be considered when building the event history.

If there are any events after that block that mutate the DID, the earliest of them SHOULD be used to populate the
properties of the `didDocumentMetadata`:
* `nextVersionId` MUST be the block number of the next update to the DID document.
* `nextUpdate` MUST be the ISO date string of the block time of the next update (without sub-second resolution).

In case the DID has had updates prior to or included in the `versionId` block number, the `updated` and `versionId`
properties of the `didDocumentMetadata` MUST correspond to the latest block prior to the `versionId` query string param.

Any timestamp comparisons of `validTo` fields of the event history MUST be done against the `versionId` block timestamp.

Example:
`?versionId=12101682`
```json
{
  "didDocumentMetadata": {
    "versionId": "12090175",
    "updated": "2021-03-22T18:14:29Z",
    "nextVersionId": "12276565",
    "nextUpdate": "2021-04-20T10:48:42Z"
  }
}
```

#### Security considerations of DID versioning

Applications must take precautions when using versioned DID URIs.
If a key is compromised and revoked then it can still be used to issue signatures on behalf of the "older" DID URI.
The use of versioned DID URIs is only recommended in some limited situations where the timestamp of signatures can also
be verified, where malicious signatures can be easily revoked, and where applications can afford to check for these
explicit revocations of either keys or signatures.
Wherever versioned DIDs are in use, it SHOULD be made obvious to users that they are dealing with potentially revoked data.

### `initial-state` query string parameter

TBD

## Reference Implementations

The code at [https://github.com/decentralized-identity/vrsc-did-resolver]() is intended to present a reference
implementation of this DID method.

## References

**[1]** <https://w3c-ccg.github.io/did-core/>

**[2]** <https://github.com/ethereum/EIPs/issues/1056>

**[3]** <https://github.com/decentralized-identity/vrsc-did-resolver>

**[4]** <https://github.com/uport-project/vrsc-did-registry>

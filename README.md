# HSM Signing ETH

HSM (Hardware Secure Module) supports a proprietary interface and generic interface (PKCS#11)

Ethereum use keccak256 to sign a transaction

## HSM vs KMS

- **HSM (Hardware Secure Module)** do crypto operation, seperate crypto things from app
- **KMS (Key Management System)** do key management, let app do crypto operation

Ref: <https://blog.fornetix.com/hardware-security-modules-and-encryption-key-management#:~:text=HSM%20moves%20the%20crypto%20operations,perform%20their%20own%20crypto%20functions.>

## Settings

Create your own `.env`

```bash
###########
# Commons #
###########

PROVIDER=<your-infura-provider>

###########
# SoftHSM #
###########

SLOT_PIN=1234
SLOT_NO=0

###########
# AWS-KMS #
###########

ACCESS_KEY_ID=
SECRET_ACCESS_KEY=
KMS_KEY_ID=

```

## Implementation

- Setup HSM - We use SoftHSM
- Use Graphene for JS PKCS#11 library
- Verify signature by using `ecrecover` with `r`, `s` and `v` to retrieve ETH address

## SoftHSM2

> Before getting start, please try init-token before run the code

Github: <https://github.com/psmiraglia/docker-softhsm>

Example Command: <https://github.com/psmiraglia/docker-softhsm>

### SoftHSM commands

Install on macos by `brew install softhsm`

1. Create Token

   ```bash
   ❯ softhsm2-util --init-token --slot 0 --label "ETH Signer"

   === SO PIN (4-255 characters) ===
   Please enter SO PIN: ****
   Please reenter SO PIN: ****
   === User PIN (4-255 characters) ===
   Please enter user PIN: ****
   Please reenter user PIN: ****
   The token has been initialized and is reassigned to slot 188408182
   ```

2. Delete Token

   ```bash
   ❯ softhsm2-util --delete-token --slot 0 --token "My First Token"

   Found token (2c3f0f65-5f52-bfaf-2531-d4f628189a82) with matching token label.
   The token (/usr/local/var/lib/softhsm/tokens/2c3f0f65-5f52-bfaf-2531-d4f628189a82) has been deleted.
   ```

3. Show slot

   ```bash
   ❯ softhsm2-util --show-slots
   Available slots:
   Slot 188408182
      Slot info:
         Description:      SoftHSM slot ID 0xb3ae176
         Manufacturer ID:  SoftHSM project
         Hardware version: 2.6
         Firmware version: 2.6
         Token present:    yes
      Token info:
         Manufacturer ID:  SoftHSM project
         Model:            SoftHSM v2
         Hardware version: 2.6
         Firmware version: 2.6
         Serial number:    e64960a68b3ae176
         Initialized:      yes
         User PIN init.:   yes
         Label:            ETH Signer
   ```

Other commands

```bash
Support tool for PKCS#11
Usage: softhsm2-util [ACTION] [OPTIONS]
Action:
  --delete-token    Delete the token at a given slot.
                    Use with --token or --serial.
                    WARNING: Any content in token will be erased.
  -h                Shows this help screen.
  --help            Shows this help screen.
  --import <path>   Import a key pair from the given path.
                    The file must be in PKCS#8-format.
                    Use with --slot or --token or --serial, --file-pin,
                    --label, --id, --no-public-key, and --pin.
  --init-token      Initialize the token at a given slot.
                    Use with --slot or --token or --serial or --free,
                    --label, --so-pin, and --pin.
                    WARNING: Any content in token will be erased.
  --show-slots      Display all the available slots.
  -v                Show version info.
  --version         Show version info.
Options:
  --aes             Used to tell import to use file as is and import it as AES.
  --file-pin <PIN>  Supply a PIN if the file is encrypted.
  --force           Used to override a warning.
  --free            Use the first free/uninitialized token.
  --id <hex>        Defines the ID of the object. Hexadecimal characters.
                    Use with --force if multiple key pairs may share
                    the same ID.
  --label <text>    Defines the label of the object or the token.
  --module <path>   Use another PKCS#11 library than SoftHSM.
  --no-public-key   Do not import the public key.
  --pin <PIN>       The PIN for the normal user.
  --serial <number> Will use the token with a matching serial number.
  --slot <number>   The slot where the token is located.
  --so-pin <PIN>    The PIN for the Security Officer (SO).
  --token <label>   Will use the token with a matching token label.
```

## Steps

Reference: <https://ethereum.stackexchange.com/questions/73192/using-aws-cloudhsm-to-sign-transactions>

1. Open connection to HSM to create a keypair
2. Retrieve the public key to calculate corresponding ETH address
3. Create a tx like

   ```javascript
   const txParams = {
     nonce: "0x" + nonce.toString(16),
     gasPrice: "0x09184e72a00",
     gasLimit: "0x27100",
     to: "0x4D8519890C77217A352d3cC978B0b74165154421",
     value: web3.utils.toHex(web3.utils.toWei("0.01", "ether")),
     chainId: 4,
   };
   ```

4. Handle to private key request signature

   ```javascript
   const sign = session.createSign("ECDSA", yourPrivateKey);
   const sig = sign.once(msgHash);
   ```

5. `r` is the first 32 bytes, `s` is the second 32 bytes and `v` is calculated value

   ```javascript
   const rs = {
     r: sig.slice(0, 32),
     s: sig.slice(32, 64),
   };
   ```

## Further Reading

- <https://luhenning.medium.com/the-dark-side-of-the-elliptic-curve-signing-ethereum-transactions-with-aws-kms-in-javascript-83610d9a6f81>
- <https://github.com/PeculiarVentures/graphene>
- <https://github.com/SUNET/pkcs11-proxy/blob/master/USAGE>
- <https://github.com/lucashenning/aws-kms-ethereum-signing/blob/master/aws-kms-sign.ts>
- <https://github.com/wshbair/HSM2ETH/blob/master/main.js>
- <https://stackoverflow.com/questions/55747517/hsm-returns-a-67-byte-ecdsa-secp256k1-public-key-what-does-this-mean>
- <https://etherworld.co/2017/11/17/understanding-the-concept-of-private-key-public-key-and-address-in-ethereum-blockchain/>

## Success transaction be like

```bash
❯ node kms-app.js
Generated Ethereum address: 0xbe49f9edf4dfef9ea2a0cc99fe31e93283cd9fdc
s is in the wrong curve... filpping {
  r: '63507246550103913211799200121630693932435627961224814745340471185598666232031',
  s: '95327525057705487496968717802488474339607438014628402368244188282933859413181',
  tempSig: '8c67d3e72b2e95a80e502b67dac1fa1b18f938c43ebee448ee9d65269637d0dfd2c17796bd0ea64aea52b735371ca77125da70ee413c9bf39f7edcebb1456cbd',
  length: 128
}
New s: {
  s: '20464564179610707926602267206199433513230126264446502014360974858584302081156'
}
Verify is equal: {
  ethAddr: '0xbe49f9edf4dfef9ea2a0cc99fe31e93283cd9fdc',
  recoveredEthAddr: '0xbe49f9edf4dfef9ea2a0cc99fe31e93283cd9fdc'
}
s is in the wrong curve... filpping {
  r: '19112615238544339651347136862071208009206489458210448392391828822873187967667',
  s: '60750984576188957845088467154219725679021207682388481191013544826661593769290',
  tempSig: '2a415b5bfc3d25802c069e482cd4089e6e9269d406db67d367edbbc528d262b3864fd6b880cf962af07647c5cf9b38ccc6b20a94176fbe8a11dd6e7686e9654a',
  length: 128
}
New s: {
  s: '55041104661127237578482517854468182173816356596686423191591618314856567725047'
}
Verify is equal: {
  ethAddr: '0xbe49f9edf4dfef9ea2a0cc99fe31e93283cd9fdc',
  recoveredEthAddr: '0xbe49f9edf4dfef9ea2a0cc99fe31e93283cd9fdc'
}
Signed transaction: {
  serializedTx: 'f865808509184000008302710094238fadd911b6f0c4e1ba30f8ee514805e173692580001ba02a415b5bfc3d25802c069e482cd4089e6e9269d406db67d367edbbc528d262b3a079b029477f3069d50f89b83a3064c731f3fcd25297d8e1b1adf4f016494cdbf7',
  txHash: '4022162f3df4cc08e83fedc4bc01284de34da38dca4d2deba0863155f32cd437'
}
Current account balance is 1100000000000000000
Confirmation: 0
Receipt to return: {
  blockHash: '0x4d32ceb42787171e0b2cfd0447845274885d0256d9ec2119c96708bdea901085',
  blockNumber: 9412148,
  contractAddress: null,
  cumulativeGasUsed: 114342,
  effectiveGasPrice: '0x918400000',
  from: '0xbe49f9edf4dfef9ea2a0cc99fe31e93283cd9fdc',
  gasUsed: 21004,
  logs: [],
  logsBloom: '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  status: true,
  to: '0x238fadd911b6f0c4e1ba30f8ee514805e1736925',
  transactionHash: '0xc7d2cbd82abd8fb75633757efa856756ef05d8cc2d6238e6d4da92ee89de0480',
  transactionIndex: 2,
  type: '0x0'
}
Sign and sendTx txReceipt, transaction hash: 0xc7d2cbd82abd8fb75633757efa856756ef05d8cc2d6238e6d4da92ee89de0480
Confirmation: 1
Receipt to return: {
  blockHash: '0x4d32ceb42787171e0b2cfd0447845274885d0256d9ec2119c96708bdea901085',
  blockNumber: 9412148,
  contractAddress: null,
  cumulativeGasUsed: 114342,
  effectiveGasPrice: '0x918400000',
  from: '0xbe49f9edf4dfef9ea2a0cc99fe31e93283cd9fdc',
  gasUsed: 21004,
  logs: [],
  logsBloom: '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  status: true,
  to: '0x238fadd911b6f0c4e1ba30f8ee514805e1736925',
  transactionHash: '0xc7d2cbd82abd8fb75633757efa856756ef05d8cc2d6238e6d4da92ee89de0480',
  transactionIndex: 2,
  type: '0x0'
}
```

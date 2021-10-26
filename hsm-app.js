const graphene = require("graphene-pk11");
const { keccak256 } = require("js-sha3");
const ethUtil = require("ethereumjs-util");
const BN = require("bn.js");
const { Transaction } = require("@ethereumjs/tx");
const Common = require("@ethereumjs/common").default;
const { Chain } = require("@ethereumjs/common");
const Web3 = require("web3");
const prompt = require("prompt-sync")();

require("dotenv").config();

// TODO: To complete this, find way to store keys and make wallet address always the same

const PROVIDER = process.env.PROVIDER;
const LIB = "/usr/local/lib/softhsm/libsofthsm2.so";
const SLOT_PIN = process.env.SLOT_PIN;
const SLOT_NO = Number(process.env.SLOT_NO);

const web3 = new Web3(new Web3.providers.HttpProvider(PROVIDER));

const Module = graphene.Module;
const mod = Module.load(LIB, "SoftHSM");
mod.initialize();

function decodeECPointToPublicKey(data) {
  if (data.length === 0 || data[0] !== 4) {
    throw new Error("Only uncompressed point format supported");
  }
  // ASN first 3 bytes
  // 04 - OCTET STRING, 41 - Length 65 bytes
  // For secp256k1, 044104 always at beginning
  return data.slice(3, 67);
}

function calculateEthSig(session, msgHash, ethAddr, privateKey) {
  // Continue signing until find s < (secp256k1.size/2)
  let flag = true;
  let tempSig;

  // Not all EC signature is a valid signature
  while (flag) {
    const sign = session.createSign("ECDSA", privateKey);
    tempSig = sign.once(msgHash);
    const _s = tempSig.slice(32, 64);
    const sValue = new BN(_s.toString("hex"), 16); // Hex
    const secp256k1N = new BN(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      16
    ); // Max value on the curve
    const secp256k1halfN = secp256k1N.div(new BN(2));
    if (sValue.lt(secp256k1halfN)) {
      flag = false;
    }
  }

  const rs = {
    r: tempSig.slice(0, 32),
    s: tempSig.slice(32, 64),
  };

  let v = 27;
  let publicKey = ethUtil.ecrecover(ethUtil.toBuffer(msgHash), v, rs.r, rs.s);
  let addrBuffer = ethUtil.pubToAddress(publicKey);
  let recoveredEthAddr = ethUtil.bufferToHex(addrBuffer);

  if (ethAddr !== recoveredEthAddr) {
    v = 28;
    publicKey = ethUtil.ecrecover(ethUtil.toBuffer(msgHash), v, rs.r, rs.s);
    addrBuffer = ethUtil.pubToAddress(publicKey);
    recoveredEthAddr = ethUtil.bufferToHex(addrBuffer);
  }

  console.log("Verify is equal:", { ethAddr, recoveredEthAddr });

  return { r: rs.r, s: rs.s, v: v };
}

// Main function
async function main() {
  const slot = mod.getSlots(SLOT_NO);
  if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
    const session = slot.open(
      graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
    );
    session.login(SLOT_PIN);

    // Generate key pair
    const keys = session.generateKeyPair(
      graphene.KeyGenMechanism.ECDSA,
      {
        keyType: graphene.KeyType.ECDSA,
        id: Buffer.from([1, 2, 3, 4, 5]), // Uniquer id for keys in storage https://www.cryptsoft.com/pkcs11doc/v230/group__SEC__9__7__KEY__OBJECTS.html
        label: "publickey",
        token: true,
        verify: true,
        paramsECDSA: graphene.NamedCurve.getByName("secp256k1").value,
      },
      {
        keyType: graphene.KeyType.ECDSA,
        id: Buffer.from([1, 2, 3, 4, 5]), // Uniquer id for keys in storage https://www.cryptsoft.com/pkcs11doc/v230/group__SEC__9__7__KEY__OBJECTS.html
        label: "privatekey",
        token: true,
        sign: true,
      }
    );

    console.log("Key type:", graphene.KeyType[keys.privateKey.type]); // Key type: EC
    console.log("Object's class:", graphene.ObjectClass[keys.privateKey.class]); // Object's class: PRIVATE_KEY

    // Extract public key and calculate ethereum address

    // The first 3 bytes for uncompressed key
    // https://datatracker.ietf.org/doc/html/rfc5480#section-2.2
    const publicKey = decodeECPointToPublicKey(
      keys.publicKey.getAttribute({ pointEC: null }).pointEC
    );
    const address = keccak256(publicKey);
    const buf2 = Buffer.from(address, "hex");
    const ethAddr = `0x${buf2.slice(-20).toString("hex")}`; // Take last 20 bytes as Ethereum adress
    console.log("Generated Ethereum address:", ethAddr);

    // 1. Sign the ethereum address of the sender
    const encodedMsg = ethAddr;
    const msgHash = ethUtil.keccak256(Buffer.from(encodedMsg)); // Use Ethereum address for signing
    const addressSign = calculateEthSig(
      session,
      msgHash,
      encodedMsg,
      keys.privateKey
    );
    console.log("Verified Ethereum address:", {
      r: addressSign.r,
      s: addressSign.s,
      v: addressSign.v,
    });

    const txParams = {
      nonce: await web3.eth.getTransactionCount(ethAddr), // Change nonce everytime sending
      gasPrice: "0x0918400000",
      gasLimit: 160000,
      to: "0x238fadd911b6F0C4e1Ba30f8ee514805e1736925",
      value: "0x00",
      data: ethUtil.bufferToHex(Buffer.from("krgko_hsm")),
      r: addressSign.r,
      s: addressSign.s,
      v: addressSign.v,
    };

    // https://github.com/ethereumjs/ethereumjs-monorepo/tree/master/packages/tx#legacy-transactions
    // https://github.com/ethereumjs/ethereumjs-monorepo/tree/master/packages/common
    const common = new Common({ chain: Chain.Rinkeby });
    const tx = new Transaction(txParams, { common, freeze: false });
    const txHash = tx.getMessageToSign();

    // 2. Sign the raw transaction
    const txSig = calculateEthSig(session, txHash, ethAddr, keys.privateKey);
    tx.r = new BN(txSig.r);
    tx.s = new BN(txSig.s);
    tx.v = new BN(txSig.v);

    const serializedTx = tx.serialize().toString("hex");
    console.log("Signed transaction:", {
      raw: tx.toJSON(),
      sender: ethUtil.bufferToHex(
        ethUtil.pubToAddress(tx.getSenderPublicKey())
      ),
      serializedTx,
      txHash: txHash.toString("hex"),
    });

    // Due to every time exec it create new address
    let ans;
    while (ans !== "y") {
      ans = prompt(`Did you fund ${ethAddr} already? [at lease 0.5ETH] (y/n): `);
      if (ans === "y" || ans === "Y") {
        console.log("Sending transaction ...");
        web3.eth
          .sendSignedTransaction("0x" + serializedTx)
          .on("confirmation", function (confirmationNumber, receipt) {
            console.log("Confirmation:", confirmationNumber);
            console.log("Receipt to return:", receipt);
          })
          .on("receipt", (txReceipt) => {
            console.log(
              "Sign and sendTx txReceipt, transaction hash: " +
                txReceipt.transactionHash
            );
          })
          .on("error", console.error);
        return;
      }
      if (ans === "n" || ans === "N") {
        return;
      }
    }

    session.logout();
    session.close();
  } else {
    console.log("Error: cannot found available slot");
  }

  mod.finalize();
}

main();

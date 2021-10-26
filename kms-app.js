// Old version ethereumjs-tx

const { keccak256 } = require("js-sha3");
const ethUtil = require("ethereumjs-util");
const BN = require("bn.js");
const { Transaction } = require("ethereumjs-tx");
const Common = require("@ethereumjs/common").default;
const { Chain } = require("@ethereumjs/common");
const Web3 = require("web3");
const { KMS } = require("aws-sdk");
const asn1 = require("asn1.js");

require("dotenv").config();

// Note: On AWS-KMS we use ECC_SECG_P256K1 for signing/verification

const PROVIDER = process.env.PROVIDER;
const ACCESS_KEY_ID = process.env.ACCESS_KEY_ID;
const SECRET_ACCESS_KEY = process.env.SECRET_ACCESS_KEY;
const REGION = "ap-southeast-1";
const API_VERSION = "latest";
const KMS_KEY_ID = process.env.KMS_KEY_ID;

const kms = new KMS({
  accessKeyId: ACCESS_KEY_ID,
  secretAccessKey: SECRET_ACCESS_KEY,
  region: REGION,
  apiVersion: API_VERSION,
});

const EcdsaSigAsnParse = asn1.define("EcdsaSig", function () {
  // Parsing according to https://datatracker.ietf.org/doc/html/rfc5480#section-2
  // r = x, s = y :: coordinate of EC
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

const EcdsaPubKey = asn1.define("EcdsaPubKey", function () {
  // Parsing according to https://datatracker.ietf.org/doc/html/rfc5480#section-2
  this.seq().obj(
    this.key("algo").seq().obj(this.key("a").objid(), this.key("b").objid()),
    this.key("pubKey").bitstr()
  );
});

function getEthAddr(publicKey) {
  // Defined the schema in EcdsaPubKey object
  const result = EcdsaPubKey.decode(publicKey, "der");

  // Remove 0x04 which is the public key start
  let pubKeyBuffer = result.pubKey.data;
  pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length);

  const address = keccak256(pubKeyBuffer); // Need to add buffer
  const buf2 = Buffer.from(address, "hex");

  // https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html, take last 20 bytes as Ethereum adress
  const ethAddr = `0x${buf2.slice(-20).toString("hex")}`;
  console.log("Generated Ethereum address:", ethAddr);

  return ethAddr;
}

async function sign(msgHash, keyId) {
  const params = {
    KeyId: keyId,
    Message: msgHash,
    SigningAlgorithm: "ECDSA_SHA_256",
    MessageType: "DIGEST",
  };
  return kms.sign(params).promise();
}

async function calculateEthSig(msgHash, ethAddr) {
  const signature = await sign(msgHash, KMS_KEY_ID);
  if (!signature.Signature) {
    throw new Error("Signature is undefined.");
  }

  const decoded = EcdsaSigAsnParse.decode(signature.Signature, "der");
  const r = decoded.r; // BN
  let s = decoded.s; // BN

  const tempSig = r.toString(16) + s.toString(16);

  // Continue signing until find s < (secp256k1.size/2)
  // Not all EC signature is a valid signature
  const secp256k1N = new BN(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    16
  ); // Max value on the curve
  const secp256k1halfN = secp256k1N.div(new BN(2));

  if (s.gt(secp256k1halfN)) {
    console.log("s is in the wrong curve... filpping", {
      r: r.toString(10),
      s: s.toString(10),
      tempSig,
      length: tempSig.length,
    });

    s = secp256k1N.sub(s);
    console.log("New s:", { s: s.toString(10) });
  }

  const rs = {
    r,
    s,
  };

  // Recover public key from signature
  // Find the right v, there are 2 matching eliptic curve signature - can be 27 or 28
  let v = 27;
  let publicKey = ethUtil.ecrecover(
    msgHash,
    v,
    rs.r.toBuffer(),
    rs.s.toBuffer()
  );
  let addrBuffer = ethUtil.pubToAddress(publicKey);
  let recoveredEthAddr = ethUtil.bufferToHex(addrBuffer);

  if (ethAddr !== recoveredEthAddr) {
    v = 28;
    publicKey = ethUtil.ecrecover(msgHash, v, rs.r.toBuffer(), rs.s.toBuffer());
    addrBuffer = ethUtil.pubToAddress(publicKey);
    recoveredEthAddr = ethUtil.bufferToHex(addrBuffer);
  }

  console.log("Verify is equal:", { ethAddr, recoveredEthAddr });

  return { r: rs.r, s: rs.s, v: v };
}

async function getPublicKey(keyId) {
  // Return object contains public-key in DER-encoded x509 format
  // a.k.a https://datatracker.ietf.org/doc/html/rfc5480#section-2, Subject Public Key Info (SPKI)
  return kms.getPublicKey({ KeyId: keyId }).promise();
}

// Main function
async function main() {
  const web3 = new Web3(new Web3.providers.HttpProvider(PROVIDER));

  const kmsPubKey = await getPublicKey(KMS_KEY_ID);
  const ethAddr = getEthAddr(kmsPubKey.PublicKey);
  const ethAddrHash = ethUtil.keccak256(Buffer.from(ethAddr));

  const addressSign = await calculateEthSig(ethAddrHash, ethAddr);
  const txParams = {
    nonce: await web3.eth.getTransactionCount(ethAddr), // Change nonce everytime sending
    gasPrice: "0x0918400000",
    gasLimit: 160000,
    to: "0x238fadd911b6F0C4e1Ba30f8ee514805e1736925",
    value: "0x00",
    data: ethUtil.bufferToHex(Buffer.from("krgko")),
    r: addressSign.r,
    s: addressSign.s,
    v: addressSign.v,
  };

  // https://github.com/ethereumjs/ethereumjs-monorepo/tree/master/packages/tx#legacy-transactions
  // https://github.com/ethereumjs/ethereumjs-monorepo/tree/master/packages/common
  // const common = new Common({ chain: Chain.Rinkeby });
  const tx = new Transaction(txParams, { chain: 'rinkeby' });
  const txHash = tx.hash(false);

  // 2. Sign the raw transaction
  const txSig = await calculateEthSig(txHash, ethAddr);
  tx.r = txSig.r;
  tx.s = txSig.s;
  tx.v = txSig.v;

  const serializedTx = tx.serialize().toString("hex");
  console.log(tx)
  console.log("Signed transaction:", {
    serializedTx,
    txHash: txHash.toString("hex"),
  });

  const balance = await web3.eth.getBalance(ethAddr);
  console.log("Current account balance is", balance);
  if (balance > 0) {
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
  } else {
    console.log("The account has not fund yet");
  }
}

main();

import _sodium from 'libsodium-wrappers';
import Wallet from 'ethereumjs-wallet';
import utils from 'ethereumjs-util';
import path from 'path';
const openpgp = require('openpgp');
import Promise from 'bluebird';
const fs = Promise.promisifyAll(require('fs'));

const { Console } = require('console');
global.console = new Console(process.stderr, process.stderr);

import trispussizeite from '../index';

let sodium;

describe('trispussizeite', () => {
  
  beforeAll(async () => {
    await _sodium.ready;
    sodium = _sodium;
  });

  it('gpg -> openpgp -> web3', async () => {
    // Retrieve Alice's ED25519 GPG Key
    const alicePassphrase = 'secret';
    const alicePrivateKeyArmored = (await fs.readFileAsync(
      path.join(__dirname, '../../../data/private_key.asc')
    )).toString();
    const alice = openpgp.key.readArmored(
      alicePrivateKeyArmored
    ).keys[0];
    await alice.decrypt(alicePassphrase);
    const alicePrimaryKey = alice.primaryKey;
    const aliceUser = alice.users[0];

    // Self Certificate is valid
    expect(await aliceUser.selfCertifications[0].verify(
      alicePrimaryKey, { userid: aliceUser.userId, key: alicePrimaryKey }
    ));
    expect(await aliceUser.verifyCertificate(
      alicePrimaryKey, aliceUser.selfCertifications[0], [alice.toPublic()]
    )).toEqual(openpgp.enums.keyStatus.valid);

    // Generate and decrypt a new secp256k1 pgp key for Bob
    const bobPassphrase = 'secp256k1 key';
    const bobOptions = {
      userIds: [{ name: 'Bob (secp256k1)', email: 'bob@example.com' }],
      curve: 'secp256k1',
      passphrase: bobPassphrase
    };
    const bobKey = await openpgp.generateKey(bobOptions);
    const bob = openpgp.key.readArmored(
      bobKey.privateKeyArmored
    ).keys[0];
    await bob.decrypt(bobPassphrase);
    const bobPrimaryKey = bob.primaryKey;
    const bobUser = bob.users[0];

    // Self Certificate is valid
    expect(await bobUser.selfCertifications[0].verify(
      bobPrimaryKey, { userid: bobUser.userId, key: bobPrimaryKey }
    ));
    expect(await bobUser.verifyCertificate(
      bobPrimaryKey, bobUser.selfCertifications[0], [bob.toPublic()]
    )).toEqual(openpgp.enums.keyStatus.valid);

    // Alice trusts Bob
    const trustedBob = await bob.toPublic().signPrimaryUser([alice]);
    expect(await trustedBob.users[0].otherCertifications[0].verify(
      alicePrimaryKey, { userid: bobUser.userId, key: bob.toPublic().primaryKey }
    )).toBe(true);

    // Bob trusts Alice
    const trustedAlice = await alice.toPublic().signPrimaryUser([bob]);
    expect(await trustedAlice.users[0].otherCertifications[0].verify(
      bobPrimaryKey, { userid: aliceUser.userId, key: alice.toPublic().primaryKey }
    )).toBe(true);

    // Signing message
    const signed = await openpgp.sign({ data: 'Hello, World!', privateKeys: bob })
    const msg = openpgp.cleartext.readArmored(signed.data);
    // Verifying signed message
    const msgOutput = await openpgp.verify({ message: msg, publicKeys: bob.toPublic() });
    expect(msgOutput.signatures[0].valid);
    // Verifying detached signature
    const sigOutput = await openpgp.verify({
      message: openpgp.message.fromText('Hello, World!'),
      publicKeys: bob.toPublic(),
      signature: openpgp.signature.readArmored(signed.data)
    });
    expect(sigOutput.signatures[0].valid);

    // Encrypting and decrypting
    const msgData = 'Alice wrote this, and only Bob can read it.';
    const encrypted = await openpgp.encrypt({
      data: msgData,
      publicKeys: [bob.toPublic()],
      privateKeys: [alice]
    });
    const encryptedMsg = await openpgp.message.readArmored(encrypted.data);

    // Decrypting and verifying
    const decryptedMsg = await openpgp.decrypt({
      message: encryptedMsg,
      privateKeys: [bob],
      publicKeys: [alice.toPublic()]
    });
    expect(decryptedMsg.data).toEqual(msgData);
    expect(decryptedMsg.signatures[0].valid);

    // Create Ethereum wallet from Bob key
    const wallet = Wallet.fromPrivateKey(
      new Buffer(sodium.to_hex(bob.primaryKey.params[2].data), 'hex')
    );

    // Sign message with Ethereum wallet
    const ethMsg = 'Hello, World!';
    const msgHash = utils.sha3(ethMsg);
    const { v, r, s } = utils.ecsign(msgHash, wallet._privKey);
    const pubKey = utils.ecrecover(msgHash, v, r, s);

    // Validate Ethereum pubKey matches PGP pubKey
    const publicKeyHex = sodium.to_hex(bob.primaryKey.params[1].data).substring(2);
    expect(pubKey.toString('hex')).toEqual(publicKeyHex);

    // Verify Ethereum Address
    const addr = utils.pubToAddress(pubKey);
    const wallet_address = '0x' + wallet.getAddress().toString('hex');
    expect('0x' + addr.toString('hex')).toBe(wallet_address);

    // Verifying from armored public keys
    
    // Reading Bob from plaintext
    const bobPub = openpgp.key.readArmored(
      trustedBob.armor()
    ).keys[0];

    // Reading Alice from plaintext
    const alicePub = openpgp.key.readArmored(
      trustedAlice.armor()
    ).keys[0];

    // Verify Bob email
    expect(bobPub.users[0].userId.userid.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi)[0]).toEqual('bob@example.com');

    // Verify Alice email
    expect(alicePub.users[0].userId.userid.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi)[0]).toEqual('alice@example.com');

    // Verify that Bob trusts Alice
    expect(await bobPub.users[0].otherCertifications[0].verify(
      alicePub.primaryKey, { userid: bobPub.users[0].userId, key: bobPub.primaryKey }
    )).toBe(true);

    // Verify that Alice trusts Bob
    expect(await alicePub.users[0].otherCertifications[0].verify(
      bobPub.primaryKey, { userid: alicePub.users[0].userId, key: alicePub.primaryKey }
    )).toBe(true);
  });

  afterAll(() => {
    // CLEAN()
  });
});
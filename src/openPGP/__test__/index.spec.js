import path from 'path';
import g9g from '../index';

describe('g9g', () => {
  const passphrase = 'secret';

  beforeAll(async () => {
    let gpg = await g9g.gpg_import({
      publicKeys: path.join(__dirname, '../../data/public_keys.asc'),
      privateKeys: path.join(__dirname, '../../data/private_keys.asc'),
      trust: path.join(__dirname, '../../data/trust.txt')
    });
    expect(gpg.call).toBeDefined();
  });

  it('encrypt + decrypt', async () => {
    let plaintext_buffer = Buffer.from('Hello ' + new Date().toString());
    // console.log('plaintext_buffer: ', plaintext_buffer);
    let encrypted_buffer = await g9g.encrypt({
      passphrase,
      input_buffer: plaintext_buffer
    });
    // console.log('encrypted_buffer: ', encrypted_buffer);
    let decrypted_plaintext_buffer = await g9g.decrypt({
      passphrase,
      input_buffer: encrypted_buffer
    });
    // console.log('decrypted_plaintext_buffer: ', decrypted_plaintext_buffer);
    expect(decrypted_plaintext_buffer).toEqual(plaintext_buffer);
  });

  it('sign + verify', async () => {
    let plaintext_buffer = Buffer.from('Hello ' + new Date().toString());
    // console.log('plaintext_buffer: ', plaintext_buffer);
    let signature_buffer = await g9g.sign({
      passphrase,
      input_buffer: plaintext_buffer
    });
    // console.log('signature_buffer: ', signature_buffer);
    let verified_signature = await g9g.verify({
      passphrase,
      input_buffer: signature_buffer
    });
    expect(verified_signature).toBe(true);
    // console.log('verified_signature: ', verified_signature);
  });

  afterAll(() => {
    // CLEAN()
  });
});
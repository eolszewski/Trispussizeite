var gpg = require('gpg');
var Promise = require('bluebird');
var fs = Promise.promisifyAll(require('fs'));

const input_file = '/tmp/temp.input_file';
const output_file = '/tmp/temp.output_file';

const import_key = key => {
  return new Promise((resolve, reject) => {
    gpg.importKeyFromFile(key, (err, result, fingerprint) => {
      if (err) {
        reject(err);
      } else {
        resolve({
          result,
          fingerprint
        });
      }
    });
  });
};

const gpg_import = async ({ publicKey, privateKey, trust }) => {
  await import_key(publicKey);
  await import_key(privateKey);
  return gpg;
};

const encrypt = async ({ passphrase, input_buffer }) => {
  return new Promise(async (resolve, reject) => {
    let stdinStr = passphrase;
    let argsArray = [
      '--batch',
      '--passphrase-fd',
      '0',
      '--no-tty',
      '-c',
      '--output',
      output_file,
      input_file
    ];
    await fs.writeFileAsync(input_file, input_buffer);
    gpg.call(stdinStr, argsArray, async (err, data) => {
      if (err) {
        reject(err);
      } else {
        data = await fs.readFileAsync(output_file);
        await fs.unlinkAsync(output_file);
        await fs.unlinkAsync(input_file);
        resolve(data);
      }
    });
  });
};

const decrypt = async ({ passphrase, input_buffer }) => {
  return new Promise(async (resolve, reject) => {
    let stdinStr = passphrase;
    let argsArray = [
      '--batch',
      '--passphrase-fd',
      '0',
      '--no-tty',
      '-d',
      '--output',
      output_file,
      input_file
    ];
    let data = await fs.writeFileAsync(input_file, input_buffer);
    gpg.call(stdinStr, argsArray, async (err, data) => {
      if (err) {
        reject(err);
      } else {
        data = await fs.readFileAsync(output_file);
        await fs.unlinkAsync(output_file);
        await fs.unlinkAsync(input_file);
        resolve(data);
      }
    });
  });
};

const sign = async ({ passphrase, input_buffer, user }) => {
  return new Promise(async (resolve, reject) => {
    let stdinStr = passphrase;
    let argsArray = [
      '--batch',
      '--pinentry-mode',
      'loopback',
      '--command-fd',
      '0',
      '-u',
      user,
      '--output',
      output_file,
      '--sign',
      input_file
    ];
    await fs.writeFileAsync(input_file, input_buffer);
    gpg.call(stdinStr, argsArray, async (err, data) => {
      if (err) {
        reject(err);
      } else {
        data = await fs.readFileAsync(output_file);
        await fs.unlinkAsync(output_file);
        await fs.unlinkAsync(input_file);
        resolve(data);
      }
    });
  });
};

const verify = async ({ passphrase, input_buffer }) => {
  return new Promise(async (resolve, reject) => {
    let stdinStr = passphrase;
    let argsArray = ['--verify', input_file];
    await fs.writeFileAsync(input_file, input_buffer);
    gpg.call(stdinStr, argsArray, async (err, data) => {
      if (err) {
        reject(err);
      } else {
        await fs.unlinkAsync(input_file);
        resolve(true);
      }
    });
  });
};

module.exports = {
  gpg_import,
  encrypt,
  decrypt,
  sign,
  verify
};
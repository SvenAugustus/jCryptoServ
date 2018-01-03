/*
 * jCryptoServ JavaScript data encryption v1.0.0
 *
 * Copyright (c) 2020 Sven Augustus
 * Apache License
 * Version 2.0, January 2004
 * http://www.apache.org/licenses/
 *
 * @author Sven Augustus
 *
 * depends：
 * 1、CryptoJS v3.1.2  rollups/aes.js、rollups/pbkdf2.js
 * 2、JSEncrypt v2.3.1
 */
function jCryptoServ(keySize, iterationCount) {
  this.keySize = keySize;
  this.PBKDF2KeySize = keySize / 32;
  this.PBKDF2IterationCount = iterationCount;
}

jCryptoServ.prototype.defaultOptions = {
  getKeysURL: "crypto?generateKeyPair=true",
  handshakeURL: "crypto?handshakes=true"
};

/**
 * Authenticate with the server (One way)
 *
 * @param {function}
 *            success The function to call if the operation was successfull
 * @param {function}
 *            failure The function to call if an error has occurred
 * @param {object}
 *            options config the urls
 */
jCryptoServ.prototype.authenticateOnway = function (success, failure, options) {
  var _options = $.extend({}, this.defaultOptions, options);
  var AESEncryptionKey = this.getSecret();
  this.authenticate(AESEncryptionKey, _options.getKeysURL,
      _options.handshakeURL, success, failure);
};

/**
 * Creates a random string(key) for use in the AES algorithm
 */
jCryptoServ.prototype.getSecret = function () {
  var key;
  if (window.crypto && window.crypto.getRandomValues) {
    var ckey = new Uint32Array(2); // Uint32Array 2 = 16 B = 128 bits
    window.crypto.getRandomValues(ckey);
    key = CryptoJS.lib.WordArray.create(ckey).toString(CryptoJS.enc.Hex);
  } else {
    key = CryptoJS.lib.WordArray.random(128 / 16).toString(CryptoJS.enc.Hex);
  }
  return key;
};

/**
 * Authenticates with the server
 *
 * @param {string}
 *            AESEncryptionKey The AES key
 * @param {string}
 *            publicKeyURL The public key URL
 * @param {string}
 *            handshakeURL The handshake URL
 * @param {function}
 *            success The function to call if the operation was successfull
 * @param {function}
 *            failure The function to call if an error has occurred
 */
jCryptoServ.prototype.authenticate = function (AESEncryptionKey, publicKeyURL,
    handshakeURL, success, failure) {
  var _self = this;
  // 1. client requests RSA public key from server
  _self.getPublicKey(publicKeyURL, function (publickey) {
    var jsEncrypt = new JSEncrypt();

    jsEncrypt.setPublicKey(publickey);

    // 2.client encrypts a randomly generated key with the RSA public key
    _self.encryptKey(jsEncrypt, AESEncryptionKey, function (encryptedKey) {

      // 3.server decrypts key with the RSA private key and stores it in the session
      // 4.server encrypts the decrypted key with AES and sends it back to the client
      _self.handshake(handshakeURL, encryptedKey, function (response) {

        // 5.client decrypts it with AES,
        // if the key matches the client is in sync with the server and is ready to go
        if (_self.challenge(response.challenge, AESEncryptionKey)) {
          // 6.everything else is encrypted using AES
          success.call(this, AESEncryptionKey);
        } else {
          failure.call(this);
        }
      });
    });
  });
};

/**
 * Gets the RSA keys from the specified url, and saves it into a RSA keypair
 *
 * @param {string}
 *            url The url to contact
 * @param {function}
 *            callback The function to call when the operation has finshed
 */
jCryptoServ.prototype.getPublicKey = function (url, callback) {
  $.getJSON(url, function (data) {
    if ($.isFunction(callback)) {
      callback.call(this, data.publickey);
    }
  });
};

jCryptoServ.prototype.generateKey = function (salt, passPhrase) {
  var key = CryptoJS.PBKDF2(passPhrase, CryptoJS.enc.Hex.parse(salt), {
    keySize: this.PBKDF2KeySize,
    iterations: this.PBKDF2IterationCount
  });
  return key;
};

jCryptoServ.prototype.lpad = function (str, size, ch) {
  return (Array(size).join(ch) + str).slice(-size);
};

/**
 * Decrypts data using AES 128/256
 *
 * @param {string}
 *            cipherText The data to decrypt(Ciphertext)
 * @param {string}
 *            secret The AES secret
 * @returns {string} The result of the decryption(Plaintext)
 */
jCryptoServ.prototype.decrypt = function (cipherText, secret) {
  var passPhrase = secret.toString();
  var salt = this.lpad(passPhrase, 32, '0');
  var iv = this.lpad(passPhrase, 32, '0');
  //alert(cipherText);

  var key = this.generateKey(salt, passPhrase);
  var cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Base64.parse(cipherText)
  });
  var decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
    iv: CryptoJS.enc.Hex.parse(iv)
  });
  return decrypted.toString(CryptoJS.enc.Utf8);
};

/**
 * Encrypts data using AES 128/256
 *
 * @param {string}
 *            plainText The data to encrypt(Plaintext)
 * @param {string}
 *            secret The AES secret
 * @returns {string} The result of the encryption(Ciphertext)
 */
jCryptoServ.prototype.encrypt = function (plainText, secret) {
  var passPhrase = secret.toString();
  var salt = this.lpad(passPhrase, 32, '0');
  var iv = this.lpad(passPhrase, 32, '0');

  var key = this.generateKey(salt, passPhrase);
  var encrypted = CryptoJS.AES.encrypt(plainText, key, {
    iv: CryptoJS.enc.Hex.parse(iv)
  });
  return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
};

/**
 * Makes sure that the challenge the client sent, is correct
 *
 * @param {string}
 *            challenge The challenge string
 * @param {string}
 *            secret The AES secret
 */
jCryptoServ.prototype.challenge = function (challenge, secret) {
  var _self = this;

  var decrypt = _self.decrypt(challenge, secret);
  if (decrypt == secret) {
    return true;
  }
  return false;
};

/**
 * Executes a handshake with the server
 *
 * @param {string}
 *            url The url to connect to
 * @param {string}
 *            ecrypted The encrypted AES secret
 * @param {function}
 *            callback The function to call when the handshaking has finished
 */
jCryptoServ.prototype.handshake = function (url, ecrypted, callback) {
  $.ajax({
    url: url,
    dataType: "json",
    type: "POST",
    data: {
      key: ecrypted
    },
    success: function (response) {
      callback.call(this, response);
    }
  });
};
/**
 * Encrypts the AES secret using RSA
 *
 * @param {object}
 *            JSEncrypt object
 * @param {string}
 *            secret The AES secret
 * @param {function}
 *            callback The function to call when the encryption has finished
 */
jCryptoServ.prototype.encryptKey = function (jsEncrypt, secret, callback) {
  var encryptedString = jsEncrypt.encrypt(secret);

  if ($.isFunction(callback)) {
    callback(encryptedString);
  } else {
    return encryptedString;
  }
};

var jCryptoServ = new jCryptoServ(128, 1000);// 128 Bits





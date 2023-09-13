const CRYPTO_PASS = process.env.CRYPTO_PASS;
const CRYPTO_SALT = process.env.CRYPTO_SALT;
const CryptoJS = require("crypto-js");
var password = CRYPTO_PASS;
var salt = CRYPTO_SALT;
var key = CryptoJS.PBKDF2(password, salt,{
  keySize: 256 / 32,
  iterations: 100,
});
module.exports = {
  encrypt: (str) => {
    try {
      return CryptoJS.AES.encrypt(str, key.toString()).toString();
    } catch (error) {
      return "error";
    }
  },
 decrypt: (str) => {
    try {
      const dattt = CryptoJS.AES.decrypt(str, key.toString());
      return dattt.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      return "error";
    }
  },
  encryptobj: (obj) => {
    try {
      return CryptoJS.AES.encrypt(
        JSON.stringify(obj),
        key.toString()
      ).toString();
    } catch (error) {
      return "error";
    }
  },
  decryptobj: (str) => {
    try {
      const objt = CryptoJS.AES.decrypt(str,key.toString());
     
      return JSON.parse(objt.toString(CryptoJS.enc.Utf8));
    } catch (error) {
      console.log("----", error);
      return "error";
    }
  },
};
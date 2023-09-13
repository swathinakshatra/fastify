const tiger = require("tiger-balm");
const tigerpassword = process.env.TIGER_PASSWORD;
const tigersalt = process.env.TIGER_SALT;
var password = tigerpassword;
var salt = tigersalt;
module.exports = {
  encrypt: (text) => {
    const encryptedtext = tiger.encrypt(password, salt, text);
    if (!encryptedtext) {
      return "text not encrypted";
    }
    return encryptedtext;
  },
  decrypt: (text) => {
    const decryptedtext = tiger.decrypt(password, salt, text);
    if (!decryptedtext) {
      return "text not encrypted";
    }
    return decryptedtext;
  },
};
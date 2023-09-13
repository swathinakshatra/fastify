const randomstring = require("randomstring");



const generateId = () => {
  const randomChars = randomstring.generate({
    length: 15, 
    charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  });

  const id = randomChars + "@RAILS";
  return id;
}










const generatecoinid = () => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let coinid = '';
  for (let i = 0; i < 16; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    coinid += characters.charAt(randomIndex);
  }
  return coinid;
};








module.exports = {generatecoinid ,generateId};
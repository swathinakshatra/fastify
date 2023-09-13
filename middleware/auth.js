require("dotenv").config();
const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).send('Access denied. No Token provided.');
  
  try {
    const decoded = jwt.verify(token, process.env.jwtPrivateKey);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).send('Invalid token.');
  }
}

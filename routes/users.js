
const Queries=require('../helpers/mongofunctions');
const {twofactorRegistration,
   loginuser,
   validateemail,
   loginverify, verifytwofa, validatelimit}
   =require('../helpers/validations');
const bcrypt = require("bcrypt");
const { generateId } = require("../middleware/userid");
const redisquery=require('../helpers/redis');
const jwt = require("jsonwebtoken");
const twofactor = require("node-2fa");
const tiger=require('../helpers/tigerbalm');
const auth=require('../middleware/auth');
const moment=require('moment');
const crypto=require('../helpers/crypto');
const teleg=require('../helpers/telegram');
function routes(fastify, options, done) {
fastify.post("/userregistration", async (req, reply) => {
    try {
     const { error } = twofactorRegistration(req.body);
      if (error) return reply.code(400).send(error.details[0].message);
      const userexists = await Queries.findOneDocument(
        { email: req.body.email},"User");
      if (userexists) return reply.code(400).send("User already exists");
      const formattedDate = moment().format("DD-MM-YYYY");
      const newusers = {
        userid: generateId(),
        username: req.body.username,
        email: req.body.email,
        password: req.body.password,
        last_login_ip:req.body.last_login_ip,
        fcm_token:req.body.fcm_token,
        referral_one:req.body.referral_one,
        balances:req.body.balances,
        date_registration: formattedDate,
        };
      const salt = await bcrypt.genSalt(10);
      newusers.password = await bcrypt.hash(newusers.password, salt);
      const users = await Queries.insertDocument("User", newusers);
      if (!users) return reply.code(400).send("Failed to register user");
      const redisusers = await redisquery.redisSETEX(newusers.email,30, JSON.stringify(users));
      console.log("redisusers",redisusers) 
     if (!redisusers) return reply.code(400).send("Failed to insert data into Redis");
     return reply.code(200).send("User Registered successfully");
    } catch (error) {
      await teleg.alert_Developers(error);
      return reply.code(400).send(`error userregistration -->${error}`);
    }
  });
  fastify.post('/getredis', async (req, reply) => {
    try {
      const email = req.body.email;
      const dataExists = await redisquery.redisexists(email);
     if (dataExists) {
      const data = await redisquery.redisget(email);
        console.log("Data from Redis:", data);
        return reply.code(200).send(data);
      } else {
       const user = await Queries.findOneDocument({ email }, "User");
       if (!user) {
          return reply.code(400).send("Email not found");
        }
        await redisquery.redisSETEX(email, 60, JSON.stringify(user));
        const cachedData = await redisquery.redisget(email);
        if (!cachedData) {
          return reply.code(400).send("Failed to retrieve cached data from Redis");
        }
        console.log("Data from MongoDB:", user);
        return reply.code(200).send(cachedData);
      }
    } catch (error) {
      console.error(error);
      return reply.code(400).send("Error retrieving data");
    }
  });

 
  fastify.post("/getusers", async (req, reply) => {
    try {
      const decrypted = crypto.decryptobj(req.body.enc);
     console.log("dec",decrypted);
      const { error } =validatelimit(decrypted);
      if (error) return reply.code(400).send(error.details[0].message);
      const limit = decrypted.limit;
      const users = await Queries.findlimit("User", limit);
      if (!users) return reply.code(400).send("No users found");
      return reply.code(200).send(crypto.encryptobj(users));
    } catch (error) {
      await teleg.alert_Developers(error);
      return reply.code(400).send(`error getusers -->${error}`);
    }
  
  });

  fastify.post("/userlogin", async (req, reply) => {
    try {
      const { error } = loginuser(req.body);
      if (error) return reply.code(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },"User");
      if (!user) {
        return reply.code(400).send("Email not found");
      } else {
        const validpassword = await bcrypt.compare(
          req.body.password,
          user.password
        );
        if (!validpassword) {
          return reply.code(400).send("Incorrect password");
        } else {
          const otp = "123456";
          const redisinsert = await redisquery.redisSETEX(user.email, 60, otp);
          if (!redisinsert) {
            return reply.code(400).send("Failed to send OTP.");
          }
          return reply.code(200).send(crypto.encryptobj({
                twoFacode: user.twoFacode,
                otp: "OTP sent successfully",
              })
            );
        }
      }
    } catch (error) {
      await teleg.alert_Developers(error);
      return reply.code(400).send(`error userlogin -->${error}`);
    }
  });
  fastify.post("/resendotp", async (req, reply) => {
    try {
      const { error } = validateemail(req.body);
      if (error) return reply.code(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },"User");
      if (!user) return reply.code(400).send("Email not found");
      const otp = "123456";
      const redisinsert = await redisquery.redisSETEX(user.email, 60, otp);
      if (!redisinsert) {
        return reply.code(400).send("Failed to send OTP.");
      }
      return reply.code(200).send(crypto.encryptobj("OTP send successfully"));
    } catch (error) {
      await teleg.alert_Developers(error);
      return reply.code(400).send(`error replyendotp -->${error}`);
    }
  });
  fastify.post("/verifyotp",async(req, reply) => {
    try {
      const { error } = loginverify(req.body);
      if (error) return reply.code(400).send(error.details[0].message);
      const user = await Queries.findOneDocument({ email:req.body.email },"User");
      if (!user) return reply.code(400).send("Email not found");
      const email = req.body.email;
      const otp = req.body.otp;
      const redisget = await redisquery.redisGET(email);
      if (!redisget) {
        return reply.code(400).send("OTP expired");
      }
      if (redisget !== otp) {
        return reply.code(400).send("Incorrect OTP");
      }
     if (user.twoFacode === "enabled") {
        const twoFaCode = req.body.twoFaCode;
        const decryptedSecret = tiger.decrypt(user.twoFaKey);
        const replyult = twofactor.verifyToken(decryptedSecret, twoFaCode);
       if (!replyult) {
          return reply.code(400).send("Invalid twoFaCode");
        } else if (replyult.delta !== 0) {
          return reply.code(400).send("TwoFacode Expired");
        }
      }
      const token = jwt.sign(
        {
          userid: user.userid,
          username:user.username,
          email: user.email,
          twofacode: user.twofacode
        },
        process.env.jwtPrivateKey,
        { expireplyIn: "90d" }
      );
      const encryptedreplyponse = crypto.encryptobj({
        token: token,
        message: "Login successfully",
      });
      return reply.code(200).send(encryptedreplyponse);
    } catch (error) {
      await teleg.alert_Developers(error);
      console.log(error);
      return reply.code(400).send(`Error loginverify --> ${error}`);
    }
  });
  fastify.post("/twofaenable", {preHandler: auth}, async (req, reply) => {
    try {
      const { error } = validateemail(req.body);
      if (error) return reply.code(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },
        "User");
      if (!user) {
        return reply.code(400).send("Email not found");
      }
      const { secret, qr } = twofactor.generateSecret({
        name: "Rails",
        account: user.userid,
      });
      const encryptedSecret = tiger.encrypt(secret);
      const updated = await Queries.findOneAndUpdate(
        { email: req.body.email },
        { twoFaKey: encryptedSecret },
        "User",
        { new: true }
      );
      if (!updated) {
        return reply.code(400).send("Failed to update document");
      }
      return reply.code(200).send(crypto.encryptobj({ secret: secret, qr }));
    } catch (error) {
      await teleg.alert_Developers(error);
      console.log(error);
      return reply.code(400).send(`Error twofaenable: ${error}`);
    }
  }); 
  fastify.post("/verifyenable", {preHandler: auth}, async (req, reply) => {
    try {
      const { error } = verifytwofa(req.body);
      if (error) return reply.code(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.user.email },
        "User"
      );
      if (!user) {
        return reply.code(400).send("Email not found");
      }
      const twoFaCode = req.body.twoFaCode;
      const decryptedSecret = tiger.decrypt(user.twoFaKey);
      const replyult = twofactor.verifyToken(decryptedSecret, twoFaCode);
     if (replyult && replyult.delta === 0) {
        const updated = await Queries.findOneAndUpdate(
          { email: req.user.email },
          { twoFacode: "enabled" },
          "User",
          { new: true }
        );
        if (!updated) {
          return reply.code(400).send("Failed to update document");
        }
        return reply
          .code(200)
          .send(
            crypto.encryptobj({ twofacode: "twoFACode verified successfully" })
          );
      } else if (replyult && replyult.delta !== 0) {
        return reply.code(400).send("Twofacode has expired");
      } else {
        return reply.code(400).send("Invalid Twofacode");
      }
    } catch (error) {
      await teleg.alert_Developers(error);
      return reply.code(400).send(`error verifyenable -->${error}`);
    }
  });
  fastify.post("/twofadisable", {preHandler: auth}, async (req, reply) => {
    try {
      const { error } = validateemail(req.body);
      if (error) return reply.code(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.body.email },"User");
      if (!user) {
        return reply.code(400).send("Email not found");
      } else {
        const { secret, qr } = twofactor.generateSecret({
          name: "Rails",
          account: user.userid,
        });
        tiger.encrypt(secret);
        return reply.code(200).send(crypto.encryptobj({ secret: secret, qr }));
      }
    } catch (error) {
      await teleg.alert_Developers(error);
      console.log(error);
      return reply.code(400).send(`Error 2fadisable: ${error}`);
    }
  });
  
  fastify.post("/verifydisable",{preHandler: auth},async (req, reply) => {
    try {
      const { error } = verifytwofa(req.body);
      if (error) return reply.code(400).send(error.details[0].message);
      const user = await Queries.findOneDocument(
        { email: req.user.email },
        "User"
      );
      if (!user) {
        return reply.code(400).send("Email not found");
      }
      const twoFaCode = req.body.twoFaCode;
      const decryptedSecret = tiger.decrypt(user.twoFaKey);
      const replyult = twofactor.verifyToken(decryptedSecret, twoFaCode);
      if (replyult && replyult.delta === 0) {
        const updated = await Queries.findOneAndUpdate(
          { email: req.user.email },
          { twoFacode: "disabled" },
          "User",
          { new: true });
        if (!updated) {
          return reply.code(400).send("Failed to update document");
        }
        return reply.code(200).send(
            crypto.encryptobj({ twofacode: "TwoFaCode verified successfully" })
          );
      } else if (replyult && replyult.delta !== 0) {
        return reply.code(400).send("Twofacode has expired");
      } else {
        return reply.code(400).send("Invalid twofacode");
      }
    } catch (error) {
      await teleg.alert_Developers(error);
      return reply.code(400).send(`error verifydisable -->${error}`);
    }
  });
  done();
}


  




module.exports = routes;   
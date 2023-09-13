
const Queries = require("../helpers/mongofunctions");
const redisquery = require("../helpers/redis");
const { generateId } = require("../middleware/userid");

const {
  adminValidation,
  loginadmin,
  validateemail,
  loginverify,
  verifytwofa,
  validateNewAdmin,
  validateresetpassword,
  validateadmintype,
  validateadminid,
  validateenc,
} = require("../helpers/validations");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");
const twofactor = require("node-2fa");
const tiger = require("../helpers/tigerbalm");
const crypto = require("../helpers/crypto");
const teleg = require("../helpers/telegram");
const amw=require('../helpers/async');



function routes(fastify, options, done) {
    fastify.post('/adminregistration', async (req, reply) => {
      try {
        
        //const requestBody = req.body || {}; 
        let data = !req.body ? {} : req.body;
        const { error } = adminValidation(data);
        if (error) {
          return reply.code(400).send(error.details[0].message);
        }

        if (error) {
          return reply.code(400).send(error.details[0].message);
        }
        const emailExists = await Queries.findOneDocument(
          { email: req.body.email },
          "Admin");
          
        if (emailExists) {
          return reply.code(400).send("Email already exists");
        } else {
          const newAdmin = {
            adminId: generateId(),
            name: req.body.name,
            email: req.body.email,
            password: req.body.password,
            admintype: req.body.admintype,
          };
          const salt = await bcrypt.genSalt(10);
          newAdmin.password = await bcrypt.hash(newAdmin.password, salt);
          const inserted = await Queries.insertDocument("Admin", newAdmin);
          await teleg.alert_Developers(
            "Registration successful: " + newAdmin.name + " registered.");
          if (inserted) {
            return reply.code(200).send("SuperAdmin registered successfully");
          } else {
            return reply.code(400).send("Failed to register Admin");
          }
        }
      } catch (error) {
        console.error(error);
        return reply.code(400).send(`Error in adminregistration --> ${error}`);
      }
    });
   
    
  fastify.post("/adminlogin", async (req, reply) => {
  try {
    const { error } =  validateenc(req.body);
    if (error) {
      return reply.code(400).send(error.details[0].message);
    } else {
      const decrypted = crypto.decryptobj(req.body.enc);
      const { error } = loginadmin(decrypted);
      if (error) {
        return reply.code(400).send(error.details[0].message);
      }
      const admin = await Queries.findOneDocument(
        { email: req.body.email },
        "Admin"
      );

      if (!admin) {
        return reply.code(400).send("Email not found");
      }

      const validpassword = await bcrypt.compare(
        req.body.password,
        admin.password
      );

      if (!validpassword) {
        return reply.code(400).send("Incorrect password");
      }
      const otp = "123456";
      const redisinsert = await redisquery.redisSETEX(`login_otp_${admin.email}`,60,otp);
      if (!redisinsert) {
        return reply.code(400).send("Failed to send OTP.");
      }
      return reply.code(200).send(
        ({
          twoFaStatus: admin.twoFaStatus,
          otp: "OTP sent successfully",
        })
      );
    }
    
  } catch (error) {
    await teleg.alert_Developers(error);
    return reply.code(400).send(`Error in adminlogin --> ${error}`);
  }
});
fastify.post("/resendotp", async(req, reply) => {
  try {
    // const req.body = crypto.decryptobj(req.body.enc);
    const { error } = validateemail(req.body);
    if (error) return reply.code(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: req.body.email },
      "Admin");
    if (!admin) return reply.code(400).send("email not found");
    const otp = "123456";
    const redisinsert = await redisquery.redisSETEX(`login_otp_${admin.email}`, 60, otp);
    if (!redisinsert) {
      return reply.code(400).send("Failed to send OTP.");
    }
    return reply.code(200).send(("OTP send successfully"));
  } catch (error) {
    await teleg.alert_Developers(error);
    return reply.code(400).send(`error replyendotp -->${error}`);
  }
});
fastify.post("/verifylogin", async (req, reply) => {
  try {
     //const req.body = crypto.decryptobj(req.body.enc);
    const { error } = loginverify(req.body);
    if (error) return reply.code(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument({ email: req.body.email },"Admin");
    if (!admin) return reply.code(400).send("Email not found");
    const email = req.body.email;
    const otp = req.body.otp;
    const redisget = await redisquery.redisGET(`login_otp_${email}`);
    if (!redisget) {
      return reply.code(400).send("OTP expired");
    }
    if (redisget !== otp) {
      return reply.code(400).send("Incorrect OTP");
    }
   
    if (admin.twoFaStatus === "enabled") {
      const twoFaCode = req.body.twoFaCode;
      const decryptScretSecret = tiger.decrypt(admin.twoFaKey);
      const replyult = twofactor.verifyToken(decryptScretSecret, twoFaCode);

      if (!replyult) {
        return reply.code(400).send("Invalid twoFaCode");
      } else if (replyult.delta !== 0) {
        return reply.code(400).send("twoFacode Expired");
      }
    }
    const token = jwt.sign(
      {
        adminId: admin.adminId,
        name:admin.name,
        email: admin.email,
        twoFaStatus: admin.twoFaStatus,
        admintype: admin.admintype,
      },
      process.env.jwtPrivateKey,
      { expiresIn: "90d" }
    );
    const response = ({
      token: token,
      message: "Login successfully",
    });
    return reply.code(200).send(response);
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return reply.code(400).send(`Error loginverify --> ${error}`);
  }
});
fastify.post("/2faenable",{preHandler: auth},async (req, reply) => {
  try {
    console.log(req.user);
  //  const req.body = crypto.decryptobj(req.body.enc);
    const { error } = validateemail(req.body);
    if (error) return reply.code(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: req.body.email },"Admin");
    if (!admin) {
      return reply.code(400).send("email not found");
    }
    const {secret, qr} = twofactor.generateSecret({
      name: "Rails",
      account: admin.adminId,
    });
    const encryptedSecret = tiger.encrypt(secret);
    const updated = await Queries.findOneAndUpdate(
      { email:req.body.email},
      { twoFaKey:encryptedSecret},
      "Admin",
      {new:true});
    if (!updated) {
      return reply.code(400).send("Failed to update document");
    }
    return reply.code(200).send(({ secret: secret,qr}));
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return reply.code(400).send(`Error 2faenable: ${error}`);
  }
});
fastify.post("/verify2faenable",{preHandler: auth},async (req, reply) => {
  try {
    // const req.body = crypto.decryptobj(req.body.enc);
    // const { error } = verifytwofa(req.body);
    if (error) return reply.code(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      {email: req.user.email},"Admin");
    if (!admin) {
      return reply.code(400).send("email not found");
    }
    const twoFaCode = req.body.twoFaCode;
    const decryptScret = tiger.decrypt(admin.twoFaKey);
    const replyult = twofactor.verifyToken(decryptScret, twoFaCode);
   if (reply && reply.delta === 0) {
      const updated = await Queries.findOneAndUpdate(
        { email: req.user.email },
        { twoFaStatus: "enabled" },
        "Admin",
        { new: true }); 
      if (!updated) {
        return reply.code(400).send("Failed to update document");
      }
      return reply
        .status(200)
        .send(
          crypto.encryptobj({ twofacode: "twoFACode verified successfully" }));
    } else if (replyult && replyult.delta !== 0) {
      return reply.code(400).send("Twofacode has expired");
    } else {
      return reply.code(400).send("Invalid Twofacode");
    }
  } catch (error) {
    console.log(error);
    return reply.code(400).send(`Error verify2faenable: ${error.message}`);
  }
});
fastify.post("/2fadisable", {preHandler: auth},async (req, reply) => {
  try {
    // const req.body = crypto.decryptobj(req.body.enc);
     const { error } = validateemail(req.body);
    if (error) return reply.code(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: req.body.email },
      "Admin");
    if (!admin) { 
      return reply.code(400).send("email not found");
    } else {
      const { secret, qr } = twofactor.generateSecret({
        name: "Rails",
        account: admin.adminId});
      tiger.encrypt(secret);
      return reply.code(200).send(crypto.encryptobj({ secret: secret, qr }));
    }
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return reply.code(400).send(`Error 2fadisable: ${error}`);
  }
});

fastify.post("/verify2fadisable",{preHandler: auth},async (req, reply) => {
  try {
    // const req.body = crypto.decryptobj(req.body.enc);
     const { error } = verifytwofa(req.body);
    if (error) return reply.code(400).send(error.details[0].message);
    const admin = await Queries.findOneDocument(
      { email: req.user.email },"Admin");
    if (!admin) {
      return reply.code(400).send("email not found");
    }
    const twoFaCode = req.body.twoFaCode;
    const decryptScret = tiger.decrypt(admin.twoFaKey);
    const replyult = twofactor.verifyToken(decryptScret, twoFaCode);
    if (replyult && replyult.delta === 0){
      const updated = await Queries.findOneAndUpdate(
        { email: req.user.email },
        { twoFaStatus: "disabled" },
        "Admin",
        { new: true });
      if (!updated) {
        return reply.code(400).send("Failed to update document");
      }
      return reply.code(200).send(
      crypto.encryptobj({ twofacode: "twoFaCode verified successfully" }));
    } else if (replyult && replyult.delta !== 0) {
      return reply.code(400).send("Twofacode has expired");
    } else {
      return reply.code(400).send("Invalid twofacode");
    }
  } catch (error) {
    console.log(error);
    return reply.code(400).send(`Error verify2fadisable: ${error.message}`);
  }
});
fastify.post("/addAdmin", {preHandler: auth},async (req, reply) => {
  try {
    // const req.body = crypto.decryptobj(req.body.enc);
     const { error } = validateNewAdmin(req.body);
    if (error) {
      return reply.code(400).send(error.details[0].message);
    }
    if (req.user.admintype !== "1") {
      return reply.code(400).send("Not an admin");
    }

    const emailExists = await Queries.findOneDocument(
      { email: req.body.email },
      "Admin"
    );
    if (emailExists) {
      return reply.code(400).send("Email already exists");
    }
    const newAdmin = {
      adminId: generateId(),
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      admintype: req.body.admintype,
    };
    const salt = await bcrypt.genSalt(10);
    newAdmin.password = await bcrypt.hash(newAdmin.password, salt);
    const insertedAdmin = await Queries.insertDocument("Admin", newAdmin);
    if (!insertedAdmin) {
      return reply.code(400).send("Failed to register Admin");
    }
    await teleg.alert_Developers(
      "Reistration successfully: " +
        newAdmin.name +
        " registered: " );
    return reply.code(200).send(crypto.encryptobj("Admin added successfully"));
  } catch (err) {
    await teleg.alert_Developers(err);
    return reply.code(400).send(`error Registration -->${err}`);
  }
});

fastify.post("/changepassword", {preHandler: auth},async (req, reply) => {
  try {
    // const req.body = crypto.decryptobj(req.body.enc);
   if (req.user.admintype !== "1") {
      return reply.code(400).send("Invalid admintype");
    }
    const { adminId, newPassword } = req.body;
    const { error } = validateresetpassword(req.body);
    if (error) {
      return reply.code(400).send(error.details[0].message);
    }
    const admin = await Queries.findOneDocument({ adminId }, "Admin");
    if (!admin) {
      return reply.code(400).send("Admin not found");
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    const updatedAdmin = await Queries.findOneAndUpdate(
      { adminId: req.body.adminId },
      { password: hashedPassword },
      "Admin",
      { new: true });
    if (!updatedAdmin) {
      return reply.code(400).send("Failed to update password");
    }
   return reply.code(200).send(crypto.encryptobj("Password changed successfully"));
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return reply.code(400).send(`Error in changepassword --> ${error}`);
  }
});

fastify.post("/getAdmins",  {preHandler: auth},async (req, reply) => {
  try {
    if (req.user.admintype !== "1") {
      return reply.code(400).send("Invalid admintype");
    }
   const admins = await Queries.findfilter("Admin", {admintype: { $ne: "1" }}, { _id: 0, __v: 0 });
    if (!admins) {
      return reply.code(400).send("No admin found");
    }
    return reply.code(200).send(crypto.encryptobj(admins));
  } catch (error) {
    await teleg.alert_Developers(error);
    console.log(error);
    return reply.code(400).send(`Error in getadmins --> ${error}`);
  }
});
fastify.post("/changeAdminType",{preHandler: auth},async (req, reply) => {
  try {
    // const req.body =crypto.decryptobj(req.body.enc);
   if (req.user.admintype !== "1") {
      return reply.code(400).send("Not an Admin");
    }
    const { error } = validateadmintype(req.body);
    if (error) {
      return reply.code(400).send(error.details[0].message);
    }
    const { adminId, admintype } = req.body;
    const updatedAdmin = await Queries.findOneAndUpdate(
      { adminId: adminId },
      { $set: { admintype: admintype}},
      "Admin",
      { new: true });
   if (!updatedAdmin) {
      return reply.code(400).send("Failed to update admin");
    }
    return reply.code(200).send(crypto.encryptobj("Admin type updated successfully"));
  } catch (err) {
    await teleg.alert_Developers(err);
    return reply.code(400).send(`Error change admintype --> ${err}`);
  }
});
fastify.post("/deleteadmin",{preHandler: auth},async (req, reply) => {
  try {
  //  const req.body = crypto.decryptobj(req.body.enc);
   if (req.user.admintype !== "1") {
      return reply.code(400).send("Invalid admintyp");
    }
    const {error} =  validateadminid(req.body);
    if (error) return reply.code(400).send(error.details[0].message);
     const user = await Queries.findOneDocument({ adminId:req.body.adminId },"Admin");
    if (!user) return reply.code(400).send("No User Found");
    const deleted=await Queries.findOneAndDelete({ adminId:req.body.adminId },"Admin");
    if(!deleted) return reply.code(400).send("failed to delete admin");
    return reply.send(crypto.encryptobj({ success: "Admin Deleted Successfully" }));
  } catch (err) {
    await teleg.alert_Developers(err);
    return reply.code(400).send(`Error delete admintype --> ${err}`);
  }

});
done();
}



module.exports = routes;

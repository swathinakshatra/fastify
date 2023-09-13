const mongoose = require("mongoose");
const registrationSchema =new mongoose.Schema({
        userid: { type: String, required: true },
        username: { type: String, unique: true, required: true },
        email: { type: String, unique: true, required: true },
        password: { type: String, required: true },
        date_registration: { type: String, required: true },
        kyc_status: { type: String,required:true, enum: ['accepted', 'rejected'], default: 'rejected' },
        kyc_details: {
          kyc_image: [{ type: String }], 
          kyc_pdf: [{ type: String }]
        },
        user_status: { type: String,required:true,enum: ['Active', 'InActive'], default: 'Active'  },
        withdraw_status: { type: String,required:true, enum: ['disabled', 'enabled'], default: 'disabled'  },
        last_login_ip: { type: String, required: true},
        fcm_token: { type: String, required: true, default: '0'},
        balances: { type: Array, default: [] },
        referral_one: { type: String,required:true},
        twofakey:{type:String,default:'0'},
        twofastatus: { type: String,required:true,enum: ['disabled', 'enabled'], default: 'disabled' },
      });
const User = mongoose.model("User",registrationSchema);
exports.User = User;

const mongoose = require('mongoose');

const adminControlsSchema = new mongoose.Schema({
  Register: { type: String, required: true, default: "Enable" },
  login: { type: String, required: true, default: "Enable" },
  Transfer: { type: String, required: true, default: "Enable" },
  referral_one: {
    status: { type: String, required: true, default: 'Enable' },
    level: { type: String, required: true},
    percentage: { type: Number, required: true, default: 10 } 
  },
 
  coins: { type: Array, default: [] }
});

const AdminControls = mongoose.model('AdminControls', adminControlsSchema);
exports.AdminControls = AdminControls;
    
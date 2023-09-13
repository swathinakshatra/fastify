const mongoose = require('mongoose');

const AdminSchema = new mongoose.Schema({
  name:{ type: String, required: true,minlength:5,maxlength: 50 },
  adminId: { type: String, required: true },
  email: { type: String, required: true, unique: true,minlength:5,maxlength:250,},
  password: { type: String, required: true,minlength:8,maxlength:1024 },
  date: { type: Date, required: true, default: Date.now },
  admintype: { type: String, required: true },
  twoFaKey: { type: String, default: '0' },
  twoFaStatus: {type: String,required: true,enum: ['disabled', 'enabled'],default: 'disabled'},
}); 

const Admin = mongoose.model('Admin', AdminSchema);
exports.Admin=Admin;
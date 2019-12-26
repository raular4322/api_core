const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const {Schema} = mongoose;


const adminSchema = new Schema({
  nickname: {type: String, required: false, unique: true, default: 'test'},
  mail: {type: String, required: true, unique: true, default: 'test@test.test'},
  password: {type: String, required: true, unique: false, default: '12345678'},
  active: {type: Boolean},
});

adminSchema.pre('save', function(next) {
  const admin = this;
  if (!admin.isModified('password')) return next();
  bcrypt.genSalt((err, salt) => {
    if (err) return next(err);
    bcrypt.hash(admin.password, salt, (err, hash) => {
      if (err) return next(err);
      admin.password = hash;
      admin.active = true;
      next();
    });
  });
});

adminSchema.methods.comparePassword = function(candidatePassword, result) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    result(err, isMatch);
  });
};

module.exports = mongoose.model('Admin', adminSchema);

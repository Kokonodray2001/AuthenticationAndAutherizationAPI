const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const schema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true, // convert to lower case
    validate: [validator.isEmail, "please provide an valid email"], //predefined validation function validator.isEmai
  },
  photo: {
    type: String,
    default: "0",
  },
  password: {
    type: String,
    required: true,
    minlenght: 8,
    select: false, // this will not be displayed in any output
  },

  passwordConfirm: {
    type: String,
    required: true,
    validate: {
      validator: function (el) {
        return el === this.password; // this will only work on save not on findOneandUpdate
      },
      message: "password don't match",
    },
  },
  passwordChangedAt: Date,
  role: {
    type: String,
    enum: ["type1User", "type2User", "admin"],
    default: "type1User",
  },
  passwordResetToken: String,
  passwordResetExpires: Date,
});

//mongoose middleware
schema.pre("save", async function (next) {
  //pre save runs between getting the data and then saving it in the database
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12); //12 -> lenght of salt // hash is async version
  this.passwordConfirm = undefined; //as it is already used before to confirm so we can delet it now
  next();
});

//instance methods -> will be avaliable on all instance of user Model
schema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  //we are using userpassword as an parameter because this.password is not avaliable as it is made as select : false
  return await bcrypt.compare(candidatePassword, userPassword);
};
schema.methods.changedPassword = async function (JWTTimestap) {
  if (this.passwordChangedAt) {
    const changedTimeStamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    console.log(typeof changeedTimeStamp, " ", typeof JWTTimestap);
    return changedTimeStamp > JWTTimestap;
  }
  //false means not changed
  return false;
};

schema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  console.log(
    resetToken,
    " ",
    this.passwordResetToken,
    " ",
    this.passwordResetExpires
  );
  return resetToken;
};
const User = mongoose.model("testUser", schema);
module.exports = User;

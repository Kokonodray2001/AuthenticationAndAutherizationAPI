require("dotenv").config();
const { config } = require("dotenv");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const AppError = require("../utils/appError");
const { promisify } = require("util");

//const connect =  require('../utils/dbConnection');
const mongoose = require("mongoose");
const { decode } = require("punycode");
mongoose
  .connect(
    process.env.MONGO_URL,
    { useNewUrlParser: true },
    mongoose.set("strictQuery", true)
  )
  .then(() => console.log("connected mongo"))
  .catch((err) => console.log(err));

const singToken = (id) => {
  return jwt.sign({ id: id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};
exports.signup = async (req, res, next) => {
  try {
    const { name, email, password, passwordConfirm } = req.body; //passwordChangedAt
    // const newUser = new User({
    //     name : name,
    //     email :  email,
    //     password : password,
    //     passwordConfirm : passwordConfirm
    // })
    //newUser.save();

    //const result =  await User.create(req.body);// will not use this to proctect anyone to register as admin or add an value to an undesired field
    const newUser = await User.create({
      name: name,
      email: email,
      password: password,
      passwordConfirm: passwordConfirm,
      //passwordChangedAt : passwordChangedAt
    });

    const token = singToken(newUser._id);
    res.status(200).json({
      JWToken: token,
      status: "success",
      data: {
        user: newUser,
      },
    });
  } catch (error) {
    next(error);
  }
};

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    //1) check emial and passeord exists;
    if (!email || !password) {
      throw new AppError("please provide email and password!", 400);
    }
    //2) check user exists
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      throw new AppError("password or email is not correct", 401);
    }
    const correct = await user.correctPassword(password, user.password); // user is an inctsnce of User model
    if (!correct) {
      throw new AppError("password or email is not correct", 401);
    }

    // 3)if all ok, send JWT back to client
    const token = singToken(user._id);

    res.send({
      status: "success",
      token: token,
    });
  } catch (error) {
    next(error);
  }
};

exports.protectRoutes = async (req, res, next) => {
  //Authorize user before alloewing access to protected routes
  try {
    let token;

    //1)getting token and check if it's there -> the jwt token is formated as Authorization : Bearer JwtToken this signifies the scheme followed in authorization
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1]; // token is decleared out  as in new ES6 version it is an local var inside the if block
    } else {
      throw new AppError("user not logged in ", 401);
    }

    //2)verification of token
    const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    //    example   decode = { id: '64a997a13b53a6a2a4ea7695', iat: 1689003415, exp: 1689435415 }
    //3)check if user still exists
    const currentUser = await User.findById(decode.id);
    if (!currentUser) {
      throw new AppError(
        "the user belonging to the token no longet exists",
        401
      );
    }
    //4)checking if the password is changed
    // if (currentUser.changedPassword(decode.iat)) {
    //   throw new AppError(
    //     "User recently changed the password please login again",
    //     401
    //   );
    // }
    //5) grant access to proceted route
    req.user = currentUser; //  putting the currentuser data to future use if needed
    next();
    //res.send(req.user);
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      next(new AppError("invalid JWT token", 401));
    } else if (error.name === "TokenExpiredError") {
      next(new AppError("Your session has expired", 401));
    } else next(error);
  }
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError("You dont have permission to perform this action", 403)
      );
    }
    next();
  };
};

exports.deleteUser = (req, res, next) => {
  res.send("Deleted");
};

exports.resetPassword = (req, res, next) => {};

exports.forgotPassword = async (req, res, next) => {
  try {
    //1) get user from db on basis of posted email
    const user = await User.findOne({ email: req.body.email });
    if (!user) throw new AppError("Invalid email address", 404);
    //2) generate random email token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false }); //validateBeforeSave : false} is required because to skip all the required:true and validators
    //3) send it to user's email
    res.send(resetToken);
  } catch (error) {
    next(error);
  }
};

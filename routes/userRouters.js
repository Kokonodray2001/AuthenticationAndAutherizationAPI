const express = require("express");
const authController = require("../controllers/authControllers");

const router = express.Router();

router.post("/signUp", authController.signup);
router.post("/logIn", authController.login);
router.get("/protect", authController.protectRoutes, authController.deleteUser);
router.post("/forgotPassword", authController.forgotPassword);
router.post("/resetPassword", authController.resetPassword);

router.delete(
  "/delete",
  authController.protectRoutes,
  authController.restrictTo("admin", "type2-User"),
  authController.deleteUser
); // to protect  certein routes for specific role
module.exports = router;

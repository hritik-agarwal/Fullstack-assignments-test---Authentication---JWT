// Validation
const Joi = require("joi");

// Register validation
const registerValidation = (data) => {
  const userSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
  })
  return userSchema.validate(data);
};

// Login validation
const loginValidation = (data) => {
  const userSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  })
  return userSchema.validate(data);
};

module.exports.registerValidation = registerValidation;
module.exports.loginValidation = loginValidation;

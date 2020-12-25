const router = require('express').Router();
const User = require('../models/User');
const RefreshToken =require('../models/RefreshToken');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { verifyAuthToken, verifyRefreshToken } = require('./verifyToken');
const {registerValidation, loginValidation} = require('./validation');

// Your code goes here


//Register
router.post('/register', async (req, res) =>{

    // 1. check if user data is correctly written i.e. validation of data
    // 2. check if user is already registered
    // 3. hash the password
    // 4. create new user and add it to database

    // Step 1
    const {error} = registerValidation(req.body);
    if(error) return res.status(400).json({message: error.details[0].message});
    // Step 2
    const userExist = await User.findOne({email: req.body.email});
    if(userExist) return res.status(400).send("Email already exists.");
    // Step 3
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(req.body.password, salt);
    // Step 4
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword,
    });
    try{
        const savedUser = await user.save();
        res.json({user: savedUser._id});
    } catch(err){
        res.status(400).json({message: error.message})
    }
})

// Login
router.post('/login',async (req, res) =>{

    // 1. check if user data is correctly written i.e. validation of data
    // 2. check if such user exist in our database
    // 3. compare the password with that stored in database
    // 4. create auth token and refresh token 
    // 5. add refresh token to database
    // 6. return auth token & refresh token

    // Step 1
    const {error} = loginValidation(req.body);
    if(error) return res.status(400).json({message: error.details[0].message});
    // Step 2
    const userExist = await User.findOne({email: req.body.email});
    if(!userExist) return res.status(400).json({message: 'Email not found'})
    // Step 3
    const validPassword = await bcrypt.compare(req.body.password, userExist.password);
    if(!validPassword) return res.status(400).json({message: "password is wrong"})
    // Step 4
    const authToken = jwt.sign({user_id : userExist._id}, process.env.TOKEN_SECRET, {expiresIn: '24h'});
    const refToken = new RefreshToken({
        token: jwt.sign({user_id : userExist._id}, process.env.REFRESH_TOKEN_SECRET)
    });
    // Step 5
    try{
        const refreshToken = await refToken.save();
        res.header({'auth-token': authToken, 'refresh-token': refreshToken.token}).json({'auth-token': authToken, 'refresh-token': refreshToken.token, 'refresh-token-id': refreshToken._id});
    } catch(error){
        res.status(500).json({message: error.message})
    }
})  

// get user details
router.get('/me', verifyAuthToken, async (req, res) => {

    // 1. verification of auth token will be done in middleware
    // 2. check if such user exist in our database
    // 3. return the user data

    // Step 2
    const userExist = await User.findOne({_id: req.user.user_id});
    if(!userExist) return res.status(429).json({message: 'Access Denied'});
    // Step 3
    res.json({name: userExist.name, email: userExist.email});
})

// generate New Auth-Token
router.get('/newAuthToken', verifyRefreshToken, async (req, res) =>{

    // 1. verification of refresh token will be done in middleware
    // 2. create a new auth token
    // 3. return auth token & refresh token

    const refreshToken = req.header('refresh-token');
    // Step 2
    const authToken = jwt.sign({user_id : req.user.user_id}, process.env.TOKEN_SECRET, {expiresIn: '24h'});
    // Step 3
    res.header({'auth-token': authToken, 'refresh-token': refreshToken}).json({'auth-token': authToken, 'refresh-token': refreshToken});
})

// logout
router.delete('/logout', verifyRefreshToken, async (req, res) =>{

    // 1. verification of refresh token will be done in middleware
    // 2. delete the refresh token from database
    // 3. remove the auth token & refresh token from header
    // 4. return the user "that he is successfully logged out"

    const refreshToken = req.header('refresh-token');

    try{
        // Step 2
        const tokenDeleted = await RefreshToken.deleteOne({token: refreshToken});
        // Step 3
        res.removeHeader('auth-token'); res.removeHeader('refresh-token');
        // Step 4
        res.json({token_id: refreshToken, message: 'Successfully logged out'});
    }catch(error){
        res.status(500).json({message: error.message});
    }
})


module.exports = router;
const jwt = require('jsonwebtoken');
const RefreshToken = require('../models/RefreshToken');

function verifyAuthToken (req, res, next) {

    // check if request header contains auth-token
    // verify the token & store the payload information in req.user to use it later to fetch details from database

    // Step 1
    const authToken = req.header('auth-token');
    if(!authToken) res.status(401).json({message: 'Access denied'});

    // Step 2
    try{
      const payload = jwt.verify(authToken, process.env.TOKEN_SECRET);
      req.user = payload;
      next();
    } catch (error){
      return res.status(400).json({message: error.message});
    }
}   

async function verifyRefreshToken (req, res, next) {

    // check if request header contains refresh-token 
    // check if it is in database also
    // verify the token & store the payload information in req.user to use it later in creating new auth token

    // Step 1
    const refreshToken = req.header('refresh-token');
    if(!refreshToken) res.status(401).json({message: 'Access denied'});

    const tokenExist = await RefreshToken.findOne({token: refreshToken});
    if(!tokenExist) res.status(401).json({message: 'Access denied'});

    // Step 2
    try{
        const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        req.user = payload;
        next();
    } catch (error){
        return res.status(400).json({message: error.message});
    }
}

module.exports.verifyAuthToken = verifyAuthToken;
module.exports.verifyRefreshToken = verifyRefreshToken;
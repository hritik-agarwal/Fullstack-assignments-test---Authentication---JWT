const mongooose = require('mongoose');

const tokenSchema = new mongooose.Schema({
    token: String,
})

const RefreshToken = mongooose.model('tokens', tokenSchema);

module.exports = RefreshToken;
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, unique: true, sparse: true }, // Optional and unique
    password: { type: String, required: true },
    profilePic: String,
});

module.exports = mongoose.model('User', userSchema);
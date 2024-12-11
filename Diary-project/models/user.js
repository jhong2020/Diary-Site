// models/user.js

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    profilePic: String, // 프로필 사진 경로를 저장하는 필드 추가
    diary: { type: mongoose.Schema.Types.ObjectId, ref: 'Diary' } // 일기장과 사용자를 연결하는 필드
});

module.exports = mongoose.model('User', userSchema);

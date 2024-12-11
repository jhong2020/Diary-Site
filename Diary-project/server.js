const express = require('express');
const app = express();
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt') // 패스워드 암호화
const jwt = require('jsonwebtoken'); // 토큰 생성
const User = require('./models/user');
require('dotenv').config();
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(bodyParser.json()); 
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://admin:73531959@cluster0.ultg1uw.mongodb.net/test')

// mongoose.connect('mongodb+srv://admin:73531959@cluster0.ultg1uw.mongodb.net/test', { 
//     useNewUrlParser: true, 
//     useUnifiedTopology: true 
// });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// 세션 관리를 위한 패키지 및 설정
const session = require('express-session');
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

// 사용자가 로그인되어 있는지 확인하는 미들웨어
function checkLoggedIn(req, res, next) {
    if (req.session.loggedIn) {
        next();
    } else {
        res.redirect('/login');
    }
}


const diarySchema = new mongoose.Schema({
    title: String,
    content: String,
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }
});


const Diary = mongoose.model('Diary', diarySchema);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

function generateAuthToken(user) {
    return jwt.sign({ _id: user._id, username: user.username, password: user.password }, process.env.JWT_SECRET);
    
}


function isAuthenticated(req, res, next) {
    const token = req.cookies.auth_token;

    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                // 인증 실패 시 로그인 페이지로 리다이렉트
                return res.redirect('/login');
            } else {
                // 인증 성공 시 다음 미들웨어로 진행
                req.user = decoded; // 디코딩된 사용자 정보를 요청 객체에 저장
                next();
            }
        });
    } else {
        // 토큰이 없는 경우 로그인 페이지로 리다이렉트
        res.redirect('/login');
    }
}

app.get('/', (req, res) => {
    res.render('main', { loggedIn: req.cookies.auth_token ? true : false });
    
});


app.get('/diary', isAuthenticated, async (req, res) => {
    try {
        const foundDiaries = await Diary.find({ userId: req.user._id });
        res.render('diary', { diaries: foundDiaries });
    } catch (err) {
        console.log(err);
        res.status(500).send("일기를 불러오는 동안 오류가 발생했습니다.");
    }
});


app.get('/list', isAuthenticated, async (req, res) => {
    try {
        const diaries = await Diary.find().populate('author');
        res.render('list', { diaries });
    } catch (err) {
        console.error(err);
        res.status(500).send('서버 오류');
    }
});



app.get('/diary/:id', async (req, res) => {
    try {
        const diary = await Diary.findById(req.params.id);
        if (!diary) {
            return res.status(404).send("일기를 찾을 수 없습니다.");
        }
        res.render('diaryDetail', { diary: diary });
    } catch (err) {
        console.log(err);
        res.status(500).send("일기를 불러오는 동안 오류가 발생했습니다.");
    }
});


// 검색 결과 페이지 라우트
app.get('/search',  async (req, res) => {
    const keyword = req.query.keyword;

    try {
        const foundDiaries = await Diary.find({ $or: [{ title: { $regex: keyword, $options: 'i' } }, { content: { $regex: keyword, $options: 'i' } }] });
        res.render('search', { keyword: keyword, diaries: foundDiaries }); // diaries 변수를 함께 전달
    } catch (err) {
        console.log(err);
        res.status(500).send("검색하는 동안 오류가 발생했습니다.");
    }
});



// 수정 페이지 라우트
app.get('/edit/:id', async (req, res) => {
    try {
        const diary = await Diary.findById(req.params.id);
        res.render('edit', { diary: diary });
    } catch (err) {
        console.log(err);
        res.status(500).send("일기를 불러오는 동안 오류가 발생했습니다.");
    }
});

// 수정 처리 라우트
app.post('/edit/:id', async (req, res) => {
    try {
        const { title, content } = req.body;
        await Diary.findByIdAndUpdate(req.params.id, { title: title, content: content });
        res.redirect('/diary');
    } catch (err) {
        console.log(err);
        res.status(500).send("일기를 수정하는 동안 오류가 발생했습니다.");
    }
});

// 삭제 처리 라우트
app.get('/delete/:id',  async (req, res) => {
    try {
        await Diary.findOneAndDelete({ _id: req.params.id });
        res.redirect('/list');
    } catch (err) {
        console.log(err);
        res.status(500).send("일기를 삭제하는 동안 오류가 발생했습니다.");
    }
});

app.get('/write', isAuthenticated, (req, res) => {
    res.render('write');
});

app.post('/write', isAuthenticated, async (req, res) => {
    const { title, content } = req.body;

    const newDiary = new Diary({
        userId: req.user._id,
        title: title,
        content: content
    });

    try {
        await newDiary.save();
        res.redirect('/list');
    } catch (err) {
        console.log(err);
        res.status(500).send("일기를 저장하는 동안 오류가 발생했습니다.");
    }
});

app.get('/register',  (req, res) => {
    res.render('register.ejs')
})

app.post('/register', async (req, res) => {
    try {
        // 사용자 이름이 이미 존재하는지 확인
        const existingUser = await User.findOne({ username: req.body.username });
        if (existingUser) {
            return res.status(400).send('이미 사용 중인 사용자 이름입니다.');
        }

        // 사용자 이름이 중복되지 않으면 사용자 추가
        let hash = await bcrypt.hash(req.body.password, 10);
        await User.create({
            username: req.body.username,
            password: hash
        });
        res.redirect('/');
    } catch (error) {
        console.log(error);
        res.status(500).send('서버 에러');
    }
});



app.get('/login', async (req, res) => {
    res.render('login.ejs')
})

app.post('/login', async (req, res) => {
    try {
        let user = await User.findOne({ username: req.body.username });
        if (!user) {
            return res.send("User not found");
        }
        if (await bcrypt.compare(req.body.password, user.password)) {
            // 로그인 성공 시 토큰 생성
            const token = generateAuthToken(user);
            // 쿠키에 토큰 설정
            res.cookie('auth_token', token, { httpOnly: true });
            // 로그인 성공 후 /diary로 리다이렉션
            res.redirect('/');
        } else {
            res.send("비밀번호가 일치하지 않습니다.");
        }
    } catch (error) {
        console.log(error);
        res.status(500).send('서버 에러');
    }
});


// server.js

app.get('/MyPage', isAuthenticated, async (req, res) => {
    try {
        // 사용자 정보를 불러오는 코드
        const user = await User.findById(req.user._id);
        res.render('MyPage', { user: user });
    } catch (error) {
        console.log(error);
        res.status(500).send('서버 에러');
    }
});
app.post('/MainPage', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        // 새로운 비밀번호로 해싱
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        // 기존 비밀번호 업데이트
        user.password = hashedPassword;
        await user.save();
        res.redirect('/MyPage'); // 비밀번호 변경 후 마이페이지로 리다이렉트
    } catch (error) {
        console.log(error);
        res.status(500).send('서버 에러');
    }
});




app.get('/dashboard', (req, res) => {
    const token = req.cookies.auth_token;

    if(token) {
        jwt.verify(token, secretKey, (err, decoded) => {
            if(err) {
                return res.status(401).send('인증 오류: 토큰이 유효하지 않습니다.');
            } else {
                res.send(`환영합니다, ${decoded.username}님!`);
            }
        });
    } else {
        res.status(401).send('인증 오류: 토큰이 없습니다.');
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('auth_token'); // auth_token 쿠키 삭제
    res.redirect('/login'); // 로그인 페이지로 리다이렉트
});

app.post('/logout', (req, res) => {
    res.clearCookie('auth_token'); // auth_token 쿠키를 삭제하여 로그아웃
    res.redirect('/'); // 로그아웃 후 메인 페이지로 리다이렉트
});

const multer = require('multer');

// 파일 업로드를 처리할 multer 미들웨어 설정
const upload = multer({ dest: 'uploads/' });

// 프로필 사진 업로드 라우트
app.post('/uploadProfilePic', isAuthenticated, upload.single('profilePic'), async (req, res) => {
    try {
        // 요청에서 파일 정보 추출
        const file = req.file;

        // 파일이 없는 경우 에러 메시지 반환
        if (!file) {
            return res.status(400).send('프로필 사진을 찾을 수 없습니다.');
        }

        // 업로드된 파일의 경로를 사용자 데이터에 저장 (예: MongoDB의 User 모델에 profilePic 필드 추가)
        const user = await User.findById(req.user._id);
        user.profilePic = file.path;
        await user.save();

        res.redirect('/MyPage'); // 프로필 페이지로 리다이렉트
    } catch (error) {
        console.log(error);
        res.status(500).send('서버 에러');
    }
});

// 비밀번호 변경 처리 라우트
// 서버 사이드 코드에서의 변경 비밀번호 처리 라우트
app.post('/changePassword', isAuthenticated, async (req, res) => {
    try {
        // 사용자 정보 불러오기
        const user = await User.findById(req.user._id);
        
        // 클라이언트에서 전달된 현재 비밀번호 확인
        const currentPassword = req.body.currentPassword;
        
        // 입력한 현재 비밀번호와 저장된 비밀번호 비교
        const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isPasswordMatch) {
            return res.status(400).send('현재 비밀번호가 일치하지 않습니다.');
        }
        
        // 새로운 비밀번호와 확인용 비밀번호가 일치하는지 확인
        if (req.body.newPassword !== req.body.confirmNewPassword) {
            return res.status(400).send('새로운 비밀번호와 확인용 비밀번호가 일치하지 않습니다.');
        }
        
        // 새로운 비밀번호를 해싱하여 저장
        const hashedNewPassword = await bcrypt.hash(req.body.newPassword, 10);
        user.password = hashedNewPassword;
        await user.save();
        
        res.redirect('/logout'); // 비밀번호 변경 후 마이페이지로 리다이렉트
    } catch (error) {
        console.error(error);
        res.status(500).send('서버 에러');
    }
});


// 서버 시작
app.listen(3000, () => {
    console.log('서버가 http://localhost:3000 에서 실행중입니다.');
});


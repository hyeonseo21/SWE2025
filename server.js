
const express = require('express'); //서버 생성
const mysql = require('mysql2'); //mysql 연결
const bcrypt = require('bcryptjs'); //비밀번호 암호화
const bodyParser = require('body-parser'); //요청 본문 파싱
const session = require('express-session'); //세션 관리
const path = require('path'); //파일 경로 처리
const nodemailer = require('nodemailer'); //이메일 전송
const fs = require('fs'); //파일 시스템 접근

const app = express(); //express 애플리케이션 생성
const port = 3000; //포트 번호 

const resetCodes = {}; //초기화 코드 저장

const transporter = nodemailer.createTransport({ //이메일 세팅
  service: 'gmail',
  auth: {
    user: '@gmail.com', //지메일 아이디
    pass: '' //각자의 지메일 2차 번호
  }
});

app.use(bodyParser.urlencoded({ extended: true })); //요청 본문 파싱으로 이 코드가 없으면 로그인 기능이 작동하지 않음음
app.use(bodyParser.json()); //요청 본문 파싱으로 이 코드가 없으면 로그인 기능이 작동하지 않음

app.use(express.static(path.join(__dirname, '../fend')));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false
}));

// MySQL과 연결
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '4971',
  database: 'enpick_db'
});

db.connect(err => { //db와 연결
  if (err) throw err;
  console.log('MySQL 연결 성공!');
});

app.get('/', (req, res) => { //local:3000 접속시 진입점을 설정
  const filePath = 'login.html';
  const options = { root: path.join(__dirname, '../fend') };
  
  res.sendFile(filePath, options, (err) => {
    if (err) { //오류 점검용
      console.error('파일 전송 중 오류 발생:', err);
      res.status(err.status || 500).send('파일을 찾을 수 없거나 서버 오류입니다.');
    }
  });
});

app.post('/signup', async (req, res) => { //회원가입 요청시 실행되는 코드
  const { full_name, email, password } = req.body;

  if (!full_name || !email || !password) {
    return res.redirect('/signup.html?error=' + encodeURIComponent('All fields are required.'));
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10); //
    db.query(
      'INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
      [full_name, email, hashedPassword],
      (err) => {
        if (err) {
          console.error('회원가입 DB 삽입 오류:', err);
          return res.redirect('/signup.html?error=' + encodeURIComponent('Email already exists or server error.'));
        }
        res.redirect('/login.html');
      }
    );
  } catch (e) {
    console.error('회원가입 중 서버 에러:', e);
    return res.redirect('/signup.html?error=' + encodeURIComponent('Internal server error.'));
  }
});

app.post('/login', async (req, res) => { //로그인 요청시 실행
  const { email, password } = req.body;
  try {
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) throw err;
      if (results.length === 0) return res.send('Email not found.');

      const user = results[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        req.session.user = user;
        res.redirect('/home.html');
      } else {
        res.send('Incorrect password.');
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).send('Server error.');
  }
});

app.get('/home.html', (req, res) => {
  if (!req.session.user) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, '../fend/home.html'));
});

app.post('/send-reset-code', (req, res) => { //비밀번호 찾기 요청시 실행
  const { email } = req.body;
  const trimmedEmail = (email || '').trim().toLowerCase();

  if (!trimmedEmail) {
    return res.redirect('/forgot-password.html?error=' + encodeURIComponent('Please enter your email.'));
  }

  db.query('SELECT * FROM users WHERE email = ?', [trimmedEmail], (err, results) => {
    if (err) {
      console.error('DB 오류:', err);
      return res.redirect('/forgot-password.html?error=' + encodeURIComponent('Server error.'));
    }

    if (!results || results.length === 0) {
      return res.redirect('/forgot-password.html?error=' + encodeURIComponent('Email not registered.'));
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    resetCodes[trimmedEmail] = code;

    const mailOptions = {
      from: 'qus7932@gmail.com',
      to: trimmedEmail,
      subject: 'EnPick Password Reset Code',
      text: `Verification Code: ${code}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('이메일 전송 실패:', error);
        return res.redirect('/forgot-password.html?error=' + encodeURIComponent('Failed to send email.'));
      }
      res.redirect(`/verify-code.html?email=${encodeURIComponent(trimmedEmail)}`);
    });
  });
});

app.post('/verify-code', (req, res) => { //인증번호 코드 검증 요청시 실행
  const { email, code } = req.body;

  if (resetCodes[email] && resetCodes[email] === code) {
    delete resetCodes[email];
    return res.redirect(`/reset-password.html?email=${encodeURIComponent(email)}`);
  } else {
    return res.send('Invalid verification code.');
  }
});

app.post('/reset-password', async (req, res) => { //비밀번호 재설정 
  const email = req.body.email;
  const newPassword = req.body.newPassword;

  if (!email || !newPassword) {
    return res.status(400).send('Invalid input.');
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err, result) => {
      if (err) {
        console.error('비밀번호 재설정 오류:', err);
        return res.status(500).send('An error occurred while updating the password.');
      }

      if (result.affectedRows === 0) {
        return res.status(404).send('No account associated with this email.');
      }

      res.send('success');
    });
  } catch (error) {
    console.error('비밀번호 해시 오류:', error);
    res.status(500).send('Server error');
  }
});
app.listen(port, () => {
  console.log(`서버가 http://localhost:${port} 에서 실행 중`);
});

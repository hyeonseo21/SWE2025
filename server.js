const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const port = 3000;

const resetCodes = {};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: '@gmail.com',
    pass: ''
  }
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../enpick-frontend')));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false
}));

//MySQL 연결
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'qpalzm12!',
  database: 'enpick_db'
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL 연결 성공!');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../enpick-frontend/signup.html'));
});

app.post('/signup', async (req, res) => {
  const { full_name, email, password } = req.body;

  if (!full_name || !email || !password) {
    return res.redirect('/signup.html?error=' + encodeURIComponent('All fields are required.'));
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
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

app.post('/login', async (req, res) => {
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
  res.sendFile(path.join(__dirname, '../enpick-frontend/home.html'));
});

app.post('/send-reset-code', (req, res) => {
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
      from: '@gmail.com',
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

app.post('/verify-code', (req, res) => {
  const { email, code } = req.body;

  if (resetCodes[email] && resetCodes[email] === code) {
    delete resetCodes[email];
    return res.redirect(`/reset-password.html?email=${encodeURIComponent(email)}`);
  } else {
    return res.send('Invalid verification code.');
  }
});

app.post('/reset-password', async (req, res) => {
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

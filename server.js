
const express = require('express'); //서버 생성
const mysql = require('mysql2'); //mysql 연결
const bcrypt = require('bcryptjs'); //비밀번호 암호화
const bodyParser = require('body-parser'); //요청 본문 파싱
const session = require('express-session'); //세션 관리
const path = require('path'); //파일 경로 처리
const nodemailer = require('nodemailer'); //이메일 전송
const fs = require('fs'); //파일 시스템 접근
const cors = require('cors'); //수정됨: 브라우저 보안 정책 충돌로 인해

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

app.use(cors());

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
  port: 3306,   //수정됨: port번호 3306 아닐경우 추가
  user: 'root',
  password: ' ',
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

app.post('/login', async (req, res) => { //수정됨: 로그인 에러메세지 출력 위해 수정, json방식 이용
  const { email, password } = req.body;
  try {
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) throw err;
      if (results.length === 0) {
        return res.status(401).json({
          success: false,
          message: 'Incorrect Email'
        });
      }

      const user = results[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        req.session.user = user;
        res.status(200).json({
          success: true,
          role: user.role,
          name: user.full_name
        });
      } else {
        res.status(401).json({ success: false, message: 'Incorrect Password' });
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).send({success: false, message: 'Server error.'});
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

// 단어장 단어 목록 API (MySQL에서 조회)
// My단어장 반영 수정.
app.get('/api/words', (req, res) => {
  const { type, difficulty } = req.query;
  const userId = req.session.user.id;
  const params = [ userId ];
  let sql = `
    SELECT
      wl.id, wl.word, wl.part_of_speech, wl.meaning, wl.difficulty,
      IF(m.user_id IS NOT NULL, 1, 0) AS is_starred
    FROM word_lists wl
    LEFT JOIN mywords m
      ON wl.id = m.word_id
     AND m.user_id = ?
  `;

  if (type === 'my') {
    // 내 단어장 모드: INNER JOIN 효과
    sql += ` WHERE m.user_id = ? `;
    params.push(userId);
  }
  else if (difficulty) {
    const diffs = Array.isArray(difficulty) ? difficulty : [difficulty];
    const ph = diffs.map(_=>'?').join(',');
    sql += ` WHERE wl.difficulty IN (${ph}) `;
    params.push(...diffs);
  }

  sql += ` ORDER BY wl.word ASC`;

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'DB 조회 실패' });
    }
    res.json(results);
  });
});




app.post('/api/words', (req, res) => {
  const { word, part_of_speech, meaning, difficulty } = req.body;
  if (!word || !part_of_speech || !meaning || !difficulty) {
    return res.status(400).json({ error: '모든 필드를 입력해야 합니다.' });
  }

  const sql = 'INSERT INTO word_lists (word, part_of_speech, meaning, difficulty) VALUES (?, ?, ?, ?)';
  db.query(sql, [word, part_of_speech, meaning, difficulty], (err, result) => {
    if (err) {
      console.error('단어 추가 오류:', err);
      return res.status(500).json({ error: '단어 추가 실패' });
    }
    res.json({ success: true, id: result.insertId });
  });
});

app.put('/api/words/:id', (req, res) => {
  const { id } = req.params;
  const { word, part_of_speech, meaning, difficulty } = req.body;

  const sql = 'UPDATE word_lists SET word = ?, part_of_speech = ?, meaning = ?, difficulty = ? WHERE id = ?';
  db.query(sql, [word, part_of_speech, meaning, difficulty, id], (err, result) => {
    if (err) {
      console.error('단어 수정 오류:', err);
      return res.status(500).json({ error: '수정 실패' });
    }
    res.json({ success: true });
  });
});

app.delete('/api/words/:id', (req, res) => {
  const { id } = req.params;

  // 100개 이하 삭제 제한
  db.query('SELECT COUNT(*) AS count FROM word_lists', (err, results) => {
    if (err) return res.status(500).json({ error: 'DB 오류' });

    if (results[0].count <= 100) {
      return res.status(400).json({ error: '100개 이하일 경우 삭제 불가' });
    }

    db.query('DELETE FROM word_lists WHERE id = ?', [id], (err) => {
      if (err) return res.status(500).json({ error: '삭제 실패' });
      res.json({ success: true });
    });
  });
});

app.post('/api/promote', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: '이메일 누락' });

  const sql = 'UPDATE users SET role = "admin" WHERE email = ?';
  db.query(sql, [email], (err, result) => {
    if (err) return res.status(500).json({ error: '승격 실패' });
    if (result.affectedRows === 0) return res.status(404).json({ error: '사용자 없음' });
    res.json({ success: true });
  });
});


app.post('/api/demote', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: '이메일 누락' });

  // root 계정은 회수 불가
  if (email === 'root@enpick.kr') {
    return res.status(403).json({ error: 'root 계정은 회수할 수 없습니다.' });
  }

  const sql = 'UPDATE users SET role = "user" WHERE email = ? AND role = "admin"';
  db.query(sql, [email], (err, result) => {
    if (err) return res.status(500).json({ error: '회수 실패' });
    if (result.affectedRows === 0) return res.status(404).json({ error: '해당 관리자 없음' });
    res.json({ success: true });
  });
});


app.get('/admin.html', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, '../fend/admin.html'));
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: '로그인하지 않았습니다.' });
  }

  const { id, email, role } = req.session.user;
  res.json({ id, email, role });
});

// 상세 정보 가져오기
app.get('/api/details/:wordId', (req, res) => {
  const wordId = req.params.wordId;
  const sql = `SELECT * FROM word_details WHERE word_id = ?`;
  db.query(sql, [wordId], (err, result) => {
    if (err) return res.status(500).send('DB 조회 오류');
    if (result.length === 0) return res.status(404).send('상세 정보 없음');
    res.json(result[0]);
  });
});

// 상세 정보 추가 또는 수정
app.post('/api/details/:wordId', (req, res) => {
  const wordId = req.params.wordId;
  const { synonym, antonym, example, example_kor } = req.body;

  // 먼저 해당 wordId가 이미 존재하는지 확인
  db.query(`SELECT * FROM word_details WHERE word_id = ?`, [wordId], (err, rows) => {
    if (err) return res.status(500).send('DB 오류');
    if (rows.length > 0) {
      // 업데이트
      const sql = `
        UPDATE word_details SET synonym=?, antonym=?, example=?, example_kor=?
        WHERE word_id=?`;
      db.query(sql, [synonym, antonym, example, example_kor, wordId], (err, result) => {
        if (err) return res.status(500).send('업데이트 오류');
        res.send('수정 완료');
      });
    } else {
      // 새로 추가
      const sql = `
        INSERT INTO word_details (word_id, synonym, antonym, example, example_kor)
        VALUES (?, ?, ?, ?, ?)`;
      db.query(sql, [wordId, synonym, antonym, example, example_kor], (err, result) => {
        if (err) return res.status(500).send('삽입 오류');
        res.send('등록 완료');
      });
    }
  });
});

//음성 인식
app.get('/api/tts', async (req, res) => {
  const text = req.query.text;
  const region = req.query.region || 'us'; // 기본 미국식
  if (!text) return res.status(400).send('Text query is required.');

  // Voice ID 설정
  const VOICES = {
    us: 'ErXwobaYiN019PkySvjV', // Antoni - 미국식
    uk: 'ThT5KcBeYPX3keUQqHPh',   // Dorothy - 영국식
    au: 'ZQe5CZNOzWyzPSCn5a3c'    // James - 호주식
  };
  const VOICE_ID = VOICES[region] || VOICES.us;

  try {
    const ttsRes = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${VOICE_ID}`, {
      method: 'POST',
      headers: {
        'accept': 'audio/mpeg',
        'xi-api-key': 'sk_d060c0d4d86e9d43614031f95b2c23b9d49746d59f1241bd', // 실제 API 키로 대체
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        text,
        model_id: 'eleven_monolingual_v1',
        voice_settings: {
          stability: 0.4,
          similarity_boost: 0.7
        }
      })
    });

    if (!ttsRes.ok) return res.status(ttsRes.status).send('Failed to fetch TTS audio');

    const arrayBuffer = await ttsRes.arrayBuffer();
    const audioBuffer = Buffer.from(arrayBuffer); 
    res.set('Content-Type', 'audio/mpeg');
    res.send(audioBuffer);
  } catch (err) {
    console.error('TTS Error:', err);
    res.status(500).send('TTS Server error');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('로그아웃 실패');
    res.clearCookie('connect.sid'); // 쿠키 제거
    res.send('로그아웃 성공');
  });
});

app.get('/api/gamewords', (req, res) => {
  const user = req.session.user;
  const { source, level, count } = req.query;

  const limit = parseInt(count) || 10;

  if (!user) return res.status(401).json({ error: '로그인 필요' });

  if (source === 'mywords') {
    // 사용자의 MyWords에서 랜덤하게 단어 추출
    const sql = `
      SELECT wl.id, wl.word, wl.meaning
      FROM mywords mw
      JOIN word_lists wl ON mw.word_id = wl.id
      WHERE mw.user_id = ?
      ORDER BY RAND() LIMIT ?
    `;
    db.query(sql, [user.id, limit], (err, results) => {
      if (err) {
        console.error('MyWords 게임 단어 조회 오류:', err);
        return res.status(500).json({ error: 'DB 오류' });
      }
      res.json(results);
    });
  } else {
    // 전체 단어장에서 난이도 기준으로 랜덤 추출
    const sql = `
      SELECT id, word, meaning
      FROM word_lists
      WHERE difficulty = ?
      ORDER BY RAND() LIMIT ?
    `;
    db.query(sql, [level, limit], (err, results) => {
      if (err) {
        console.error('전체 단어장 게임 단어 조회 오류:', err);
        return res.status(500).json({ error: 'DB 오류' });
      }
      res.json(results);
    });
  }
});



app.post('/api/mywords', (req, res) => {
  const { user_id, word_id, source } = req.body;
  const columnMap = {
    favorite: 'added_by_favorite',
    test: 'added_by_test',
    game: 'added_by_game'
  };
  const targetColumn = columnMap[source];
  if (!targetColumn) return res.status(400).send('잘못된 source');

  const query = `
    INSERT INTO mywords (user_id, word_id, ${targetColumn})
    VALUES (?, ?, 1)
    ON DUPLICATE KEY UPDATE
      ${targetColumn} = 1,
      added_at = NOW()
  `;
  db.query(query, [user_id, word_id], (err) => {
    if (err) {
      console.error('MyWords 추가 실패:', err);
      return res.sendStatus(500);
    }
    res.sendStatus(200);
  });
});

app.get('/api/mywords', (req, res) => {
  const userId = req.query.user_id;
  const sql = `
    SELECT 
      m.word_id, 
      w.word, 
      w.meaning, 
      w.part_of_speech, 
      m.added_by_favorite, 
      m.added_by_test, 
      m.added_by_game, 
      m.added_at
    FROM mywords m
    JOIN word_lists w ON m.word_id = w.id
    WHERE m.user_id = ?
  `;
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('My 단어장 불러오기 실패:', err);
      return res.sendStatus(500);
    }
    res.json(results);
  });
});

app.get('/api/testwords', (req, res) => {
  const { type, count, source, difficulty } = req.query;
  const userId = req.session.user?.id || req.query.user_id;

  if (!userId && source === 'mywords') {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }

  if (type === 'daily') {
    if (source === 'mywords') {
      const query = `
        SELECT w.id, w.word, w.meaning 
        FROM mywords m 
        JOIN word_lists w ON m.word_id = w.id 
        WHERE m.user_id = ? 
        ORDER BY RAND() LIMIT ?
      `;
      db.query(query, [userId, Number(count)], (err, results) => {
        if (err) return res.status(500).json({ error: 'DB 오류' });
        res.json(results);
      });
    } else {
      const levels = (difficulty || '600,700,800,900').split(',');
      const placeholders = levels.map(() => '?').join(',');
      const query = `
        SELECT id, word, meaning
        FROM word_lists 
        WHERE difficulty IN (${placeholders}) 
        ORDER BY RAND() LIMIT ?
      `;
      db.query(query, [...levels, Number(count)], (err, results) => {
        if (err) return res.status(500).json({ error: 'DB 오류' });
        res.json(results);
      });
    }
  } else if (type === 'level') {
    const levels = ['600', '700', '800', '900'];
    const eachCount = 6;
    const promises = levels.map(lv => {
      return new Promise((resolve, reject) => {
        db.query(
          `SELECT id, word, meaning, difficulty FROM word_lists WHERE difficulty = ? ORDER BY RAND() LIMIT ?`,
          [lv, eachCount],
          (err, results) => {
            if (err) reject(err);
            else resolve(results);
          }
        );
      });
    });

    Promise.all(promises)
      .then(results => {
        const flat = results.flat().slice(0, Number(count));
        res.json(flat);
      })
      .catch(err => {
        console.error('레벨 테스트 DB 오류:', err);
        res.status(500).json({ error: '레벨 테스트 불러오기 실패' });
      });
  } else {
    res.status(400).json({ error: '잘못된 테스트 유형' });
  }
});

app.post('/api/testwords/retry', (req, res) => {
  const { word_ids } = req.body;
  if (!word_ids || !Array.isArray(word_ids) || word_ids.length === 0) {
    return res.status(400).json({ error: 'word_ids가 필요합니다.' });
  }

  const placeholders = word_ids.map(() => '?').join(',');
  const sql = `SELECT id, word, meaning FROM word_lists WHERE id IN (${placeholders})`;

  db.query(sql, word_ids, (err, results) => {
    if (err) {
      console.error('/api/testwords/retry 오류:', err);
      return res.sendStatus(500);
    }
    res.json(results);
  });
});

app.get('/api/mywords/check', (req, res) => {
  const { user_id, word_id } = req.query;
  const sql = `SELECT 1 FROM mywords WHERE user_id = ? AND word_id = ? LIMIT 1`;

  db.query(sql, [user_id, word_id], (err, results) => {
    if (err) return res.status(500).json({ error: 'DB 오류' });
    res.json({ exists: results.length > 0 });
  });
});

app.delete('/api/mywords', (req, res) => {
  const { user_id, word_id } = req.body;
  const sql = `DELETE FROM mywords WHERE user_id = ? AND word_id = ?`;

  db.query(sql, [user_id, word_id], (err) => {
    if (err) return res.status(500).json({ error: '삭제 실패' });
    res.sendStatus(200);
  });
});

app.post('/api/save-test-result', (req, res) => {
  const { userId, correctCount, wrongCount } = req.body;
  if (!userId || correctCount == null || wrongCount == null) {
    return res.status(400).json({ error: '필수 값 누락' });
  }

  const sql = `
    INSERT INTO test_results_summary (user_id, correct_total, wrong_total)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE
      correct_total = correct_total + VALUES(correct_total),
      wrong_total = wrong_total + VALUES(wrong_total)
  `;
  db.query(sql, [userId, correctCount, wrongCount], (err) => {
    if (err) {
      console.error("누적 정답률 저장 오류:", err);
      return res.status(500).json({ error: 'DB 오류' });
    }
    res.sendStatus(200);
  });
});

app.get('/api/test-summary', (req, res) => {
  const userId = req.session.user?.id;
  if (!userId) return res.status(401).json({ error: '로그인 필요' });

  const sql = `
    SELECT correct_total, wrong_total, accuracy
    FROM test_results_summary
    WHERE user_id = ?
  `;
  db.query(sql, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'DB 오류' });
    if (results.length === 0) {
      return res.json({ correct_total: 0, wrong_total: 0, accuracy: 0 });
    }
    res.json(results[0]);
  });
});

// ✅ 학습 완료 단어 조회
app.get('/api/learned', (req, res) => {
  const { user_id } = req.query;
  const sql = `SELECT word_id FROM learned_words WHERE user_id = ?`;
  db.query(sql, [user_id], (err, results) => {
    if (err) {
      console.error('학습 완료 조회 오류:', err);
      return res.status(500).json({ error: 'DB 오류' });
    }
    res.json(results.map(r => r.word_id)); // [101, 102, ...]
  });
});

// ✅ 학습 완료 추가
app.post('/api/learned', (req, res) => {
  const { user_id, word_id } = req.body;
  const sql = `INSERT IGNORE INTO learned_words (user_id, word_id) VALUES (?, ?)`;
  db.query(sql, [user_id, word_id], (err) => {
    if (err) {
      console.error('학습 완료 등록 오류:', err);
      return res.status(500).json({ error: '등록 실패' });
    }
    res.sendStatus(200);
  });
});

// ✅ 학습 완료 삭제
app.delete('/api/learned', (req, res) => {
  const { user_id, word_id } = req.body;
  const sql = `DELETE FROM learned_words WHERE user_id = ? AND word_id = ?`;
  db.query(sql, [user_id, word_id], (err) => {
    if (err) {
      console.error('학습 완료 삭제 오류:', err);
      return res.status(500).json({ error: '삭제 실패' });
    }
    res.sendStatus(200);
  });
});



app.listen(port, () => {
  console.log(`서버가 http://localhost:${port} 에서 실행 중`);
});

require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const { sendVerificationEmail, sendPasswordResetEmail } = require('./mailer');

const app = express();
const port = Number(process.env.PORT || 4000);
const jwtSecret = process.env.JWT_SECRET || 'change-this-secret';
const refreshTokenDays = Number(process.env.REFRESH_TOKEN_DAYS || 7);

app.use(cors({
  origin: process.env.CLIENT_ORIGIN || 'http://localhost:4200',
  credentials: true
}));
app.use(express.json());

app.get('/', (_req, res) => {
  res.json({ message: 'Angular auth MySQL API is running' });
});

app.post('/accounts/authenticate', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const account = await findAccountByEmail(email);

    if (!account || !account.is_verified || !await bcrypt.compare(password || '', account.password_hash)) {
      return badRequest(res, 'Email or password is incorrect');
    }

    const refreshToken = await createRefreshToken(account.id);
    setRefreshTokenCookie(res, refreshToken);

    res.json({
      ...basicDetails(account),
      jwtToken: generateJwtToken(account)
    });
  } catch (error) {
    next(error);
  }
});

app.post('/accounts/refresh-token', async (req, res, next) => {
  try {
    const currentToken = getCookie(req, 'refreshToken');
    if (!currentToken) return unauthorized(res);

    const tokenRow = await findActiveRefreshToken(currentToken);
    if (!tokenRow) return unauthorized(res);

    await db.execute('UPDATE refresh_tokens SET revoked = NOW() WHERE token = ?', [currentToken]);

    const refreshToken = await createRefreshToken(tokenRow.account_id);
    setRefreshTokenCookie(res, refreshToken);

    const account = await findAccountById(tokenRow.account_id);
    res.json({
      ...basicDetails(account),
      jwtToken: generateJwtToken(account)
    });
  } catch (error) {
    next(error);
  }
});

app.post('/accounts/revoke-token', auth, async (req, res, next) => {
  try {
    const currentToken = getCookie(req, 'refreshToken');
    if (currentToken) {
      await db.execute('UPDATE refresh_tokens SET revoked = NOW() WHERE token = ?', [currentToken]);
    }
    clearRefreshTokenCookie(res);
    res.json({});
  } catch (error) {
    next(error);
  }
});

app.post('/accounts/register', async (req, res, next) => {
  try {
    const account = req.body;
    const existing = await findAccountByEmail(account.email);
    if (existing) return res.json({});

    const [[countRow]] = await db.execute('SELECT COUNT(*) AS total FROM accounts');
    const role = countRow.total === 0 ? 'Admin' : 'User';
    const verificationToken = randomToken();
    const passwordHash = await bcrypt.hash(account.password, 10);

    await db.execute(
      `INSERT INTO accounts
        (title, first_name, last_name, email, password_hash, role, is_verified, verification_token)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        account.title || null,
        account.firstName,
        account.lastName,
        account.email,
        passwordHash,
        role,
        false,
        verificationToken
      ]
    );

    const emailSent = await sendVerificationEmail(account, verificationToken);

    res.json({
      message: emailSent
        ? 'Registration successful. Please check your email for verification instructions.'
        : 'Registration successful. Use this token on the verify email page while email sending is not configured.',
      verificationToken
    });
  } catch (error) {
    next(error);
  }
});

app.post('/accounts/verify-email', async (req, res, next) => {
  try {
    const { token } = req.body;
    const [result] = await db.execute(
      'UPDATE accounts SET is_verified = TRUE, verification_token = NULL WHERE verification_token = ?',
      [token]
    );

    if (result.affectedRows === 0) return badRequest(res, 'Verification failed');
    res.json({});
  } catch (error) {
    next(error);
  }
});

app.post('/accounts/forgot-password', async (req, res, next) => {
  try {
    const account = await findAccountByEmail(req.body.email);
    if (account) {
      const resetToken = randomToken();
      await db.execute(
        'UPDATE accounts SET reset_token = ?, reset_token_expires = DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE id = ?',
        [resetToken, account.id]
      );

      const emailSent = await sendPasswordResetEmail(account, resetToken);
      return res.json({
        message: emailSent
          ? 'Please check your email for password reset instructions.'
          : 'Password reset token created. Use this token on the reset password page while email sending is not configured.',
        resetToken
      });
    }
    res.json({});
  } catch (error) {
    next(error);
  }
});

app.post('/accounts/validate-reset-token', async (req, res, next) => {
  try {
    const account = await findAccountByResetToken(req.body.token);
    if (!account) return badRequest(res, 'Invalid token');
    res.json({});
  } catch (error) {
    next(error);
  }
});

app.post('/accounts/reset-password', async (req, res, next) => {
  try {
    const account = await findAccountByResetToken(req.body.token);
    if (!account) return badRequest(res, 'Invalid token');

    const passwordHash = await bcrypt.hash(req.body.password, 10);
    await db.execute(
      `UPDATE accounts
       SET password_hash = ?, is_verified = TRUE, reset_token = NULL, reset_token_expires = NULL
       WHERE id = ?`,
      [passwordHash, account.id]
    );

    res.json({});
  } catch (error) {
    next(error);
  }
});

app.get('/accounts', auth, async (_req, res, next) => {
  try {
    const [rows] = await db.execute('SELECT * FROM accounts ORDER BY id');
    res.json(rows.map(basicDetails));
  } catch (error) {
    next(error);
  }
});

app.get('/accounts/:id', auth, async (req, res, next) => {
  try {
    const account = await findAccountById(req.params.id);
    if (!account) return res.status(404).json({ message: 'Account not found' });
    if (account.id !== req.account.id && req.account.role !== 'Admin') return unauthorized(res);
    res.json(basicDetails(account));
  } catch (error) {
    next(error);
  }
});

app.post('/accounts', auth, adminOnly, async (req, res, next) => {
  try {
    const account = req.body;
    if (await findAccountByEmail(account.email)) {
      return badRequest(res, `Email ${account.email} is already registered`);
    }

    const passwordHash = await bcrypt.hash(account.password, 10);
    await db.execute(
      `INSERT INTO accounts
        (title, first_name, last_name, email, password_hash, role, is_verified)
       VALUES (?, ?, ?, ?, ?, ?, TRUE)`,
      [
        account.title || null,
        account.firstName,
        account.lastName,
        account.email,
        passwordHash,
        account.role || 'User'
      ]
    );

    res.json({});
  } catch (error) {
    next(error);
  }
});

app.put('/accounts/:id', auth, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (id !== req.account.id && req.account.role !== 'Admin') return unauthorized(res);

    const existing = await findAccountById(id);
    if (!existing) return res.status(404).json({ message: 'Account not found' });

    const passwordHash = req.body.password
      ? await bcrypt.hash(req.body.password, 10)
      : existing.password_hash;

    await db.execute(
      `UPDATE accounts
       SET title = ?, first_name = ?, last_name = ?, email = ?, role = ?, password_hash = ?
       WHERE id = ?`,
      [
        req.body.title || null,
        req.body.firstName,
        req.body.lastName,
        req.body.email,
        req.account.role === 'Admin' ? req.body.role || existing.role : existing.role,
        passwordHash,
        id
      ]
    );

    const account = await findAccountById(id);
    res.json(basicDetails(account));
  } catch (error) {
    next(error);
  }
});

app.delete('/accounts/:id', auth, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (id !== req.account.id && req.account.role !== 'Admin') return unauthorized(res);

    await db.execute('DELETE FROM accounts WHERE id = ?', [id]);
    res.json({});
  } catch (error) {
    next(error);
  }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ message: 'Server error' });
});

app.listen(port, () => {
  console.log(`API server listening on http://localhost:${port}`);
});

async function auth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return unauthorized(res);

    const payload = jwt.verify(token, jwtSecret);
    const account = await findAccountById(payload.id);
    if (!account) return unauthorized(res);

    req.account = account;
    next();
  } catch {
    return unauthorized(res);
  }
}

function adminOnly(req, res, next) {
  if (req.account.role !== 'Admin') return unauthorized(res);
  next();
}

async function findAccountById(id) {
  const [rows] = await db.execute('SELECT * FROM accounts WHERE id = ?', [id]);
  return rows[0];
}

async function findAccountByEmail(email) {
  const [rows] = await db.execute('SELECT * FROM accounts WHERE email = ?', [email]);
  return rows[0];
}

async function findAccountByResetToken(token) {
  const [rows] = await db.execute(
    'SELECT * FROM accounts WHERE reset_token = ? AND reset_token_expires > NOW()',
    [token]
  );
  return rows[0];
}

async function findActiveRefreshToken(token) {
  const [rows] = await db.execute(
    'SELECT * FROM refresh_tokens WHERE token = ? AND revoked IS NULL AND expires > NOW()',
    [token]
  );
  return rows[0];
}

async function createRefreshToken(accountId) {
  const token = randomToken();
  await db.execute(
    'INSERT INTO refresh_tokens (account_id, token, expires) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? DAY))',
    [accountId, token, refreshTokenDays]
  );
  return token;
}

function generateJwtToken(account) {
  return jwt.sign({ id: account.id }, jwtSecret, {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m'
  });
}

function basicDetails(account) {
  return {
    id: account.id,
    title: account.title,
    firstName: account.first_name,
    lastName: account.last_name,
    email: account.email,
    role: account.role,
    dateCreated: account.date_created,
    isVerified: Boolean(account.is_verified)
  };
}

function randomToken() {
  return crypto.randomBytes(40).toString('hex');
}

function setRefreshTokenCookie(res, token) {
  const maxAge = refreshTokenDays * 24 * 60 * 60;
  res.setHeader('Set-Cookie', `refreshToken=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`);
}

function clearRefreshTokenCookie(res) {
  res.setHeader('Set-Cookie', 'refreshToken=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || '';
  const match = cookies
    .split(';')
    .map(cookie => cookie.trim())
    .find(cookie => cookie.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.split('=').slice(1).join('=')) : '';
}

function badRequest(res, message) {
  return res.status(400).json({ message });
}

function unauthorized(res) {
  return res.status(401).json({ message: 'Unauthorized' });
}

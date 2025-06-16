// =================================================================
// ==      FILE FINAL: server.js (dengan Fitur Lupa Password)   ==
// =================================================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Library bawaan Node.js untuk token acak
const nodemailer = require('nodemailer'); // Library baru untuk email
const { Pool } = require('pg');

// === KONFIGURASI DATABASE ===
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = 'ini-adalah-kunci-rahasia-yang-sangat-aman-dan-panjang';

function generateSlug() { return Math.random().toString(36).substring(2, 8); }

// === KONFIGURASI PENGIRIM EMAIL (NODEMAILER) ===
// Mengambil kredensial dari Environment Variables di Render
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', true);

app.use(cors({
  origin: [
    'https://hamdirzl.my.id', 
    'https://www.hamdirzl.my.id', 
    'https://hrportof.netlify.app'
  ] 
}));

app.use(express.json());

// === ROUTES ===

app.get('/', (req, res) => res.send('Halo dari Backend Server Node.js! Terhubung ke PostgreSQL.'));

app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Input tidak valid.' });

        const passwordHash = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
            [email, passwordHash]
        );
        res.status(201).json({ message: 'Pengguna berhasil dibuat!', user: newUser.rows[0] });
    } catch (error) {
        if (error.code === '23505') return res.status(409).json({ error: 'Email sudah terdaftar.' });
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ error: 'Email atau password salah.' });

        const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordCorrect) return res.status(401).json({ error: 'Email atau password salah.' });

        const ipAddress = req.ip; 
        console.log(`Login Berhasil: Pengguna '${user.email}' (ID: ${user.id}) masuk dari IP: ${ipAddress}`);
        
        const userAgent = req.headers['user-agent'];
        pool.query(
            'INSERT INTO login_activity (user_id, ip_address, user_agent) VALUES ($1, $2, $3)',
            [user.id, ipAddress, userAgent]
        ).catch(err => console.error('Gagal mencatat aktivitas login ke DB:', err)); 
        
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login berhasil!', token });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

// [ENDPOINT BARU] LUPA PASSWORD
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        // Demi keamanan, kita selalu kirim pesan sukses meskipun email tidak ditemukan
        if (!user) {
            return res.json({ message: 'Jika email terdaftar, link untuk reset password telah dikirim.' });
        }

        // Buat token reset yang aman dan unik
        const resetToken = crypto.randomBytes(32).toString('hex');
        // Token berlaku selama 1 jam
        const tokenExpires = new Date(Date.now() + 3600000); 

        // Simpan token dan waktu kedaluwarsa ke database
        await pool.query(
            'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3',
            [resetToken, tokenExpires, email]
        );

        // Kirim email ke pengguna
        // Ganti 'hamdirzl.my.id' dengan domain frontend Anda yang sebenarnya jika berbeda
        const resetUrl = `https://hamdirzl.my.id/reset-password.html?token=${resetToken}`;

        await transporter.sendMail({
            to: user.email,
            from: `"Ekosistem Hamdi" <${process.env.EMAIL_USER}>`,
            subject: 'Reset Password Akun Anda',
            html: `
                <p>Anda menerima email ini karena ada permintaan untuk mereset password akun Anda.</p>
                <p>Silakan klik link di bawah ini untuk melanjutkan:</p>
                <a href="${resetUrl}">${resetUrl}</a>
                <p>Link ini hanya berlaku selama 1 jam.</p>
                <p>Jika Anda tidak merasa meminta ini, abaikan saja email ini.</p>
            `
        });

        res.json({ message: 'Jika email terdaftar, link untuk reset password telah dikirim.' });

    } catch (error) {
        console.error('Error di forgot-password:', error);
        // Jangan kirim detail error ke pengguna, cukup pesan umum
        res.status(500).json({ error: 'Terjadi kesalahan saat memproses permintaan.' });
    }
});

// [ENDPOINT BARU] RESET PASSWORD
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        
        if (!token || !password || password.length < 6) {
            return res.status(400).json({ error: 'Token dan password baru diperlukan.' });
        }

        // Cari pengguna dengan token yang valid dan belum kedaluwarsa
        const result = await pool.query(
            'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
            [token]
        );
        const user = result.rows[0];
        
        if (!user) {
            return res.status(400).json({ error: 'Token tidak valid atau sudah kedaluwarsa.' });
        }

        // Hash password baru
        const passwordHash = await bcrypt.hash(password, 10);
        
        // Update password dan hapus token dari database
        await pool.query(
            'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
            [passwordHash, user.id]
        );

        res.json({ message: 'Password berhasil diubah. Silakan login dengan password baru Anda.' });

    } catch (error) {
        console.error('Error di reset-password:', error);
        res.status(500).json({ error: 'Terjadi kesalahan saat mereset password.' });
    }
});

app.get('/api/profile', authenticateToken, (req, res) => res.json({ user: req.user }));

app.post('/api/moods', authenticateToken, async (req, res) => {
    try {
        const { mood_level, notes } = req.body;
        const user_id = req.user.id;
        if (mood_level == null || mood_level < 1 || mood_level > 5) return res.status(400).json({ error: 'Input mood tidak valid' });

        const newMood = await pool.query(
            'INSERT INTO moods (user_id, mood_level, notes) VALUES ($1, $2, $3) RETURNING *',
            [user_id, mood_level, notes]
        );
        res.status(201).json(newMood.rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

app.get('/api/moods', authenticateToken, async (req, res) => {
    try {
        const user_id = req.user.id;
        const result = await pool.query('SELECT * FROM moods WHERE user_id = $1 ORDER BY created_at DESC', [user_id]);
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

// ============== KODE UNTUK LINK PENDEK ==============
app.post('/api/shorten', async (req, res) => {
    try {
        const { original_url } = req.body;

        if (!original_url || !(original_url.startsWith('http://') || original_url.startsWith('https://'))) {
            return res.status(400).json({ error: 'URL tidak valid. Harus diawali dengan http:// atau https://' });
        }

        const slug = generateSlug();

        const newLink = await pool.query(
            'INSERT INTO links (original_url, slug) VALUES ($1, $2) RETURNING slug',
            [original_url, slug]
        );

        const baseUrl = process.env.BASE_URL || `https://${req.get('host')}`;
        const fullShortUrl = `${baseUrl}/${newLink.rows[0].slug}`;

        res.status(201).json({ short_url: fullShortUrl });

    } catch (error) {
        console.error("Error saat membuat link pendek:", error);
        res.status(500).json({ error: 'Gagal membuat link pendek di server.' });
    }
});

app.get('/:slug', async (req, res) => {
    try {
        const { slug } = req.params;
        const result = await pool.query('SELECT original_url FROM links WHERE slug = $1', [slug]);
        const link = result.rows[0];
        if (link) {
            res.redirect(301, link.original_url);
        } else {
            res.status(404).send('Link tidak ditemukan atau Anda mencoba mengakses halaman yang tidak ada.');
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));
// =================================================================
// == FILE FINAL: server.js (Update: Fitur Riwayat Link)       ==
// =================================================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

// === KONFIGURASI DATABASE ===
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// PINDAHKAN INI KE .env DI KEMUDIAN HARI
const JWT_SECRET = 'ini-adalah-kunci-rahasia-yang-sangat-aman-dan-panjang';

function generateSlug() { return Math.random().toString(36).substring(2, 8); }

// === KONFIGURASI PENGIRIM EMAIL (NODEMAILER) ===
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// === MIDDLEWARE ===
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

function authenticateAdmin(req, res, next) {
    authenticateToken(req, res, () => {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Akses ditolak. Fitur ini hanya untuk admin.' });
        }
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
        console.log(`Login Berhasil: Pengguna '${user.email}' (ID: ${user.id}, Role: ${user.role}) masuk dari IP: ${ipAddress}`);
        
        const userAgent = req.headers['user-agent'];
        pool.query(
            'INSERT INTO login_activity (user_id, ip_address, user_agent) VALUES ($1, $2, $3)',
            [user.id, ipAddress, userAgent]
        ).catch(err => console.error('Gagal mencatat aktivitas login ke DB:', err)); 
        
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login berhasil!', token });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.json({ message: 'Jika email terdaftar, link untuk reset password telah dikirim.' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenExpires = new Date(Date.now() + 3600000); 

        await pool.query(
            'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3',
            [resetToken, tokenExpires, email]
        );

        const resetUrl = `https://hamdirzl.my.id/reset-password.html?token=${resetToken}`;

        await transporter.sendMail({
            to: user.email,
            from: `"Ekosistem Hamdi" <${process.env.EMAIL_USER}>`,
            subject: 'Reset Password Akun Anda',
            html: `<p>Anda menerima email ini karena ada permintaan untuk mereset password akun Anda.</p><p>Silakan klik link di bawah ini untuk melanjutkan:</p><a href="${resetUrl}">${resetUrl}</a><p>Link ini hanya berlaku selama 1 jam.</p><p>Jika Anda tidak merasa meminta ini, abaikan saja email ini.</p>`
        });

        res.json({ message: 'Jika email terdaftar, link untuk reset password telah dikirim.' });

    } catch (error) {
        console.error('Error di forgot-password:', error);
        res.status(500).json({ error: 'Terjadi kesalahan saat memproses permintaan.' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        
        if (!token || !password || password.length < 6) {
            return res.status(400).json({ error: 'Token dan password baru diperlukan.' });
        }

        const result = await pool.query(
            'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
            [token]
        );
        const user = result.rows[0];
        
        if (!user) {
            return res.status(400).json({ error: 'Token tidak valid atau sudah kedaluwarsa.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
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

// === ROUTES URL SHORTENER ===

app.post('/api/shorten', authenticateToken, async (req, res) => {
    try {
        const { original_url, custom_slug } = req.body;
        const userId = req.user.id; 

        if (!original_url || !(original_url.startsWith('http://') || original_url.startsWith('https://'))) {
            return res.status(400).json({ error: 'URL tidak valid. Harus diawali dengan http:// atau https://' });
        }

        let slug;

        if (custom_slug) {
            const slugRegex = /^[a-zA-Z0-9-]+$/;
            if (!slugRegex.test(custom_slug)) {
                return res.status(400).json({ error: 'Nama kustom hanya boleh berisi huruf, angka, dan tanda hubung (-).' });
            }

            const existingLink = await pool.query('SELECT slug FROM links WHERE slug = $1', [custom_slug]);
            if (existingLink.rows.length > 0) {
                return res.status(409).json({ error: 'Nama kustom ini sudah digunakan. Silakan coba yang lain.' });
            }
            slug = custom_slug;
        } else {
            slug = generateSlug();
        }
        
        const newLink = await pool.query(
            'INSERT INTO links (original_url, slug, user_id) VALUES ($1, $2, $3) RETURNING slug, original_url, created_at',
            [original_url, slug, userId]
        );

        const baseUrl = process.env.BASE_URL || `https://${req.get('host')}`;
        const fullShortUrl = `${baseUrl}/${newLink.rows[0].slug}`;

        res.status(201).json({ 
            short_url: fullShortUrl,
            link_data: newLink.rows[0] 
        });

    } catch (error) {
        console.error("Error saat membuat link pendek:", error);
        res.status(500).json({ error: 'Gagal membuat link pendek di server.' });
    }
});

app.get('/api/user/links', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await pool.query(
            'SELECT slug, original_url, created_at FROM links WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error mengambil riwayat link pengguna:', error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

// === ROUTES ADMIN ===
app.get('/api/links', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT slug, original_url, created_at FROM links ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error mengambil semua link:', error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

app.delete('/api/links/:slug', authenticateAdmin, async (req, res) => {
    try {
        const { slug } = req.params;
        const result = await pool.query('DELETE FROM links WHERE slug = $1 RETURNING slug', [slug]);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Link dengan slug tersebut tidak ditemukan.' });
        }

        res.json({ message: `Link dengan slug '${slug}' berhasil dihapus.` });
    } catch (error) {
        console.error('Error menghapus link:', error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

// === ROUTE PENGALIHAN URL (diletakkan paling akhir) ===
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
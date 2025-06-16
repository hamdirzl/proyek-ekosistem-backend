// =================================================================
// ==      FILE FINAL: server.js (dengan PostgreSQL)      ==
// =================================================================

const express = require('express');
const cors = require('cors');
const bcrypt = 'bcrypt';
const jwt = require('jsonwebtoken');
const { Pool } = require('pg'); // <-- Menggunakan library 'pg'

// === KONFIGURASI DATABASE ===
// Menghubungkan ke database PostgreSQL menggunakan URL dari Environment Variable
// Saat di Render, process.env.DATABASE_URL akan terisi otomatis.
// Untuk testing lokal, kita akan mengaturnya nanti.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Baris ini penting saat deploy di Render
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = 'ini-adalah-kunci-rahasia-yang-sangat-aman-dan-panjang';

function generateSlug() { return Math.random().toString(36).substring(2, 8); }

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
// Render akan mengatur PORT secara dinamis
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// === ROUTES (Sudah diadaptasi untuk PostgreSQL) ===

app.get('/', (req, res) => res.send('Halo dari Backend Server Node.js! Terhubung ke PostgreSQL.'));

app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Input tidak valid.' });

        const passwordHash = await bcrypt.hash(password, 10);
        // Sintaks SQL untuk PostgreSQL menggunakan $1, $2, dst. sebagai placeholder
        const newUser = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
            [email, passwordHash]
        );
        // Hasil dari 'pg' ada di dalam property 'rows'
        res.status(201).json({ message: 'Pengguna berhasil dibuat!', user: newUser.rows[0] });
    } catch (error) {
        // Kode error untuk duplikat di PostgreSQL adalah '23505'
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

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login berhasil!', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
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

// ============== KODE BARU UNTUK MEMBUAT LINK PENDEK ==============
app.post('/api/shorten', async (req, res) => {
    try {
        const { original_url } = req.body;

        // Validasi sederhana untuk memastikan URL dikirim dan valid
        if (!original_url || !(original_url.startsWith('http://') || original_url.startsWith('https://'))) {
            return res.status(400).json({ error: 'URL tidak valid. Harus diawali dengan http:// atau https://' });
        }

        const slug = generateSlug(); // Menggunakan fungsi yang sudah ada

        // Menyimpan URL asli dan slug baru ke database
        const newLink = await pool.query(
            'INSERT INTO links (original_url, slug) VALUES ($1, $2) RETURNING slug',
            [original_url, slug]
        );

        // Membuat URL pendek yang lengkap untuk dikembalikan ke frontend
        // Contoh: https://server-pribadi-hamdi.onrender.com/abcdef
        const fullShortUrl = `${req.protocol}://${req.get('host')}/${newLink.rows[0].slug}`;

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
            res.status(404).send('Link tidak ditemukan.');
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));
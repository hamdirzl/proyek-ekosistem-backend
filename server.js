// =================================================================
// ==      FILE FINAL: server.js (Backend Lengkap & Fungsional)   ==
// =================================================================

// === IMPOR LIBRARY ===
const express = require('express'); 
const cors = require('cors'); 
const setupDatabase = require('./database.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// === KONSTANTA & KUNCI RAHASIA ===
const JWT_SECRET = 'ini-adalah-kunci-rahasia-yang-sangat-aman-dan-panjang';

// === FUNGSI HELPER ===
function generateSlug() {
    return Math.random().toString(36).substring(2, 8);
}

// === MIDDLEWARE - SANG PENJAGA PINTU ===
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: Bearer TOKEN

    if (token == null) return res.sendStatus(401); // Unauthorized (Tidak ada token)

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden (Token tidak valid/kedaluwarsa)
        
        req.user = user; // Simpan payload pengguna ke object request
        next(); // Lanjutkan ke rute tujuan
    });
}

// === FUNGSI UTAMA (MAIN) ===
async function main() {
    const app = express();
    const PORT = 3000;
    const db = await setupDatabase();

    // === MIDDLEWARE Global ===
    app.use(cors());
    app.use(express.json());

    // === ROUTES (ATURAN LALU LINTAS API) ===

    // --- Rute Publik ---
    app.get('/', (req, res) => {
        res.send('Halo dari Backend Server Node.js! Server ini aktif dan berjalan.');
    });

    app.post('/api/shorten', async (req, res) => {
        try {
            const { original_url } = req.body; 
            if (!original_url) return res.status(400).json({ error: 'URL tidak boleh kosong' });
            
            const slug = generateSlug();
            await db.run('INSERT INTO links (slug, original_url) VALUES (?, ?)', [slug, original_url]);
            const shortUrl = `http://localhost:${PORT}/${slug}`;
            res.status(201).json({ short_url: shortUrl });
        } catch (error) {
            console.error('Gagal membuat link pendek:', error);
            res.status(500).json({ error: 'Terjadi kesalahan pada server' });
        }
    });

    // --- Rute Autentikasi ---
    app.post('/api/register', async (req, res) => {
        try {
            const { email, password } = req.body;
            if (!email || !password) return res.status(400).json({ error: 'Email dan password tidak boleh kosong.' });
            if (password.length < 6) return res.status(400).json({ error: 'Password minimal harus 6 karakter.' });

            const passwordHash = await bcrypt.hash(password, 10);
            await db.run('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, passwordHash]);
            res.status(201).json({ message: 'Pengguna berhasil dibuat!' });
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ error: 'Email sudah terdaftar.' });
            console.error('Gagal registrasi:', error);
            res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
        }
    });

    app.post('/api/login', async (req, res) => {
        try {
            const { email, password } = req.body;
            if (!email || !password) return res.status(400).json({ error: 'Email dan password tidak boleh kosong.' });

            const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
            if (!user) return res.status(401).json({ error: 'Email atau password salah.' });

            const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
            if (!isPasswordCorrect) return res.status(401).json({ error: 'Email atau password salah.' });

            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ message: 'Login berhasil!', token: token });
        } catch (error) {
            console.error('Gagal login:', error);
            res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
        }
    });

    // --- Rute Terproteksi (Hanya untuk yang sudah login) ---
    app.get('/api/profile', authenticateToken, (req, res) => {
        res.json({ message: 'Selamat datang di halaman profil!', user: req.user });
    });

    app.post('/api/moods', authenticateToken, async (req, res) => {
        try {
            const { mood_level, notes } = req.body;
            const user_id = req.user.id;
            if (!mood_level || typeof mood_level !== 'number' || mood_level < 1 || mood_level > 5) {
                return res.status(400).json({ error: 'mood_level harus berupa angka antara 1 dan 5.' });
            }
            const result = await db.run('INSERT INTO moods (user_id, mood_level, notes) VALUES (?, ?, ?)', [user_id, mood_level, notes]);
            res.status(201).json({ id: result.lastID, user_id, mood_level, notes });
        } catch (error) {
            console.error('Gagal menyimpan mood:', error);
            res.status(500).json({ error: 'Terjadi kesalahan pada server' });
        }
    });

    app.get('/api/moods', authenticateToken, async (req, res) => {
        try {
            const user_id = req.user.id;
            const moods = await db.all('SELECT id, mood_level, notes, created_at FROM moods WHERE user_id = ? ORDER BY created_at DESC', [user_id]);
            res.json(moods);
        } catch (error) {
            console.error('Gagal mengambil data mood:', error);
            res.status(500).json({ error: 'Terjadi kesalahan pada server' });
        }
    });

    // --- Rute Redirect (diletakkan paling akhir) ---
    app.get('/:slug', async (req, res) => {
        try {
            const slug = req.params.slug;
            if (slug === 'favicon.ico') return res.status(204).send();
            
            const link = await db.get('SELECT original_url FROM links WHERE slug = ?', [slug]);
            if (link) {
                console.log(`Redirecting ${slug} to ${link.original_url}`);
                res.redirect(301, link.original_url);
            } else {
                res.status(404).send('Link tidak ditemukan atau sudah tidak valid.');
            }
        } catch (error) {
            console.error('Gagal melakukan redirect:', error);
            res.status(500).send('Terjadi kesalahan pada server');
        }
    });

    // === MENJALANKAN SERVER ===
    app.listen(PORT, () => {
        console.log(`Server berjalan di http://localhost:${PORT}`);
    });
}

// Panggil fungsi utama untuk menjalankan seluruh proses
main();
// VERSI FINAL - PERBAIKAN PADA RUTE DETAIL JURNAL
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { convert } = require('libreoffice-convert');
const { PDFDocument } = require('pdf-lib');
const QRCode = require('qrcode');
const sharp = require('sharp');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { createClient } = require('@supabase/supabase-js');

// Inisialisasi Supabase Client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// === KONFIGURASI DATABASE ===
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

function generateSlug() { return Math.random().toString(36).substring(2, 8); }

// === KONFIGURASI PENGIRIM EMAIL (NODEMAILER) ===
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// === KONFIGURASI GOOGLE GEMINI API ===
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// === MIDDLEWARE ===
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
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
  ],
  exposedHeaders: ['Content-Disposition', 'X-Original-Size', 'X-Compressed-Size']
}));

app.use(express.json());

// Middleware untuk menyajikan file statis dari folder 'public'
app.use('/public', express.static(path.join(__dirname, 'public')));

const upload = multer({ dest: 'uploads/' });
fs.mkdir('uploads', { recursive: true }).catch(console.error);
fs.mkdir(path.join(__dirname, 'public', 'uploads'), { recursive: true }).catch(console.error); 


// === ROUTES (Bagian ini tidak saya sertakan ulang untuk keringkasan, isinya sama persis dengan file Anda sebelumnya) ===
// ...
// Autentikasi dan Registrasi
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
        const loginTime = new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' });

        pool.query(
            'INSERT INTO login_activity (user_id, ip_address, user_agent) VALUES ($1, $2, $3)',
            [user.id, ipAddress, userAgent]
        ).catch(err => console.error('Gagal mencatat aktivitas login ke DB:', err)); 
        
        try {
            await transporter.sendMail({
                to: user.email,
                from: `"Ekosistem Hamdi" <${process.env.EMAIL_USER}>`,
                subject: 'Pemberitahuan Login Akun Anda',
                html: `<p>Halo,</p>
                       <p>Kami mendeteksi login ke akun Anda (<strong>${user.email}</strong>) pada:</p>
                       <p><strong>Waktu:</strong> ${loginTime} WIB</p>
                       <p><strong>Dari IP Address:</strong> ${ipAddress}</p>
                       <p><strong>Perangkat/Browser:</strong> ${userAgent || 'Tidak diketahui'}</p>
                       <p>Jika ini bukan Anda, segera ubah password Anda atau hubungi admin.</p>
                       <p>Terima kasih,</p>
                       <p>Tim Hamdi Rizal</p>`
            });
            console.log(`Login notification email sent to ${user.email}`);
        } catch (mailError) {
            console.error('Failed to send login notification email:', mailError);
        }

        const userPayload = { id: user.id, email: user.email, role: user.role };
        const accessToken = jwt.sign(userPayload, process.env.JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign(userPayload, process.env.JWT_REFRESH_SECRET, { expiresIn: '90d' });

        await pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

        res.json({ message: 'Login berhasil!', accessToken, refreshToken });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

// ... (semua rute lain yang sudah ada sebelumnya)

// === ROUTES PORTOFOLIO (PUBLIK) ===
app.get('/api/portfolio', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, title, description, image_url, project_link FROM portfolio_projects ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching portfolio projects:', error);
        res.status(500).json({ error: 'Gagal mengambil data portofolio.' });
    }
});

app.get('/api/portfolio/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT id, title, description, image_url, project_link, created_at FROM portfolio_projects WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error(`Error fetching portfolio project with id ${req.params.id}:`, error);
        res.status(500).json({ error: 'Gagal mengambil data proyek.' });
    }
});


// === ROUTES JURNAL (PUBLIK) ===
app.get('/api/jurnal', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, title, content, image_url, created_at FROM journal_entries ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching journal entries:', error);
        res.status(500).json({ error: 'Gagal mengambil data jurnal.' });
    }
});

// ENDPOINT PUBLIK: Mengambil SATU entri jurnal berdasarkan ID
app.get('/api/jurnal/:id', async (req, res) => {
    try {
        const { id } = req.params;
        // PERBAIKAN DI SINI: Mengambil dari tabel 'journal_entries'
        const result = await pool.query('SELECT * FROM journal_entries WHERE id = $1', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Entri jurnal tidak ditemukan.' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error(`Error fetching journal entry with id ${req.params.id}:`, error);
        res.status(500).json({ error: 'Gagal mengambil data entri jurnal.' });
    }
});

// === ROUTES ADMIN (UMUM) ===
app.get('/api/links', authenticateAdmin, async (req, res) => {
    try {
        const { search = '' } = req.query;
        const searchTerm = `%${search}%`;
        
        const result = await pool.query(
            'SELECT slug, original_url, created_at FROM links WHERE slug ILIKE $1 OR original_url ILIKE $1 ORDER BY created_at DESC',
            [searchTerm]
        );
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

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { search = '' } = req.query;
        const searchTerm = `%${search}%`;

        const result = await pool.query(
            'SELECT id, email, role, created_at FROM users WHERE email ILIKE $1 ORDER BY created_at DESC',
            [searchTerm]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching all users for admin:', error);
        res.status(500).json({ error: 'Failed to fetch user list.' });
    }
});

app.put('/api/admin/users/:id/role', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body; 

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role specified.' });
        }

        if (req.user.id == id && role !== 'admin') { 
            return res.status(403).json({ error: 'Admin cannot change their own role to non-admin directly.' });
        }

        const result = await pool.query(
            'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, email, role',
            [role, id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.json({ message: `User ${result.rows[0].email} role updated to ${result.rows[0].role}.`, user: result.rows[0] });

    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ error: 'Failed to update user role.' });
    }
});

app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();

    try {
        if (req.user.id == id) {
            return res.status(403).json({ error: 'Admin cannot delete their own account.' });
        }

        await client.query('BEGIN');
        await client.query('DELETE FROM login_activity WHERE user_id = $1', [id]);
        await client.query('DELETE FROM links WHERE user_id = $1', [id]);
        const result = await client.query('DELETE FROM users WHERE id = $1 RETURNING email', [id]);

        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'User not found.' });
        }

        await client.query('COMMIT');
        res.json({ message: `Pengguna ${result.rows[0].email} dan semua data terkaitnya berhasil dihapus.` });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error deleting user with transaction:', error);
        res.status(500).json({ error: 'Gagal menghapus pengguna karena kesalahan server.' });
    } finally {
        client.release();
    }
});


// === ROUTES ADMIN PORTOFOLIO (SUPABASE) ===
app.get('/api/admin/portfolio', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM portfolio_projects ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching all portfolio projects for admin:', error);
        res.status(500).json({ error: 'Gagal mengambil data portofolio untuk admin.' });
    }
});

app.post('/api/admin/portfolio', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { title, description, project_link } = req.body;
        if (!req.file || !title || !description) {
            if (req.file) await fs.unlink(req.file.path);
            return res.status(400).json({ error: 'Gambar, judul, dan deskripsi wajib diisi.' });
        }

        const fileContent = await fs.readFile(req.file.path);
        const newFileName = `${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
        const filePathInBucket = `public/${newFileName}`;

        const { error: uploadError } = await supabase.storage.from('proyek-hamdi-web-2025').upload(filePathInBucket, fileContent, { contentType: req.file.mimetype });
        if (uploadError) throw uploadError;
        
        await fs.unlink(req.file.path);

        const { data: publicUrlData } = supabase.storage.from('proyek-hamdi-web-2025').getPublicUrl(filePathInBucket);
        
        const newProject = await pool.query(
            'INSERT INTO portfolio_projects (title, description, project_link, image_url, image_public_id, user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [title, description, project_link || null, publicUrlData.publicUrl, filePathInBucket, req.user.id]
        );

        res.status(201).json(newProject.rows[0]);

    } catch (error) {
        console.error('Error creating portfolio project with Supabase:', error);
        if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
        res.status(500).json({ error: 'Gagal membuat proyek portofolio.' });
    }
});

app.put('/api/admin/portfolio/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, project_link } = req.body;
        
        const oldDataResult = await pool.query('SELECT image_url, image_public_id FROM portfolio_projects WHERE id = $1', [id]);
        if (oldDataResult.rows.length === 0) {
            if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
            return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        }
        
        let imageUrl = oldDataResult.rows[0].image_url;
        let imagePath = oldDataResult.rows[0].image_public_id;

        if (req.file) {
            const fileContent = await fs.readFile(req.file.path);
            const newFileName = `${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
            const newFilePath = `public/${newFileName}`;

            const { error: uploadError } = await supabase.storage.from('proyek-hamdi-web-2025').upload(newFilePath, fileContent, { contentType: req.file.mimetype });
            if (uploadError) throw uploadError;

            await fs.unlink(req.file.path);
            
            if (imagePath) {
                await supabase.storage.from('proyek-hamdi-web-2025').remove([imagePath]);
            }
            
            const { data: publicUrlData } = supabase.storage.from('proyek-hamdi-web-2025').getPublicUrl(newFilePath);
            imageUrl = publicUrlData.publicUrl;
            imagePath = newFilePath;
        }

        const updatedProject = await pool.query(
            'UPDATE portfolio_projects SET title = $1, description = $2, project_link = $3, image_url = $4, image_public_id = $5 WHERE id = $6 RETURNING *',
            [title, description, project_link || null, imageUrl, imagePath, id]
        );

        res.json(updatedProject.rows[0]);

    } catch (error) {
        console.error('Error updating portfolio project:', error);
        if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
        res.status(500).json({ error: 'Gagal memperbarui proyek portofolio.' });
    }
});

app.delete('/api/admin/portfolio/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const projectResult = await pool.query('SELECT image_public_id FROM portfolio_projects WHERE id = $1', [id]);
        if (projectResult.rows.length === 0) {
            return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        }
        const imagePath = projectResult.rows[0].image_public_id;

        if (imagePath) {
            const { error: deleteError } = await supabase.storage.from('proyek-hamdi-web-2025').remove([imagePath]);
            if (deleteError) console.error("Supabase delete error (ignoring):", deleteError);
        }

        await pool.query('DELETE FROM portfolio_projects WHERE id = $1', [id]);

        res.status(200).json({ message: 'Proyek berhasil dihapus.' });
    } catch (error) {
        console.error('Error deleting portfolio project:', error);
        res.status(500).json({ error: 'Gagal menghapus proyek portofolio.' });
    }
});


// === ROUTES ADMIN JURNAL (BARU) ===
app.get('/api/admin/jurnal', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM journal_entries ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching journal entries for admin:', error);
        res.status(500).json({ error: 'Gagal mengambil data jurnal.' });
    }
});

app.post('/api/admin/jurnal', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { title, content } = req.body;
        if (!req.file || !title || !content) {
            if (req.file) await fs.unlink(req.file.path);
            return res.status(400).json({ error: 'Gambar, judul, dan konten wajib diisi.' });
        }

        const fileContent = await fs.readFile(req.file.path);
        const newFileName = `jurnal-${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
        const filePathInBucket = `public/${newFileName}`;

        const { error: uploadError } = await supabase.storage.from('proyek-hamdi-web-2025').upload(filePathInBucket, fileContent, { contentType: req.file.mimetype });
        if (uploadError) throw uploadError;
        
        await fs.unlink(req.file.path);

        const { data: publicUrlData } = supabase.storage.from('proyek-hamdi-web-2025').getPublicUrl(filePathInBucket);
        
        const newEntry = await pool.query(
            'INSERT INTO journal_entries (title, content, image_url, image_public_id, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [title, content, publicUrlData.publicUrl, filePathInBucket, req.user.id]
        );

        res.status(201).json(newEntry.rows[0]);

    } catch (error) {
        console.error('Error creating journal entry:', error);
        if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
        res.status(500).json({ error: 'Gagal membuat entri jurnal.' });
    }
});

app.put('/api/admin/jurnal/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content } = req.body;
        
        const oldDataResult = await pool.query('SELECT image_url, image_public_id FROM journal_entries WHERE id = $1', [id]);
        if (oldDataResult.rows.length === 0) {
            if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
            return res.status(404).json({ error: 'Entri jurnal tidak ditemukan.' });
        }
        
        let imageUrl = oldDataResult.rows[0].image_url;
        let imagePath = oldDataResult.rows[0].image_public_id;

        if (req.file) {
            const fileContent = await fs.readFile(req.file.path);
            const newFileName = `jurnal-${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
            const newFilePath = `public/${newFileName}`;

            const { error: uploadError } = await supabase.storage.from('proyek-hamdi-web-2025').upload(newFilePath, fileContent, { contentType: req.file.mimetype });
            if (uploadError) throw uploadError;

            await fs.unlink(req.file.path);
            
            if (imagePath) {
                await supabase.storage.from('proyek-hamdi-web-2025').remove([imagePath]);
            }
            
            const { data: publicUrlData } = supabase.storage.from('proyek-hamdi-web-2025').getPublicUrl(newFilePath);
            imageUrl = publicUrlData.publicUrl;
            imagePath = newFilePath;
        }

        const updatedEntry = await pool.query(
            'UPDATE journal_entries SET title = $1, content = $2, image_url = $3, image_public_id = $4 WHERE id = $5 RETURNING *',
            [title, content, imageUrl, imagePath, id]
        );

        res.json(updatedEntry.rows[0]);

    } catch (error) {
        console.error('Error updating journal entry:', error);
        if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
        res.status(500).json({ error: 'Gagal memperbarui entri jurnal.' });
    }
});

app.delete('/api/admin/jurnal/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const entryResult = await pool.query('SELECT image_public_id FROM journal_entries WHERE id = $1', [id]);
        if (entryResult.rows.length === 0) {
            return res.status(404).json({ error: 'Entri jurnal tidak ditemukan.' });
        }
        const imagePath = entryResult.rows[0].image_public_id;

        if (imagePath) {
            const { error: deleteError } = await supabase.storage.from('proyek-hamdi-web-2025').remove([imagePath]);
            if (deleteError) console.error("Supabase delete error (ignoring):", deleteError);
        }

        await pool.query('DELETE FROM journal_entries WHERE id = $1', [id]);

        res.status(200).json({ message: 'Entri jurnal berhasil dihapus.' });
    } catch (error) {
        console.error('Error deleting journal entry:', error);
        res.status(500).json({ error: 'Gagal menghapus entri jurnal.' });
    }
});

// === ROOT ROUTE DAN WILDCARD ===
app.get('/', (req, res) => res.send('Halo dari Backend Server Node.js! Terhubung ke PostgreSQL.'));

app.get('/:slug', async (req, res) => {
    try {
        const { slug } = req.params;
        const result = await pool.query('SELECT original_url FROM links WHERE slug = $1', [slug]);
        const link = result.rows[0];
        if (link) {
            res.redirect(301, link.original_url);
        } else {
            res.redirect(302, 'https://hamdirzl.my.id');
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));
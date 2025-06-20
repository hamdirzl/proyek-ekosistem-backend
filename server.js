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


// === ROUTES ===

// ... (SEMUA KODE ROUTES DARI /api/register HINGGA /api/chat-with-ai TETAP SAMA SEPERTI SEBELUMNYA)
// ... Tidak perlu disalin ulang jika sudah sama ...

// === ROUTES PORTOFOLIO (FINAL) ===

// ENDPOINT PUBLIK: Mengambil semua proyek portofolio
app.get('/api/portfolio', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, title, description, image_url, project_link FROM portfolio_projects ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching portfolio projects:', error);
        res.status(500).json({ error: 'Gagal mengambil data portofolio.' });
    }
});

// ENDPOINT PUBLIK: Mengambil satu proyek portofolio berdasarkan ID
app.get('/api/portfolio/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT * FROM portfolio_projects WHERE id = $1', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error(`Error fetching project with id ${req.params.id}:`, error);
        res.status(500).json({ error: 'Gagal mengambil data proyek.' });
    }
});

// === ROUTES ADMIN ===
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


// === ROUTES ADMIN PORTOFOLIO (FINAL) ===

// ENDPOINT ADMIN: Mengambil semua proyek untuk manajemen
app.get('/api/admin/portfolio', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM portfolio_projects ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching portfolio for admin:', error);
        res.status(500).json({ error: 'Gagal mengambil data portofolio untuk admin.' });
    }
});

// ENDPOINT ADMIN: Membuat proyek portofolio baru
app.post('/api/admin/portfolio', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { title, description, project_link } = req.body;
        if (!req.file || !title || !description) {
            if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
            return res.status(400).json({ error: 'Gambar, judul, dan deskripsi wajib diisi.' });
        }

        const tempPath = req.file.path;
        const newFileName = `${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
        const publicPath = path.join(__dirname, 'public', 'uploads', newFileName);
        await fs.rename(tempPath, publicPath);
        
        const imageUrl = `/public/uploads/${newFileName}`;

        const newProject = await pool.query(
            'INSERT INTO portfolio_projects (title, description, project_link, image_url, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [title, description, project_link || null, imageUrl, req.user.id]
        );

        res.status(201).json(newProject.rows[0]);

    } catch (error) {
        console.error('Error creating portfolio project:', error);
        if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
        res.status(500).json({ error: 'Gagal membuat proyek portofolio.' });
    }
});

// ENDPOINT ADMIN: Memperbarui proyek portofolio
app.put('/api/admin/portfolio/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, project_link } = req.body;

        const oldDataResult = await pool.query('SELECT image_url FROM portfolio_projects WHERE id = $1', [id]);
        if (oldDataResult.rows.length === 0) {
             if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
            return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        }
        const oldImageUrl = oldDataResult.rows[0].image_url;
        let newImageUrl = oldImageUrl;

        if (req.file) {
            if (oldImageUrl) {
                const oldImagePath = path.join(__dirname, oldImageUrl);
                await fs.unlink(oldImagePath).catch(err => console.log(`Gagal menghapus file lama: ${err.message}`));
            }
            const tempPath = req.file.path;
            const newFileName = `${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
            const publicPath = path.join(__dirname, 'public', 'uploads', newFileName);
            await fs.rename(tempPath, publicPath);
            newImageUrl = `/public/uploads/${newFileName}`;
        }

        const updatedProject = await pool.query(
            'UPDATE portfolio_projects SET title = $1, description = $2, project_link = $3, image_url = $4 WHERE id = $5 RETURNING *',
            [title, description, project_link || null, newImageUrl, id]
        );

        res.json(updatedProject.rows[0]);
    } catch (error) {
        console.error('Error updating portfolio project:', error);
         if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
        res.status(500).json({ error: 'Gagal memperbarui proyek portofolio.' });
    }
});

// ENDPOINT ADMIN: Menghapus proyek portofolio
app.delete('/api/admin/portfolio/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const projectResult = await pool.query('SELECT image_url FROM portfolio_projects WHERE id = $1', [id]);
        if (projectResult.rows.length === 0) {
            return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        }
        const imageUrl = projectResult.rows[0].image_url;
        
        await pool.query('DELETE FROM portfolio_projects WHERE id = $1', [id]);

        if (imageUrl) {
            const imagePath = path.join(__dirname, imageUrl);
            await fs.unlink(imagePath).catch(err => console.log(`Gagal menghapus file: ${err.message}`));
        }

        res.status(200).json({ message: 'Proyek berhasil dihapus.' });
    } catch (error) {
        console.error('Error deleting portfolio project:', error);
        res.status(500).json({ error: 'Gagal menghapus proyek portofolio.' });
    }
});

// === ROOT ROUTE ===
app.get('/', (req, res) => res.send('Halo dari Backend Server Node.js! Terhubung ke PostgreSQL.'));

// === WILDCARD REDIRECT ROUTE ===
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
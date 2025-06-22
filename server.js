// VERSI FINAL DENGAN INTEGRASI SUPABASE STORAGE (NAMA BUCKET SUDAH DIPERBAIKI)
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
const sanitizeHtml = require('sanitize-html');

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
fs.mkdir(path.join(__dirname, 'public', 'uploads'), { recursive: true }).catch(console.error); // Pastikan folder public ada


// === ROUTES ===

// ... (Rute autentikasi dari register hingga reset-password tetap sama persis)
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

app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        await pool.query('UPDATE users SET refresh_token = NULL WHERE id = $1', [userId]);
        res.status(200).json({ message: 'Logout berhasil.' });
    } catch (error) {
        console.error("Error logging out:", error);
        res.status(500).json({ error: 'Gagal melakukan logout.' });
    }
});

app.post('/api/refresh-token', async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(401).json({ error: 'Refresh token tidak ada.' });

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE refresh_token = $1', [token]);
        const user = userResult.rows[0];
        if (!user) return res.status(403).json({ error: 'Refresh token tidak valid.' });

        jwt.verify(token, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
            if (err) return res.status(403).json({ error: 'Refresh token kedaluwarsa atau tidak valid.' });
            
            const userPayload = { id: decoded.id, email: decoded.email, role: decoded.role };
            const newAccessToken = jwt.sign(userPayload, process.env.JWT_SECRET, { expiresIn: '15m' });
            
            res.json({ accessToken: newAccessToken });
        });
    } catch (error) {
        console.error("Error refreshing token:", error);
        res.status(500).json({ error: 'Kesalahan server saat refresh token.' });
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

// === ROUTES PENGGUNA & PERKAKAS ===
// ... (Rute Pengguna & Perkakas lainnya tetap sama)
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

        const baseUrl = process.env.BASE_URL || `https://link.hamdirzl.my.id`;
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

app.delete('/api/user/links/:slug', authenticateToken, async (req, res) => {
    try {
        const { slug } = req.params;
        const userId = req.user.id; 

        const result = await pool.query(
            'DELETE FROM links WHERE slug = $1 AND user_id = $2 RETURNING slug',
            [slug, userId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Tautan tidak ditemukan atau Anda tidak memiliki izin untuk menghapusnya.' });
        }

        res.json({ message: `Tautan dengan slug '${slug}' berhasil dihapus dari riwayat Anda.` });
    } catch (error) {
        console.error('Error menghapus tautan pengguna:', error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server saat menghapus tautan.' });
    }
});

app.get('/api/user/dashboard-stats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const linksResult = await pool.query('SELECT COUNT(*) FROM links WHERE user_id = $1', [userId]);
        const linkCount = parseInt(linksResult.rows[0].count, 10);

        const activityResult = await pool.query(
            'SELECT ip_address, login_timestamp FROM login_activity WHERE user_id = $1 ORDER BY login_timestamp DESC LIMIT 1',
            [userId]
        );
        const lastLogin = activityResult.rows[0];

        res.json({
            linkCount,
            lastLogin: lastLogin ? {
                ip: lastLogin.ip_address,
                time: new Date(lastLogin.login_timestamp).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })
            } : null
        });

    } catch (error) {
        console.error('Error fetching user dashboard stats:', error);
        res.status(500).json({ error: 'Gagal mengambil data dasbor.' });
    }
});

app.post('/api/user/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id;

        if (!currentPassword || !newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Semua kolom wajib diisi dan password baru minimal 6 karakter.' });
        }

        const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
        const user = userResult.rows[0];

        const isPasswordCorrect = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isPasswordCorrect) {
            return res.status(403).json({ error: 'Password saat ini salah.' });
        }

        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newPasswordHash, userId]);

        res.json({ message: 'Password berhasil diperbarui!' });

    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});

app.post('/api/convert', authenticateToken, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Tidak ada file yang diunggah.' });
    const { outputFormat } = req.body;
    if (!outputFormat) {
        await fs.unlink(req.file.path);
        return res.status(400).json({ error: 'Format output tidak dipilih.' });
    }
    const inputPath = req.file.path;
    const outputPath = path.join(__dirname, 'uploads', `${Date.now()}.${outputFormat}`);
    try {
        const fileBuffer = await fs.readFile(inputPath);
        let outputBuffer = await new Promise((resolve, reject) => {
            convert(fileBuffer, `.${outputFormat}`, undefined, (err, result) => {
                if (err) return reject(err);
                resolve(result);
            });
        });
        await fs.writeFile(outputPath, outputBuffer);
        res.download(outputPath, `converted-file.${outputFormat}`, async (err) => {
            if (err) console.error("Error saat mengirim file:", err);
            await fs.unlink(inputPath);
            await fs.unlink(outputPath);
        });
    } catch (error) {
        console.error('Error saat konversi file:', error);
        await fs.unlink(inputPath).catch(err => console.error("Gagal hapus input file saat error:", err));
        res.status(500).json({ error: 'Gagal mengonversi file.' });
    }
});

app.post('/api/convert/images-to-pdf', authenticateToken, upload.array('files', 15), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'Tidak ada file gambar yang diunggah.' });
    }
    const filePaths = req.files.map(file => file.path);
    try {
        const pdfDoc = await PDFDocument.create();
        for (const file of req.files) {
            if (file.mimetype !== 'image/jpeg' && file.mimetype !== 'image/png') continue;
            const imgBuffer = await fs.readFile(file.path);
            let image;
            if (file.mimetype === 'image/jpeg') {
                image = await pdfDoc.embedJpg(imgBuffer);
            } else {
                image = await pdfDoc.embedPng(imgBuffer);
            }
            const page = pdfDoc.addPage([image.width, image.height]);
            page.drawImage(image, { x: 0, y: 0, width: page.getWidth(), height: page.getHeight() });
        }
        const pdfBytes = await pdfDoc.save();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="hasil-gabungan.pdf"');
        res.send(Buffer.from(pdfBytes));
    } catch (error) {
        console.error('Error saat menggabungkan gambar ke PDF:', error);
        res.status(500).json({ error: 'Gagal membuat file PDF.' });
    } finally {
        for (const filePath of filePaths) {
            await fs.unlink(filePath).catch(err => console.error("Gagal menghapus file sementara:", err));
        }
    }
});

app.post('/api/generate-qr', authenticateToken, async (req, res) => {
    try {
        const { text, level = 'M', colorDark = '#000000', colorLight = '#ffffff' } = req.body;

        if (!text) {
            return res.status(400).json({ error: 'Teks atau URL untuk QR code tidak boleh kosong.' });
        }

        const qrOptions = {
            errorCorrectionLevel: level,
            type: 'image/png',
            quality: 0.92,
            margin: 1, 
            color: {
                dark: colorDark,
                light: colorLight
            }
        };

        const qrDataUrl = await QRCode.toDataURL(text, qrOptions);
        res.json({ qrCodeImage: qrDataUrl, message: 'QR Code berhasil dibuat!' });

    } catch (error) {
        console.error('Error generating QR code:', error);
        res.status(500).json({ error: 'Gagal membuat QR Code di server.' });
    }
});

app.post('/api/compress-image', authenticateToken, upload.single('image'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Tidak ada file gambar yang diunggah.' });
    }

    const inputPath = req.file.path;
    const originalSize = req.file.size;
    let { quality = 80, format = 'jpeg' } = req.body;

    quality = parseInt(quality);
    if (isNaN(quality) || quality < 0 || quality > 100) {
        await fs.unlink(inputPath);
        return res.status(400).json({ error: 'Nilai kualitas tidak valid. Harus antara 0 dan 100.' });
    }

    let outputFormat = format;
    if (req.file.mimetype.includes('png') && format === 'jpeg') {
        outputFormat = 'jpeg';
    } else if (req.file.mimetype.includes('jpeg') || req.file.mimetype.includes('jpg')) {
        outputFormat = 'jpeg';
    } else if (req.file.mimetype.includes('png')) {
        outputFormat = 'png';
    } else {
        await fs.unlink(inputPath);
        return res.status(400).json({ error: 'Format gambar tidak didukung (hanya JPG/PNG).' });
    }

    try {
        const imageBuffer = await fs.readFile(inputPath);
        let compressedBuffer;
        let sharpInstance = sharp(imageBuffer);

        if (outputFormat === 'jpeg') {
            compressedBuffer = await sharpInstance.jpeg({ quality: quality }).toBuffer();
        } else if (outputFormat === 'png') {
            compressedBuffer = await sharpInstance.png({ quality: quality }).toBuffer();
        } else {
            throw new Error('Unsupported output format for compression.');
        }
        
        const compressedSize = Buffer.byteLength(compressedBuffer);

        res.set('Content-Type', `image/${outputFormat}`);
        res.set('Content-Disposition', `attachment; filename="compressed-image.${outputFormat}"`);
        res.set('X-Original-Size', originalSize);
        res.set('X-Compressed-Size', compressedSize); 
        res.send(compressedBuffer);

    } catch (error) {
        console.error('Error compressing image:', error);
        res.status(500).json({ error: 'Gagal mengompres gambar di server.' });
    } finally {
        await fs.unlink(inputPath).catch(err => console.error("Gagal menghapus file input sementara:", err));
    }
});

app.post('/api/chat-with-ai', authenticateToken, async (req, res) => {
    try {
        const userMessage = req.body.message;
        const userId = req.user.id; 

        if (!userMessage) {
            return res.status(400).json({ error: 'Pesan tidak boleh kosong.' });
        }

        console.log(`Pesan dari pengguna ${userId}: ${userMessage}`);

        const chat = model.startChat({
            history: [],
            generationConfig: {
                maxOutputTokens: 200,
            },
        });

        const result = await chat.sendMessage(userMessage);
        const response = await result.response;
        const text = response.text();

        res.json({ reply: text });

    } catch (error) {
        console.error('Error calling Gemini API:', error);
        res.status(500).json({ error: 'Terjadi kesalahan saat memproses pesan AI.' });
    }
});

// === ROUTES PORTOFOLIO (PUBLIK) ===

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

// ENDPOINT PUBLIK: Mengambil SATU proyek portofolio berdasarkan ID
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
        const result = await pool.query('SELECT id, title, content, image_url, created_at FROM jurnal_posts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching jurnal posts:', error);
        res.status(500).json({ error: 'Gagal mengambil data jurnal.' });
    }
});

app.get('/api/jurnal/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT id, title, content, image_url, created_at FROM jurnal_posts WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Postingan jurnal tidak ditemukan.' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error(`Error fetching jurnal post with id ${req.params.id}:`, error);
        res.status(500).json({ error: 'Gagal mengambil data postingan jurnal.' });
    }
});


// === ROUTES ADMIN ===
// ... (Rute Admin lainnya seperti /api/links dan /api/admin/users tetap sama)
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


// === ROUTES ADMIN JURNAL (DENGAN FUNGSI BARU) ===

// ENDPOINT ADMIN: Mengambil SEMUA postingan jurnal (UNTUK PANEL ADMIN)
app.get('/api/admin/jurnal', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM jurnal_posts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching all jurnal posts for admin:', error);
        res.status(500).json({ error: 'Gagal mengambil data jurnal untuk admin.' });
    }
});

// ***************************************************************
// === [BARU] ENDPOINT KHUSUS UNTUK UNGGAH GAMBAR DARI EDITOR ===
// ***************************************************************
app.post('/api/admin/jurnal/upload-image', authenticateAdmin, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'File tidak ditemukan.' });
        }
        
        const fileContent = await fs.readFile(req.file.path);
        const newFileName = `jurnal-content/${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
        const filePathInBucket = `public/${newFileName}`;

        const { error: uploadError } = await supabase.storage.from('proyek-hamdi-web-2025').upload(filePathInBucket, fileContent, { contentType: req.file.mimetype });
        if (uploadError) throw uploadError;
        
        await fs.unlink(req.file.path);

        const { data: publicUrlData } = supabase.storage.from('proyek-hamdi-web-2025').getPublicUrl(filePathInBucket);

        // TinyMCE mengharapkan respons JSON dengan properti "location"
        res.json({ location: publicUrlData.publicUrl });

    } catch (error) {
        console.error("Gagal unggah gambar konten jurnal:", error);
        if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
        res.status(500).json({ error: "Gagal mengunggah gambar." });
    }
});


// ENDPOINT ADMIN: Membuat postingan jurnal baru (DIMODIFIKASI)
app.post('/api/admin/jurnal', authenticateAdmin, async (req, res) => {
    try {
        const { title, content } = req.body;
        if (!title || !content) {
            return res.status(400).json({ error: 'Judul dan konten wajib diisi.' });
        }

        let cleanContent = sanitizeHtml(content, { // <-- DIUBAH DARI CONST MENJADI LET
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'strong', 'em', 'u', 'a']),
            allowedAttributes: {
                ...sanitizeHtml.defaults.allowedAttributes,
                'img': ['src', 'alt', 'width', 'height', 'style'],
                'a': ['href', 'target']
            }
        });

        const firstImageMatch = cleanContent.match(/<img[^>]+src="([^">]+)"/);
        const mainImageUrl = firstImageMatch ? firstImageMatch[1] : null;

        const newPost = await pool.query(
            'INSERT INTO jurnal_posts (title, content, image_url, user_id) VALUES ($1, $2, $3, $4) RETURNING *',
            [title, cleanContent, mainImageUrl, req.user.id]
        );

        res.status(201).json(newPost.rows[0]);

    } catch (error) {
        console.error('Error creating jurnal post:', error);
        res.status(500).json({ error: 'Gagal membuat postingan jurnal.' });
    }
});

// ENDPOINT ADMIN: Memperbarui postingan jurnal (DIMODIFIKASI)
app.put('/api/admin/jurnal/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content } = req.body;
        
        let cleanContent = sanitizeHtml(content, { // <-- DIUBAH DARI CONST MENJADI LET
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'strong', 'em', 'u', 'a']),
            allowedAttributes: {
                ...sanitizeHtml.defaults.allowedAttributes,
                'img': ['src', 'alt', 'width', 'height', 'style'],
                'a': ['href', 'target']
            }
        });
        
        const firstImageMatch = cleanContent.match(/<img[^>]+src="([^">]+)"/);
        const mainImageUrl = firstImageMatch ? firstImageMatch[1] : null;

        const updatedPost = await pool.query(
            'UPDATE jurnal_posts SET title = $1, content = $2, image_url = $3 WHERE id = $4 RETURNING *',
            [title, cleanContent, mainImageUrl, id]
        );
        
        if (updatedPost.rows.length === 0) {
            return res.status(404).json({ error: 'Postingan tidak ditemukan.' });
        }

        res.json(updatedPost.rows[0]);

    } catch (error) {
        console.error('Error updating jurnal post:', error);
        res.status(500).json({ error: 'Gagal memperbarui postingan jurnal.' });
    }
});


// ENDPOINT ADMIN: Menghapus postingan jurnal (Tetap sama, tapi perlu diingat gambar di konten tidak terhapus dari Supabase)
app.delete('/api/admin/jurnal/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Perhatikan: Logika ini hanya menghapus record dari DB.
        // Gambar yang di-embed dalam konten tidak akan terhapus dari Supabase Storage.
        // Menghapusnya memerlukan parsing HTML dan iterasi, yang cukup kompleks.
        const result = await pool.query('DELETE FROM jurnal_posts WHERE id = $1 RETURNING id', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Postingan tidak ditemukan.' });
        }

        res.status(200).json({ message: 'Postingan jurnal berhasil dihapus.' });
    } catch (error) {
        console.error('Error deleting jurnal post:', error);
        res.status(500).json({ error: 'Gagal menghapus postingan jurnal.' });
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
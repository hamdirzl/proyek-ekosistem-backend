// VERSI FINAL DAN LENGKAP - DENGAN SEMUA PERBAIKAN + FITUR CHAT GAMBAR/SUARA
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt =require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const multer = require('multer');
const fs = require('fs').promises;
const fsStream = require('fs');
const path = require('path');
const { convert } = require('libreoffice-convert');
const QRCode = require('qrcode');
const sharp = require('sharp');
const { createClient } = require('@supabase/supabase-js');
const sanitizeHtml = require('sanitize-html');
const http = require('http');
const WebSocket = require('ws');
const axios = require('axios');
const { OAuth2Client } = require('google-auth-library');
const FormData = require('form-data');
const PDFDocumentKit = require('pdfkit');
const { PDFDocument } = require('pdf-lib');
const archiver = require('archiver');

// Inisialisasi Supabase Client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = `${process.env.API_BASE_URL}/api/auth/google/callback`; // Gunakan variabel dari .env

const googleClient = new OAuth2Client(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    REDIRECT_URI
);

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

// FUNGSI UNTUK NOTIFIKASI TELEGRAM
async function sendTelegramNotification(message) {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    if (!token || !chatId) {
        console.log('Token atau Chat ID Telegram tidak diatur, notifikasi dilewati.');
        return;
    }
    const url = `https://api.telegram.org/bot${token}/sendMessage`;
    try {
        await axios.post(url, {
            chat_id: chatId,
            text: message,
        });
        console.log('Notifikasi Telegram terkirim!');
    } catch (error) {
        console.error('Gagal mengirim notifikasi Telegram:', error.response ? error.response.data : error.message);
    }
}

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

const allowedOrigins = [
    'https://hamdirzl.my.id', 
    'https://www.hamdirzl.my.id', 
    'https://hrportof.netlify.app'
  ];

app.use(cors({
  origin: allowedOrigins,
  exposedHeaders: ['Content-Disposition', 'X-Original-Size', 'X-Compressed-Size']
}));


app.use(express.json({ limit: '50mb' })); // Naikkan limit untuk menampung array gambar
app.use(express.urlencoded({ limit: '50mb', extended: true }));


app.use('/public', express.static(path.join(__dirname, 'public')));

const upload = multer({ dest: 'uploads/' });
fs.mkdir('uploads', { recursive: true }).catch(console.error);
fs.mkdir(path.join(__dirname, 'public', 'uploads'), { recursive: true }).catch(console.error);

// === ROUTES (Semua app.get, app.post, dll) ===
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

app.post('/api/shorten', async (req, res) => {
    try {
        const { original_url, custom_slug } = req.body;
        
        let userId = null;
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token) {
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                userId = decoded.id;
            } catch (e) {
                console.log('Token tidak valid untuk /api/shorten, memproses sebagai tamu.');
            }
        }

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

         pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['URL Shortener']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));

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

app.post('/api/convert', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Tidak ada file yang diunggah.' });
    }

    const { outputFormat } = req.body;
    const inputPath = req.file.path;
    const inputFormat = path.extname(req.file.originalname).slice(1).toLowerCase();

    // Prioritas 1: Konversi Gambar ke Gambar menggunakan Sharp (efisien)
    const imageFormats = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'tiff'];
    if (imageFormats.includes(inputFormat) && imageFormats.includes(outputFormat)) {
        console.log('Mendeteksi konversi gambar, menggunakan Sharp...');
        try {
            const outputBuffer = await sharp(inputPath).toFormat(outputFormat).toBuffer();
            pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['Media Converter']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));
            res.set('Content-Type', `image/${outputFormat}`);
            res.set('Content-Disposition', `attachment; filename="converted-image.${outputFormat}"`);
            res.send(outputBuffer);
        } catch (error) {
            console.error('Error dengan Sharp:', error);
            res.status(500).json({ error: 'Gagal mengonversi gambar.' });
        } finally {
            await fs.unlink(inputPath);
        }
        return;
    }

    // Prioritas 2: Konversi PDF ke DOCX menggunakan CloudConvert
    if (inputFormat === 'pdf' && outputFormat === 'docx') {
        console.log('Mendeteksi konversi PDF -> DOCX, menggunakan CloudConvert API...');
        let importTask = null;
        try {
            const importResponse = await axios.post('https://api.cloudconvert.com/v2/import/upload', {}, {
                headers: { 'Authorization': `Bearer ${process.env.CLOUDCONVERT_API_KEY}` }
            });
            importTask = importResponse.data.data;

            const uploadFormData = new FormData();
            Object.entries(importTask.result.form.parameters).forEach(([key, value]) => {
                uploadFormData.append(key, value);
            });
            uploadFormData.append('file', fsStream.createReadStream(inputPath), { filename: req.file.originalname });
            
            await axios.post(importTask.result.form.url, uploadFormData, {
                headers: uploadFormData.getHeaders()
            });

            let updatedImportTask = importTask;
            while (updatedImportTask.status !== 'finished' && updatedImportTask.status !== 'error') {
                 await new Promise(resolve => setTimeout(resolve, 1000));
                 const taskStatusResponse = await axios.get(`https://api.cloudconvert.com/v2/tasks/${importTask.id}`, {
                     headers: { 'Authorization': `Bearer ${process.env.CLOUDCONVERT_API_KEY}` }
                 });
                 updatedImportTask = taskStatusResponse.data.data;
            }

            if (updatedImportTask.status === 'error') {
                throw new Error(updatedImportTask.message || 'Gagal mengunggah file ke CloudConvert.');
            }
             
            const jobResponse = await axios.post('https://api.cloudconvert.com/v2/jobs', {
                tasks: {
                    'convert-the-file': {
                        operation: 'convert',
                        input: importTask.id,
                        output_format: 'docx'
                    },
                    'export-the-file': {
                        operation: 'export/url',
                        input: 'convert-the-file'
                    }
                }
            }, {
                headers: { 'Authorization': `Bearer ${process.env.CLOUDCONVERT_API_KEY}` }
            });

            let conversionJob = jobResponse.data.data;
            while (conversionJob.status !== 'finished' && conversionJob.status !== 'error') {
                await new Promise(resolve => setTimeout(resolve, 2000));
                const jobStatusResponse = await axios.get(`https://api.cloudconvert.com/v2/jobs/${conversionJob.id}`, {
                    headers: { 'Authorization': `Bearer ${process.env.CLOUDCONVERT_API_KEY}` }
                });
                conversionJob = jobStatusResponse.data.data;
            }

            if (conversionJob.status === 'error') {
                throw new Error(conversionJob.tasks.find(t => t.status === 'error')?.message || 'Job konversi gagal.');
            }

            const exportTask = conversionJob.tasks.find(task => task.name === 'export-the-file');
            const downloadUrl = exportTask.result.files[0].url;
            
            const convertedFileResponse = await axios.get(downloadUrl, { responseType: 'arraybuffer' });
            pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['Media Converter']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));
            
            res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
            res.setHeader('Content-Disposition', `attachment; filename="converted_${path.basename(req.file.originalname, '.pdf')}.docx"`);
            res.send(Buffer.from(convertedFileResponse.data));

        } catch (error) {
            console.error('Error dengan CloudConvert API:', error.response ? error.response.data : error.message);
            res.status(500).json({ error: 'Gagal mengonversi file menggunakan layanan cloud.' });
        } finally {
             await fs.unlink(inputPath);
        }
        return;
    }

    // Prioritas 3 (Fallback): Gunakan LibreOffice untuk sisanya
    console.log(`Menggunakan konverter LibreOffice untuk ${inputFormat} -> ${outputFormat}...`);
    try {
        const fileBuffer = await fs.readFile(inputPath);
        let outputBuffer = await new Promise((resolve, reject) => {
            convert(fileBuffer, `.${outputFormat}`, undefined, (err, result) => {
                if (err) return reject(err);
                resolve(result);
            });
        });
        
        const mimeTypes = {
            pdf: 'application/pdf',
            docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        };

        pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['Media Converter']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));

        res.setHeader('Content-Type', mimeTypes[outputFormat] || 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="converted-file.${outputFormat}"`);
        res.send(outputBuffer);

    } catch (error) {
        console.error('Error saat konversi file dengan LibreOffice:', error);
        res.status(500).json({ error: `Konversi dari ${inputFormat} ke ${outputFormat} tidak didukung.` });
    } finally {
        await fs.unlink(inputPath);
    }
});

app.post('/api/generate-qr', async (req, res) => {
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
        pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['QR Code Generator']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));
        res.json({ qrCodeImage: qrDataUrl, message: 'QR Code berhasil dibuat!' });

    } catch (error) {
        console.error('Error generating QR code:', error);
        res.status(500).json({ error: 'Gagal membuat QR Code di server.' });
    }
});

app.post('/api/compress-image', upload.single('image'), async (req, res) => {
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

        pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['Image Compressor']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));

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

// [BARU] ENDPOINT UNTUK KONVERSI GAMBAR KE PDF
app.post('/api/images-to-pdf', upload.array('images'), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'Tidak ada gambar yang diunggah.' });
    }

    try {
        const {
            pageSize = 'A4',
            orientation = 'portrait',
            marginChoice = 'no_margin'
        } = req.body;

        // Tentukan margin berdasarkan pilihan
        let marginSize = 0;
        if (marginChoice === 'small') {
            marginSize = 36; // 0.5 inch
        } else if (marginChoice === 'big') {
            marginSize = 72; // 1 inch
        }

        // Atur opsi dokumen PDF
        const doc = new PDFDocumentKit({
            size: pageSize,
            layout: orientation,
            autoFirstPage: false, // Kita akan menambah halaman secara manual
            margins: {
                top: marginSize,
                bottom: marginSize,
                left: marginSize,
                right: marginSize
            }
        });

        // Atur header respons agar browser mengunduh file
        const outputFileName = `hamdirzl-images-to-pdf-${Date.now()}.pdf`;
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${outputFileName}"`);

        // Alirkan output PDF langsung ke respons
        doc.pipe(res);

        // Loop melalui setiap file gambar yang diunggah
        for (const file of req.files) {
            try {
                const image = doc.openImage(file.path);

                // Tambah halaman baru untuk setiap gambar
                doc.addPage();
                
                // Hitung area yang tersedia di halaman (ukuran halaman dikurangi margin)
                const availableWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
                const availableHeight = doc.page.height - doc.page.margins.top - doc.page.margins.bottom;

                // Skalakan gambar agar pas di dalam area yang tersedia sambil menjaga rasio aspek
                doc.image(image, doc.page.margins.left, doc.page.margins.top, {
                    fit: [availableWidth, availableHeight],
                    align: 'center',
                    valign: 'center'
                });
            } catch (imgError) {
                console.warn(`Melewatkan file yang tidak didukung atau rusak: ${file.originalname}`, imgError);
                // Tambahkan halaman dengan pesan error jika gambar tidak bisa diproses
                doc.addPage()
                   .fillColor('red')
                   .text(`Error: Gagal memproses gambar "${file.originalname}". File mungkin rusak atau format tidak didukung.`, doc.page.margins.left, doc.page.margins.top);
            } finally {
                // Hapus file sementara setelah diproses
                await fs.unlink(file.path);
            }
        }

        pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['Images to PDF']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));

        // Finalisasi dokumen PDF
        doc.end();

    } catch (error) {
        console.error('Error saat membuat PDF:', error);
        res.status(500).json({ error: 'Gagal membuat file PDF di server.' });
        // Pastikan semua file sementara dihapus jika terjadi error
        for (const file of req.files) {
            await fs.unlink(file.path).catch(e => console.error("Gagal hapus file temp saat error:", e));
        }
    }
});

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
        const result = await pool.query('SELECT * FROM portfolio_projects WHERE id = $1', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        }

        res.json(result.rows[0]);

    } catch (error) {
        console.error(`Error fetching portfolio project with id ${req.params.id}:`, error);
        res.status(500).json({ error: 'Gagal mengambil data proyek.' });
    }
});

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

app.get('/api/admin/portfolio', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM portfolio_projects ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching all portfolio projects for admin:', error);
        res.status(500).json({ error: 'Gagal mengambil data portofolio untuk admin.' });
    }
});

app.post('/api/admin/portfolio', authenticateAdmin, async (req, res) => {
    try {
        const { title, description } = req.body;
        if (!title || !description) {
            return res.status(400).json({ error: 'Judul dan deskripsi wajib diisi.' });
        }
        
        const cleanContent = sanitizeHtml(description, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'strong', 'em', 'u', 'a']),
            allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, 'img': ['src', 'alt', 'width', 'height', 'style'], 'a': ['href', 'target'] }
        });

        const firstImageMatch = cleanContent.match(/<img[^>]+src="([^">]+)"/);
        const mainImageUrl = firstImageMatch ? firstImageMatch[1] : null;

        const newProject = await pool.query(
            'INSERT INTO portfolio_projects (title, description, image_url, user_id) VALUES ($1, $2, $3, $4) RETURNING *',
            [title, cleanContent, mainImageUrl, req.user.id]
        );

        res.status(201).json(newProject.rows[0]);

    } catch (error) {
        console.error('Error creating portfolio project:', error);
        res.status(500).json({ error: 'Gagal membuat proyek portofolio.' });
    }
});

app.put('/api/admin/portfolio/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description } = req.body;
        
        const cleanContent = sanitizeHtml(description, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'strong', 'em', 'u', 'a']),
            allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, 'img': ['src', 'alt', 'width', 'height', 'style'], 'a': ['href', 'target'] }
        });
        
        const firstImageMatch = cleanContent.match(/<img[^>]+src="([^">]+)"/);
        const mainImageUrl = firstImageMatch ? firstImageMatch[1] : null;

        const updatedProject = await pool.query(
            'UPDATE portfolio_projects SET title = $1, description = $2, image_url = $3 WHERE id = $4 RETURNING *',
            [title, cleanContent, mainImageUrl, id]
        );
        
        if (updatedProject.rows.length === 0) {
            return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        }

        res.json(updatedProject.rows[0]);

    } catch (error) {
        console.error('Error updating portfolio project:', error);
        res.status(500).json({ error: 'Gagal memperbarui proyek portofolio.' });
    }
});

app.delete('/api/admin/portfolio/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM portfolio_projects WHERE id = $1 RETURNING id', [id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Proyek tidak ditemukan.' });
        res.status(200).json({ message: 'Proyek berhasil dihapus.' });
    } catch (error) {
        console.error('Error deleting portfolio project:', error);
        res.status(500).json({ error: 'Gagal menghapus proyek portofolio.' });
    }
});

app.get('/api/admin/jurnal', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM jurnal_posts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching all jurnal posts for admin:', error);
        res.status(500).json({ error: 'Gagal mengambil data jurnal untuk admin.' });
    }
});

app.post('/api/admin/jurnal/upload-image', authenticateAdmin, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'File tidak ditemukan.' });
        
        const fileContent = await fs.readFile(req.file.path);
        const newFileName = `jurnal-content/${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
        const filePathInBucket = `public/${newFileName}`;

        const { error: uploadError } = await supabase.storage.from('proyek-hamdi-web-2025').upload(filePathInBucket, fileContent, { contentType: req.file.mimetype });
        if (uploadError) throw uploadError;
        
        await fs.unlink(req.file.path);

        const { data: publicUrlData } = supabase.storage.from('proyek-hamdi-web-2025').getPublicUrl(filePathInBucket);
        res.json({ location: publicUrlData.publicUrl });

    } catch (error) {
        console.error("Gagal unggah gambar konten jurnal:", error);
        if (req.file) await fs.unlink(req.file.path).catch(err => console.error(err));
        res.status(500).json({ error: "Gagal mengunggah gambar." });
    }
});

app.post('/api/admin/jurnal', authenticateAdmin, async (req, res) => {
    try {
        const { title, content } = req.body;
        if (!title || !content) return res.status(400).json({ error: 'Judul dan konten wajib diisi.' });

        const cleanContent = sanitizeHtml(content, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'strong', 'em', 'u', 'a']),
            allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, 'img': ['src', 'alt', 'width', 'height', 'style'], 'a': ['href', 'target'] }
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

app.put('/api/admin/jurnal/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content } = req.body;
        
        const cleanContent = sanitizeHtml(content, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'strong', 'em', 'u', 'a']),
            allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, 'img': ['src', 'alt', 'width', 'height', 'style'], 'a': ['href', 'target'] }
        });
        
        const firstImageMatch = cleanContent.match(/<img[^>]+src="([^">]+)"/);
        const mainImageUrl = firstImageMatch ? firstImageMatch[1] : null;

        const updatedPost = await pool.query(
            'UPDATE jurnal_posts SET title = $1, content = $2, image_url = $3 WHERE id = $4 RETURNING *',
            [title, cleanContent, mainImageUrl, id]
        );
        
        if (updatedPost.rows.length === 0) return res.status(404).json({ error: 'Postingan tidak ditemukan.' });
        res.json(updatedPost.rows[0]);

    } catch (error) {
        console.error('Error updating jurnal post:', error);
        res.status(500).json({ error: 'Gagal memperbarui postingan jurnal.' });
    }
});

app.delete('/api/admin/jurnal/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM jurnal_posts WHERE id = $1 RETURNING id', [id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Postingan tidak ditemukan.' });
        res.status(200).json({ message: 'Postingan jurnal berhasil dihapus.' });
    } catch (error) {
        console.error('Error deleting jurnal post:', error);
        res.status(500).json({ error: 'Gagal menghapus postingan jurnal.' });
    }
});

app.get('/api/admin/chat/conversations', authenticateAdmin, async (req, res) => {
    try {
        const query = `
            WITH latest_messages AS (
                SELECT 
                    conversation_id,
                    content,
                    message_type,
                    created_at,
                    ROW_NUMBER() OVER(PARTITION BY conversation_id ORDER BY created_at DESC) as rn
                FROM chat_messages
            )
            SELECT 
                s.conversation_id,
                s.user_name,
                lm.content AS last_message,
                lm.message_type AS last_message_type,
                lm.created_at AS last_message_time
            FROM chat_sessions s
            LEFT JOIN latest_messages lm ON s.conversation_id = lm.conversation_id AND lm.rn = 1
            ORDER BY lm.created_at DESC NULLS LAST;
        `;

        const result = await pool.query(query);

        const conversationsWithStatus = result.rows.map(convo => ({
            ...convo,
            is_online: clients.has(convo.conversation_id)
        }));

        res.json(conversationsWithStatus);
    } catch (error) {
        console.error('Error fetching conversations for admin:', error);
        res.status(500).json({ error: 'Gagal mengambil daftar percakapan.' });
    }
});

// [BARU] ENDPOINT UNTUK UPLOAD FILE CHAT
app.post('/api/chat/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'File tidak ditemukan.' });
        }

        const fileContent = await fs.readFile(req.file.path);
        // Simpan di folder khusus untuk lampiran chat
        const newFileName = `chat-attachments/${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`;
        const filePathInBucket = `public/${newFileName}`;

        // Menggunakan bucket yang sama, tetapi dengan path folder yang berbeda
        const { error: uploadError } = await supabase.storage
            .from('proyek-hamdi-web-2025')
            .upload(filePathInBucket, fileContent, {
                contentType: req.file.mimetype
            });
            
        if (uploadError) {
            throw uploadError;
        }

        // Hapus file sementara setelah diunggah
        await fs.unlink(req.file.path);

        // Dapatkan URL publik dari file yang baru diunggah
        const { data: publicUrlData } = supabase.storage
            .from('proyek-hamdi-web-2025')
            .getPublicUrl(filePathInBucket);
            
        res.json({ location: publicUrlData.publicUrl });

    } catch (error) {
        console.error("Gagal unggah file chat:", error);
        if (req.file) {
            await fs.unlink(req.file.path).catch(err => console.error("Gagal hapus file temp saat error:", err));
        }
        res.status(500).json({ error: "Gagal mengunggah file ke server." });
    }
});

app.get('/api/admin/chat/history/:conversationId', authenticateAdmin, async (req, res) => {
    try {
        const { conversationId } = req.params;
        const result = await pool.query(
            'SELECT * FROM chat_messages WHERE conversation_id = $1 ORDER BY created_at ASC',
            [conversationId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching chat history:', error);
        res.status(500).json({ error: 'Gagal mengambil riwayat percakapan.' });
    }
});

app.post('/api/telegram/webhook', async (req, res) => { // Tambahkan async di sini
    const { message } = req.body;
    const token = process.env.TELEGRAM_BOT_TOKEN;

    // Pastikan ini adalah pesan balasan dari admin
    if (message && message.reply_to_message && message.chat.id.toString() === process.env.TELEGRAM_CHAT_ID) {
        
        const originalText = message.reply_to_message.text;
        const match = originalText.match(/ID: ([\w-]+)/);

        if (match && match[1]) {
            const targetUserId = match[1];
            let content;
            let messageType;

            try {
                // Langkah 1: Deteksi tipe pesan dan dapatkan kontennya
                if (message.text) {
                    messageType = 'text';
                    content = message.text;
                } else if (message.photo) {
                    // Jika foto, ambil file_id dari resolusi tertinggi
                    const file_id = message.photo[message.photo.length - 1].file_id;
                    messageType = 'image';
                    
                    // Langkah 2: Dapatkan path file dari API Telegram
                    const fileResponse = await axios.get(`https://api.telegram.org/bot${token}/getFile?file_id=${file_id}`);
                    const file_path = fileResponse.data.result.file_path;
                    
                    // Langkah 3: Bangun URL file lengkapnya
                    content = `https://api.telegram.org/file/bot${token}/${file_path}`;

                } else if (message.voice) {
                    const file_id = message.voice.file_id;
                    messageType = 'audio';

                    const fileResponse = await axios.get(`https://api.telegram.org/bot${token}/getFile?file_id=${file_id}`);
                    const file_path = fileResponse.data.result.file_path;
                    content = `https://api.telegram.org/file/bot${token}/${file_path}`;
                }

                // Jika ada konten yang berhasil didapat
                if (content && messageType) {
                    const clientData = clients.get(targetUserId);

                    // Kirim ke pengguna melalui WebSocket
                    if (clientData && clientData.ws.readyState === WebSocket.OPEN) {
                        clientData.ws.send(JSON.stringify({ type: 'status_update', status: 'terhubung' }));
                        clientData.ws.send(JSON.stringify({
                            type: 'chat',
                            sender: 'admin',
                            content: content,
                            messageType: messageType // Gunakan tipe dinamis
                        }));
                        console.log(`Balasan [${messageType}] dari Telegram untuk ${targetUserId} berhasil diteruskan.`);
                    } else {
                        console.log(`Gagal meneruskan balasan [${messageType}], pengunjung ${targetUserId} sudah offline.`);
                    }

                    // Simpan ke database dengan tipe yang benar
                    pool.query(
                        'INSERT INTO chat_messages (conversation_id, sender_id, sender_type, content, message_type) VALUES ($1, $2, $3, $4, $5)',
                        [targetUserId, 'admin', 'admin', content, messageType]
                    ).catch(err => console.error("Gagal simpan balasan admin dari Telegram ke DB:", err));
                }

            } catch (error) {
                console.error("Gagal memproses balasan dari Telegram:", error.message);
            }
        } else {
             console.log("Webhook diterima, tapi bukan format balasan yang diharapkan.");
        }
    }

    res.sendStatus(200); // Selalu kirim status 200 OK ke Telegram
});

app.get('/', (req, res) => res.send('Halo dari Backend Server Node.js! Terhubung ke PostgreSQL.'));

app.get('/api/chat/history/:conversationId', async (req, res) => {
    try {
        const { conversationId } = req.params;
        if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(conversationId)) {
            return res.status(400).json({ error: 'Format ID percakapan tidak valid.' });
        }
        const result = await pool.query(
            'SELECT sender_type, content, created_at, message_type FROM chat_messages WHERE conversation_id = $1 ORDER BY created_at ASC',
            [conversationId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching public chat history:', error);
        res.status(500).json({ error: 'Gagal mengambil riwayat percakapan.' });
    }
});

app.post('/api/split-pdf', upload.single('pdfFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Tidak ada file PDF yang diunggah.' });
    }

    // Dapatkan path file sementara dari multer
    const inputPath = req.file.path;

    try {
        const { ranges, mode = 'extract' } = req.body;
        
        if (!ranges) {
            return res.status(400).json({ error: 'Rentang halaman tidak ditentukan.' });
        }

        // --- PERBAIKAN: Baca file dari path, bukan dari buffer ---
        const pdfBuffer = await fs.readFile(inputPath);
        const pdfDoc = await PDFDocument.load(pdfBuffer);
        const totalPages = pdfDoc.getPageCount();

        // Logika parsing rentang (tetap sama)
        const pagesToProcess = ranges.split(',').reduce((acc, part) => {
            part = part.trim();
            if (part.includes('-')) {
                const [start, end] = part.split('-').map(Number);
                if (!isNaN(start) && !isNaN(end) && start <= end) {
                    for (let i = start; i <= end; i++) {
                        if (i > 0 && i <= totalPages) acc.push(i);
                    }
                }
            } else {
                const pageNum = Number(part);
                if (!isNaN(pageNum) && pageNum > 0 && pageNum <= totalPages) {
                    acc.push(pageNum);
                }
            }
            return acc;
        }, []);

        const uniquePages = [...new Set(pagesToProcess)].sort((a, b) => a - b);

        if (uniquePages.length === 0) {
            return res.status(400).json({ error: 'Rentang halaman tidak valid atau di luar jangkauan.' });
        }
        
        // Logika mode 'merge' vs 'extract' (tetap sama)
        if (mode === 'merge') {
            const pageIndices = uniquePages.map(p => p - 1);

            const mergedDoc = await PDFDocument.create();
            const copiedPages = await mergedDoc.copyPages(pdfDoc, pageIndices);
            copiedPages.forEach(page => mergedDoc.addPage(page));
            
            const pdfBytes = await mergedDoc.save();

            pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['Split PDF (Merge)']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));
            
            res.setHeader('Content-Disposition', `attachment; filename="merged-pages.pdf"`);
            res.setHeader('Content-Type', 'application/pdf');
            return res.send(Buffer.from(pdfBytes));

        } else { // mode 'extract' atau default
            // Jika hanya satu halaman, kirim sebagai PDF tunggal (lebih efisien)
            if (uniquePages.length === 1) {
                const pageNum = uniquePages[0];
                const subDoc = await PDFDocument.create();
                const [copiedPage] = await subDoc.copyPages(pdfDoc, [pageNum - 1]);
                subDoc.addPage(copiedPage);
                const pdfBytes = await subDoc.save();

                pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['Split PDF (Extract)']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));

                res.setHeader('Content-Disposition', `attachment; filename="page-${pageNum}.pdf"`);
                res.setHeader('Content-Type', 'application/pdf');
                return res.send(Buffer.from(pdfBytes));
            }

            // Jika lebih dari satu halaman, buat file ZIP
            const archive = archiver('zip', { zlib: { level: 9 } });
            res.setHeader('Content-Type', 'application/zip');
            res.setHeader('Content-Disposition', `attachment; filename=split-pages.zip`);
            archive.pipe(res);

            // Buat PDF untuk setiap halaman dan tambahkan ke ZIP
            for (const pageNum of uniquePages) {
                const subDoc = await PDFDocument.create();
                const [copiedPage] = await subDoc.copyPages(pdfDoc, [pageNum - 1]);
                subDoc.addPage(copiedPage);
                const pdfBytes = await subDoc.save();
                archive.append(Buffer.from(pdfBytes), { name: `page-${pageNum}.pdf` });
            }

            pool.query('INSERT INTO tool_usage (tool_name) VALUES ($1)', ['Split PDF (Extract)']).catch(err => console.error('Gagal mencatat penggunaan tool:', err));
            await archive.finalize();
        }

    } catch (error) {
        console.error('Error splitting PDF:', error);
        // Kirim response error dalam format JSON
        if (!res.headersSent) {
            res.status(500).json({ error: 'Gagal memproses PDF: ' + error.message });
        }
    } finally {
        // --- PERBAIKAN: Selalu hapus file sementara setelah selesai ---
        if (inputPath) {
            await fs.unlink(inputPath).catch(err => console.error("Gagal menghapus file sementara:", err));
        }
    }
});


// TAMBAHKAN ENDPOINT BARU INI
app.get('/api/tools/stats', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                tool_name, 
                COUNT(*) as usage_count 
            FROM tool_usage 
            GROUP BY tool_name 
            ORDER BY usage_count DESC 
            LIMIT 3;
        `);

        // Mapping nama agar lebih ramah-tampilan
        const toolNameMapping = {
            'URL Shortener': { name: 'URL Shortener', href: 'tools/url-shortener.html', icon: '🔗' },
            'Media Converter': { name: 'Media Converter', href: 'tools/media-converter.html', icon: '🔄' },
            'QR Code Generator': { name: 'QR Code Generator', href: 'tools/qr-code-generator.html', icon: '📱' },
            'Image Compressor': { name: 'Image Compressor', href: 'tools/image-compressor.html', icon: '🖼️' },
            'Images to PDF': { name: 'Images to PDF', href: 'tools/images-to-pdf.html', icon: '📄' },
            'Split PDF': { name: 'Split PDF', href: 'tools/split-pdf.html', icon: '✂️' }
        };

        const topTools = result.rows.map(row => ({
            ...toolNameMapping[row.tool_name],
            count: parseInt(row.usage_count, 10)
        }));

        res.json(topTools);
    } catch (error) {
        console.error('Error fetching tool stats:', error);
        res.status(500).json({ error: 'Gagal mengambil statistik tool.' });
    }
});

// === [BARU] GOOGLE AUTH ROUTES ===

app.get('/api/auth/google', (req, res) => {
    const authUrl = googleClient.generateAuthUrl({
        access_type: 'offline',
        prompt: 'consent',
        scope: [
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
        ],
    });
    res.redirect(authUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
    const { code } = req.query;

    try {
        // Tukar authorization code dengan tokens
        const { tokens } = await googleClient.getToken(code);
        googleClient.setCredentials(tokens);

        // Dapatkan informasi pengguna dari Google
        const { data: userInfo } = await googleClient.request({
            url: 'https://www.googleapis.com/oauth2/v3/userinfo',
        });

        const { email, name, picture } = userInfo;
        if (!email) {
            return res.status(400).send('Gagal mendapatkan email dari Google.');
        }

        let user;
        const client = await pool.connect();

        try {
            // Cek apakah pengguna sudah ada di database
            const existingUserResult = await client.query('SELECT * FROM users WHERE email = $1', [email]);

            if (existingUserResult.rows.length > 0) {
                // Pengguna sudah ada, langsung loginkan
                user = existingUserResult.rows[0];
                console.log(`Pengguna Google yang kembali: ${user.email}`);
            } else {
                // Pengguna baru, daftarkan mereka
                // Kita tidak menyimpan password, jadi kita bisa hash string acak atau null
                const randomPassword = crypto.randomBytes(20).toString('hex');
                const hashedPassword = await bcrypt.hash(randomPassword, 10);

                const newUserResult = await client.query(
                    'INSERT INTO users (email, password_hash, full_name, avatar_url, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                    [email, hashedPassword, name, picture, 'google']
                );
                user = newUserResult.rows[0];
                console.log(`Pengguna Google baru terdaftar: ${user.email}`);
            }

            // Buat JWT untuk sesi aplikasi kita
            const userPayload = { id: user.id, email: user.email, role: user.role };
            const accessToken = jwt.sign(userPayload, process.env.JWT_SECRET, { expiresIn: '15m' });
            const refreshToken = jwt.sign(userPayload, process.env.JWT_REFRESH_SECRET, { expiresIn: '90d' });

            await client.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

            // Redirect ke halaman frontend dengan token
            const frontendRedirectUrl = new URL(`${process.env.FRONTEND_URL}/auth-callback.html`);
            frontendRedirectUrl.searchParams.set('accessToken', accessToken);
            frontendRedirectUrl.searchParams.set('refreshToken', refreshToken);

            res.redirect(frontendRedirectUrl.toString());

        } finally {
            client.release();
        }

    } catch (error) {
        console.error('Error selama otentikasi Google:', error);
        res.redirect(`${process.env.FRONTEND_URL}/auth.html?error=google-auth-failed`);
    }
});


// !!! [PERBAIKAN] PINDAHKAN ROUTE INI KE BAGIAN AKHIR !!!
// Route ini harus menjadi yang terakhir sebelum inisialisasi server
// agar tidak menimpa route API lainnya.
app.get('/:slug', async (req, res) => {
    try {
        const { slug } = req.params;
        const result = await pool.query('SELECT original_url FROM links WHERE slug = $1', [slug]);
        const link = result.rows[0];
        if (link) {
            res.redirect(301, link.original_url);
        } else {
            // Redirect ke halaman utama jika slug tidak ditemukan
            res.redirect(302, 'https://hamdirzl.my.id');
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server.' });
    }
});


// === Inisialisasi Server & WebSocket ===
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
let adminWs = null;
const clients = new Map();

function heartbeat() {
  this.isAlive = true;
}

wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.on('pong', heartbeat);

    const urlParams = new URLSearchParams(req.url.slice(req.url.startsWith('/?') ? 2 : 1));
    const token = urlParams.get('token');

    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (!err && user.role === 'admin') {
                console.log('Admin terhubung ke WebSocket.');
                ws.isAdmin = true;
                adminWs = ws;
                ws.send(JSON.stringify({ type: 'admin_connected' }));
                clients.forEach((clientData) => {
                    if (clientData.ws.readyState === WebSocket.OPEN) {
                        clientData.ws.send(JSON.stringify({ type: 'status_update', status: 'terhubung' }));
                    }
                });
            }
        });
    }

    ws.on('message', (message) => {
    try {
        const data = JSON.parse(message);

        // BAGIAN 1: MENANGANI PESAN DARI KONEKSI ADMIN
        if (ws.isAdmin) {
            console.log(`Admin sent: ${data.type}`); // Debugging
            if (data.type === 'admin_message' && data.targetUserId) {
                const clientData = clients.get(data.targetUserId);
                if (clientData && clientData.ws.readyState === WebSocket.OPEN) {
                    // [MODIFIKASI] Teruskan messageType
                    clientData.ws.send(JSON.stringify({ type: 'chat', sender: 'admin', content: data.content, messageType: data.messageType || 'text' }));
                    // [MODIFIKASI] Simpan messageType ke DB
                    pool.query(
                        'INSERT INTO chat_messages (conversation_id, sender_id, sender_type, content, message_type) VALUES ($1, $2, $3, $4, $5)',
                        [data.targetUserId, 'admin', 'admin', data.content, data.messageType || 'text']
                    ).catch(err => console.error("Gagal simpan pesan admin ke DB:", err));
                }
            } else if (data.type === 'typing' && data.targetUserId) {
                const clientData = clients.get(data.targetUserId);
                if (clientData && clientData.ws.readyState === WebSocket.OPEN) {
                    clientData.ws.send(JSON.stringify({ type: 'typing', isTyping: data.isTyping }));
                }
            }
            return; 
        }

        // BAGIAN 2: MENANGANI PESAN DARI KONEKSI PENGGUNA
        console.log(`User sent: ${data.type}`);
        switch (data.type) {
            case 'identify':
                ws.userId = data.session.userId;
                ws.userName = data.session.userName;
                clients.set(ws.userId, { ws: ws, name: ws.userName });
                console.log(`Pengunjung teridentifikasi: ${ws.userName} (ID: ${ws.userId})`);

                // === [BAGIAN BARU] Simpan/Update sesi ke database ===
                pool.query(
                    `INSERT INTO chat_sessions (conversation_id, user_name, last_active)
                     VALUES ($1, $2, NOW())
                     ON CONFLICT (conversation_id) 
                     DO UPDATE SET user_name = EXCLUDED.user_name, last_active = NOW();`,
                    [ws.userId, ws.userName]
                ).catch(err => console.error("Gagal menyimpan sesi chat ke DB:", err));
                // ========================================================
                
                if (adminWs && adminWs.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'status_update', status: 'terhubung' }));
                } else {
                    ws.send(JSON.stringify({ type: 'status_update', status: 'menghubungi' }));
                }
                break;

            case 'user_message':
                if (!ws.userId) return; 

                const messageType = data.messageType || 'text'; // [MODIFIKASI] Dapatkan tipe pesan
                const content = data.content;

                if (adminWs && adminWs.readyState === WebSocket.OPEN) {
                    adminWs.send(JSON.stringify({ type: 'chat', sender: ws.userId, content: content, userName: ws.userName, messageType: messageType }));
                } else {
                    const notifContent = messageType !== 'text' ? `[Pesan ${messageType}] ${content}` : content;
                    const notifMessage = `Pesan Baru dari ${ws.userName}\nID: ${ws.userId}\n\nPesan: ${notifContent}`;
                    sendTelegramNotification(notifMessage);
                }
                // [MODIFIKASI] Simpan messageType ke DB
                pool.query(
                    'INSERT INTO chat_messages (conversation_id, sender_id, sender_type, content, message_type) VALUES ($1, $2, $3, $4, $5)',
                    [ws.userId, ws.userId, 'user', content, messageType]
                ).catch(err => console.error("Gagal simpan pesan user ke DB:", err));

                break;

            case 'typing':
                if (!ws.userId) return; 
                if (adminWs && adminWs.readyState === WebSocket.OPEN) {
                    adminWs.send(JSON.stringify({ 
                        type: 'typing', 
                        userId: ws.userId, 
                        isTyping: data.isTyping 
                    }));
                }
                break;
        }
    } catch (e) {
        console.error("Gagal memproses pesan WebSocket:", e);
    }
});

    ws.on('close', () => {
        if (ws.isAdmin) {
            console.log('Admin terputus dari WebSocket.');
            adminWs = null;
            clients.forEach((clientData) => {
                if (clientData.ws.readyState === WebSocket.OPEN) {
                   clientData.ws.send(JSON.stringify({ type: 'status_update', status: 'menghubungi' }));
                }
            });
        } else if (ws.userId) {
            const clientInfo = clients.get(ws.userId);
            const userName = clientInfo ? clientInfo.name : 'Pengunjung tak dikenal';
            console.log(`Pengunjung ${userName} (ID: ${ws.userId}) terputus.`);
            if (adminWs && adminWs.readyState === WebSocket.OPEN) {
                adminWs.send(JSON.stringify({ type: 'user_disconnected', userId: ws.userId }));
            }
            clients.delete(ws.userId);
        }
    });
    
    ws.on('error', (error) => {
        console.error(`WebSocket Error: ${error}`);
    });
});

const interval = setInterval(function ping() {
  wss.clients.forEach(function each(ws) {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping(function noop() {});
  });
}, 30000);

wss.on('close', function close() {
  clearInterval(interval);
});


// Panggilan server.listen HANYA SATU KALI di akhir file
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server HTTP & WebSocket berjalan di port ${PORT}`);
});
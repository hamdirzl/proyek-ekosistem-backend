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

// === KONFIGURASI DATABASE ===
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET;

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
  ],
  exposedHeaders: ['Content-Disposition', 'X-Original-Size', 'X-Compressed-Size'] // BARIS INI DIUBAH
}));

app.use(express.json());

const upload = multer({ dest: 'uploads/' });
fs.mkdir('uploads', { recursive: true }).catch(console.error);


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

// === ROUTE BARU: HAPUS TAUTAN PENGGUNA ===
app.delete('/api/user/links/:slug', authenticateToken, async (req, res) => {
    try {
        const { slug } = req.params;
        const userId = req.user.id; // Dapatkan ID pengguna dari token yang sudah diautentikasi

        // Hapus tautan hanya jika user_id cocok dengan pengguna yang login
        const result = await pool.query(
            'DELETE FROM links WHERE slug = $1 AND user_id = $2 RETURNING slug',
            [slug, userId]
        );

        if (result.rowCount === 0) {
            // Jika tidak ada baris yang terhapus, bisa berarti slug tidak ada atau
            // slug tersebut bukan milik pengguna yang sedang login
            return res.status(404).json({ error: 'Tautan tidak ditemukan atau Anda tidak memiliki izin untuk menghapusnya.' });
        }

        res.json({ message: `Tautan dengan slug '${slug}' berhasil dihapus dari riwayat Anda.` });
    } catch (error) {
        console.error('Error menghapus tautan pengguna:', error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server saat menghapus tautan.' });
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

// === ROUTE BARU: QR CODE GENERATOR ===
app.post('/api/generate-qr', authenticateToken, async (req, res) => {
    try {
        const { text, level = 'M', colorDark = '#000000', colorLight = '#ffffff' } = req.body;

        if (!text) {
            return res.status(400).json({ error: 'Teks atau URL untuk QR code tidak boleh kosong.' });
        }

        // Options for QR code generation, allowing for customization (unique, professional)
        const qrOptions = {
            errorCorrectionLevel: level, // L, M, Q, H
            type: 'image/png',
            quality: 0.92,
            margin: 1, // Minimal margin for better scanning
            color: {
                dark: colorDark,    // Warna kotak QR code
                light: colorLight   // Warna latar belakang QR code
            }
        };

        // Generate QR code as a data URL (base64 image)
        const qrDataUrl = await QRCode.toDataURL(text, qrOptions);

        res.json({ qrCodeImage: qrDataUrl, message: 'QR Code berhasil dibuat!' });

    } catch (error) {
        console.error('Error generating QR code:', error);
        res.status(500).json({ error: 'Gagal membuat QR Code di server.' });
    }
});

// === ROUTE BARU: IMAGE COMPRESSOR ===
app.post('/api/compress-image', authenticateToken, upload.single('image'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Tidak ada file gambar yang diunggah.' });
    }

    const inputPath = req.file.path;
    const originalSize = req.file.size;
    let { quality = 80, format = 'jpeg' } = req.body; // Default quality 80, format jpeg

    // Pastikan kualitas adalah angka dan dalam rentang 0-100
    quality = parseInt(quality);
    if (isNaN(quality) || quality < 0 || quality > 100) {
        await fs.unlink(inputPath);
        return res.status(400).json({ error: 'Nilai kualitas tidak valid. Harus antara 0 dan 100.' });
    }

    // Tentukan format output berdasarkan mimetype atau input
    let outputFormat = format;
    if (req.file.mimetype.includes('png') && format === 'jpeg') {
        // Jika input PNG tapi diminta JPEG, lakukan konversi
        // Atau biarkan format aslinya jika tidak diminta konversi eksplisit
        outputFormat = 'jpeg'; // Default to JPEG for size reduction
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
            // PNG compression is usually lossless or near lossless, 'quality' option affects zlib compression level
            // For lossy PNG compression (if desired), a different approach might be needed or transparency might be lost
            compressedBuffer = await sharpInstance.png({ quality: quality }).toBuffer();
        } else {
            // Ini seharusnya sudah ditangani oleh cek outputFormat sebelumnya
            throw new Error('Unsupported output format for compression.');
        }
        
        const compressedSize = Buffer.byteLength(compressedBuffer);

        // Kirim gambar yang dikompresi sebagai respons
        res.set('Content-Type', `image/${outputFormat}`);
        res.set('Content-Disposition', `attachment; filename="compressed-image.${outputFormat}"`);
        res.set('X-Original-Size', originalSize); // Kirim ukuran asli di header
        res.set('X-Compressed-Size', compressedSize); // Kirim ukuran terkompresi di header
        res.send(compressedBuffer);

    } catch (error) {
        console.error('Error compressing image:', error);
        res.status(500).json({ error: 'Gagal mengompres gambar di server.' });
    } finally {
        // Selalu hapus file yang diunggah sementara
        await fs.unlink(inputPath).catch(err => console.error("Gagal menghapus file input sementara:", err));
    }
});

// === ROUTE BARU: CHAT WITH AI ===
app.post('/api/chat-with-ai', authenticateToken, async (req, res) => {
    try {
        const userMessage = req.body.message;
        const userId = req.user.id; 

        if (!userMessage) {
            return res.status(400).json({ error: 'Pesan tidak boleh kosong.' });
        }

        console.log(`Pesan dari pengguna ${userId}: ${userMessage}`);

        // --- LOGIKA SIMULASI RESPON AI ---
        let aiReply;
        if (userMessage.toLowerCase().includes('halo')) {
            aiReply = "Halo juga! Ada yang bisa saya bantu hari ini?";
        } else if (userMessage.toLowerCase().includes('siapa kamu')) {
            aiReply = "Saya adalah asisten AI yang dibuat untuk membantu Anda di situs ini.";
        } else if (userMessage.toLowerCase().includes('apa saja fiturnya')) {
            aiReply = "Di situs ini Anda bisa menemukan portofolio, tools (pemendek URL, konverter media, penggabung gambar ke PDF, generator QR Code, kompresor gambar), dan jurnal saya.";
        } else if (userMessage.toLowerCase().includes('bagaimana cuaca')) {
            aiReply = "Maaf, saya tidak memiliki akses ke informasi cuaca saat ini. Saya hanya bisa menjawab pertanyaan seputar situs ini.";
        } else if (userMessage.toLowerCase().includes('terima kasih')) {
            aiReply = "Sama-sama! Senang bisa membantu.";
        } else {
            aiReply = "Mohon maaf, saya belum bisa memahami pertanyaan Anda. Bisakah Anda bertanya tentang fitur-fitur di situs ini atau tentang Hamdi Rizal?";
        }
        // --- AKHIR LOGIKA SIMULASI ---

        res.json({ reply: aiReply });

    } catch (error) {
        console.error('Error in /api/chat-with-ai:', error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server saat memproses pesan AI.' });
    }
});


// === ROUTES ADMIN & REDIRECT ===
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
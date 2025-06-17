# Gunakan base image Node.js
FROM node:18-slim

# Set working directory
WORKDIR /usr/src/app

# Instal dependensi sistem, termasuk LibreOffice
# Perintah ini akan mengunduh LibreOffice ke dalam image Docker Anda
RUN apt-get update && \
    apt-get install -y libreoffice --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Salin package.json dan package-lock.json
COPY package*.json ./

# Instal dependensi Node.js
RUN npm install

# Salin sisa kode aplikasi Anda
COPY . .

# Expose port yang digunakan oleh aplikasi Anda
EXPOSE 3000

# Perintah untuk menjalankan server saat container dimulai
CMD [ "node", "server.js" ]
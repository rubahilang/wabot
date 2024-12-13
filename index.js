const { Client, LocalAuth } = require('whatsapp-web.js');
const express = require('express');
const qrcodeLib = require('qrcode'); // For converting QR code to data URL
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Session Middleware
// Session Middleware
app.use(session({
    secret: 'rubahilang', // Gantilah dengan secret yang kuat di produksi
    resave: false,
    saveUninitialized: false, // Lebih baik di-set ke false
    cookie: { 
        secure: false, // Set ke true jika menggunakan HTTPS
        httpOnly: true, // Membantu mencegah XSS
        maxAge: 1000 * 60 * 60 // 1 jam
    }
}));

// Function to load users from account.json
function loadUsers() {
    const dataPath = path.join(__dirname, 'key', 'account.json');
    try {
        const data = fs.readFileSync(dataPath, 'utf8');
        const jsonData = JSON.parse(data);
        return jsonData.users;
    } catch (err) {
        console.error('Error reading account.json:', err);
        return [];
    }
}

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        // If the request expects JSON (e.g., API calls)
        if (req.headers.accept && req.headers.accept.includes('application/json')) {
            res.status(401).json({ success: false, message: 'Unauthorized' });
        } else {
            // For regular page requests, redirect to login
            res.redirect('/login.html');
        }
    }
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 menit
    max: 5, // Maksimum 5 permintaan per IP per windowMs
    message: { success: false, message: 'Terlalu banyak percobaan login. Silakan coba lagi nanti.' }
});

// Serve Public Static Files (e.g., login.html, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// API Route for Login with Validation and Rate Limiting
app.post('/login', 
    loginLimiter,
    [
        body('username').trim().isLength({ min: 1 }).withMessage('Username diperlukan.'),
        body('password').trim().isLength({ min: 1 }).withMessage('Password diperlukan.')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.json({ success: false, message: errors.array()[0].msg });
        }

        const { username, password } = req.body;

        // Load users from account.json
        const users = loadUsers();

        // Find user by username
        const user = users.find(u => u.username === username);
        if (!user) {
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // Compare password with hashed password
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // Set session
        req.session.userId = user.id;
        res.json({ success: true });
    }
);

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Logout Route using GET
app.get('/logout', isAuthenticated, (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Logout failed.');
        }
        // Optionally clear the cookie if you're using cookie-based sessions
        res.clearCookie('connect.sid'); // Replace 'connect.sid' with your session cookie name if different
        res.redirect('/'); // Redirect to homepage after successful logout
    });
});

// Protected Routes Middleware - Serve Protected Static Files
app.use('/protected', isAuthenticated, express.static(path.join(__dirname, 'protected')));

// Serve Dashboard via Protected Route
app.get('/', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'protected', 'index.html'));
});

// API Route to Change Password
app.post('/change-password', isAuthenticated, 
    [
        body('currentPassword').trim().isLength({ min: 1 }).withMessage('Password saat ini diperlukan.'),
        body('newPassword').trim().isLength({ min: 6 }).withMessage('Password baru harus minimal 6 karakter.')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.json({ success: false, message: errors.array()[0].msg });
        }

        const { currentPassword, newPassword } = req.body;

        // Load users
        const users = loadUsers();

        // Find user based on session.userId
        const user = users.find(u => u.id === req.session.userId);
        if (!user) {
            return res.json({ success: false, message: 'Pengguna tidak ditemukan.' });
        }

        // Verify current password
        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.json({ success: false, message: 'Password saat ini salah.' });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update password in users
        user.password = hashedNewPassword;

        // Save back to account.json
        const dataPath = path.join(__dirname, 'key', 'account.json');
        try {
            fs.writeFileSync(dataPath, JSON.stringify({ users }, null, 4), 'utf8');
            res.json({ success: true });
        } catch (err) {
            console.error('Error writing to account.json:', err);
            res.json({ success: false, message: 'Gagal menyimpan password baru.' });
        }
    }
);

// API Route to Add Account
// Route API untuk Tambah Akun
app.post('/add-account', isAuthenticated, 
    [
        body('newUsername').trim().isLength({ min: 1 }).withMessage('Username diperlukan.'),
        body('newPassword').trim().isLength({ min: 6 }).withMessage('Password harus minimal 6 karakter.')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.json({ success: false, message: errors.array()[0].msg });
        }

        const { newUsername, newPassword } = req.body;

        // Tambahkan logging sementara
        console.log('Received newUsername:', newUsername);
        console.log('Received newPassword length:', newPassword.length);

        // Memeriksa apakah username sudah ada
        const users = loadUsers();
        const existingUser = users.find(u => u.username === newUsername);
        if (existingUser) {
            return res.json({ success: false, message: 'Username sudah digunakan.' });
        }

        // Hash password baru
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Generate ID unik
        const newId = users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1;

        // Tambahkan pengguna baru
        const newUser = {
            id: newId,
            username: newUsername,
            password: hashedPassword
        };

        users.push(newUser);

        // Simpan kembali ke account.json
        const dataPath = path.join(__dirname, 'key', 'account.json');
        try {
            fs.writeFileSync(dataPath, JSON.stringify({ users }, null, 4), 'utf8');
            res.json({ success: true });
        } catch (err) {
            console.error('Error writing to account.json:', err);
            res.json({ success: false, message: 'Gagal menambah akun baru.' });
        }
    }
);

// Fallback Route for Unauthenticated Access to Protected Pages
app.use((req, res, next) => {
    // Handle attempts to access protected routes directly
    if (req.path.startsWith('/protected/')) {
        res.redirect('/login.html');
    } else {
        next();
    }
});

const CLIENTS_DATA_FILE = path.join(__dirname, 'clients_data.json');
const SESSIONS_DIR = path.join(__dirname, 'sessions');

// Ensure the sessions directory exists
if (!fs.existsSync(SESSIONS_DIR)) {
    fs.mkdirSync(SESSIONS_DIR);
}

// Object to store all clients
// Structure: clients[clientId] = {
//   client, name, qrData, logs:[], ready: boolean, isSending, pendingValidationConfirmations, pendingDeletions
//   pendingAutopingConfirmation, pendingAutopingDelay
// }
let clients = {};

// Function to load clients data from JSON file
function loadClientsData() {
    if (fs.existsSync(CLIENTS_DATA_FILE)) {
        try {
            const raw = fs.readFileSync(CLIENTS_DATA_FILE, 'utf-8');
            const data = JSON.parse(raw);
            return data;
        } catch (err) {
            console.error('Failed to read clients_data.json:', err);
            return {};
        }
    } else {
        return {};
    }
}

// Function to save clients data to JSON file
function saveClientsData() {
    const dataToSave = {};
    for (const cid in clients) {
        dataToSave[cid] = {
            name: clients[cid].name,
            logs: clients[cid].logs
        };
    }
    fs.writeFileSync(CLIENTS_DATA_FILE, JSON.stringify(dataToSave, null, 2), 'utf-8');
}

// Function to create a new client
function createClient(clientId) {
    const client = new Client({
        authStrategy: new LocalAuth({
            clientId: clientId,
            dataPath: SESSIONS_DIR // Specify the sessions directory
        })
    });

    // Initialize client data
    clients[clientId] = {
        client,
        name: clientId,  // Default name same as clientId
        qrData: null,
        logs: [],
        ready: false,
        isSending: false,
        pendingValidationConfirmations: {},
        pendingDeletions: {},
        pendingAutopingConfirmation: {},
        pendingAutopingDelay: {}
    };

    function addLog(msg) {
        console.log(`[${clientId}] ${msg}`);
        clients[clientId].logs.push(msg);
        saveClientsData(); // Save data each time logs change
    }

    function delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function readNumbersFromFile(filename) {
        try {
            const data = fs.readFileSync(path.resolve(__dirname, filename), 'utf-8');
            const lines = data.split('\n').map(l => l.trim()).filter(l => l.length > 0);
            return lines;
        } catch (err) {
            return [];
        }
    }

    function writeNumbersToFile(filename, numbers) {
        const data = numbers.join('\n') + '\n';
        fs.writeFileSync(path.resolve(__dirname, filename), data, 'utf-8');
    }

    function appendNumbersToFile(filename, numbers) {
        const dataToAppend = numbers.map(num => num.trim()).join('\n') + '\n';
        fs.appendFileSync(path.resolve(__dirname, filename), dataToAppend, 'utf-8');
    }

    function deleteFile(filename) {
        try {
            fs.unlinkSync(path.resolve(__dirname, filename));
            return true;
        } catch (err) {
            return false;
        }
    }

    client.on('qr', (qr) => {
        addLog('QR code received, display it on the web to scan.');
        qrcodeLib.toDataURL(qr, (err, url) => {
            if (err) {
                addLog('Failed to generate QR data URL: ' + err);
                return;
            }
            clients[clientId].qrData = url;
            saveClientsData();
        });
    });

    client.on('ready', () => {
        clients[clientId].ready = true;
        addLog('Bot successfully connected to WhatsApp!');
        clients[clientId].qrData = null;
        saveClientsData();
    });

    client.on('disconnected', (reason) => {
        clients[clientId].ready = false;
        addLog('Client disconnected. Reason: ' + reason);
        saveClientsData();
    });

    async function handleMessage(message) {
        const from = message.from;
        const body = message.body.trim();
        let { isSending, pendingValidationConfirmations, pendingDeletions, pendingAutopingConfirmation, pendingAutopingDelay } = clients[clientId];

        clients[clientId].logs.push(`Message from ${from}: ${body}`);
        saveClientsData();

        // AUTOPING FEATURE
        // Check pending autoping confirmation state
        if (pendingAutopingConfirmation[from]) {
            const response = body.toLowerCase();
            if (response === 'y') {
                // User already has autoping list
                await client.sendMessage(from, 'Enter Delay: 10-45');
                delete pendingAutopingConfirmation[from];
                pendingAutopingDelay[from] = true;
                saveClientsData();
                return;
            } else if (response === 'n') {
                await client.sendMessage(from, 'Please use the command "/add_bulk autoping number1, number2, number3"');
                delete pendingAutopingConfirmation[from];
                saveClientsData();
                return;
            } else {
                await client.sendMessage(from, 'Unrecognized answer. Type y or n');
                return;
            }
        }

        // Check pending autoping delay state
        if (pendingAutopingDelay[from]) {
            const delayInput = parseInt(body, 10);
            if (!isNaN(delayInput) && delayInput >= 10 && delayInput <= 45) {
                delete pendingAutopingDelay[from];
                saveClientsData();
                // Execute /send autoping ping.txt {delayInput}
                const sendCommand = `/send autoping ping.txt ${delayInput}`;
                await handleMessage({ from, body: sendCommand, hasMedia: false, downloadMedia: async () => { } });
                return;
            } else {
                await client.sendMessage(from, 'Invalid delay. Enter a number between 10-45');
                return;
            }
        }

        // If user types /autoping {delay}
        // Example: /autoping 20
        if (body.startsWith('/autoping ')) {
            const parts = body.split(' ');
            if (parts.length == 2) {
                const directDelay = parseInt(parts[1], 10);
                if (!isNaN(directDelay) && directDelay >= 10 && directDelay <= 45) {
                    // Directly execute /send autoping ping.txt {delay}
                    const sendCommand = `/send autoping ping.txt ${directDelay}`;
                    await handleMessage({ from, body: sendCommand, hasMedia: false, downloadMedia: async () => { } });
                    return;
                } else {
                    await client.sendMessage(from, 'Invalid delay. Must be between 10-45 or type "/autoping" without arguments for Q&A flow.');
                    return;
                }
            }
        }

        // If user only types /autoping without arguments
        if (body === '/autoping') {
            await client.sendMessage(from, 'Have you created a list named "autoping"? y/n');
            pendingAutopingConfirmation[from] = true;
            saveClientsData();
            return;
        }

                // Handle media
        if (message.hasMedia) {
            try {
                const media = await message.downloadMedia();
                let filename;
                if (media.filename) {
                    filename = media.filename;
                } else {
                    const mimeSplit = media.mimetype.split('/');
                    const extension = mimeSplit.length > 1 ? mimeSplit[1] : 'bin';
                    filename = `file_${Date.now()}.${extension}`;
                }

                const filePath = path.join(__dirname, filename);
                fs.writeFileSync(filePath, media.data, { encoding: 'base64' });
                await client.sendMessage(from, `File received and saved as ${filename}`);
                clients[clientId].logs.push(`File saved: ${filename} from ${from}`);
                saveClientsData();
            } catch (err) {
                console.error(`[${clientId}] Error downloading media:`, err);
                await client.sendMessage(from, 'Terjadi kesalahan saat mengunduh media.');
            }
            return;
        }


        // Confirmation for /valid
        if (pendingValidationConfirmations[from]) {
            const response = body.toLowerCase();
            if (response === 'y') {
                const { filename, validNumbers } = pendingValidationConfirmations[from];
                writeNumbersToFile(filename, validNumbers);
                await client.sendMessage(from, 'Invalid numbers have been removed. The file has been updated with valid numbers.');
                console.log(`[${clientId}] Invalid numbers removed from ${filename} at ${from}'s request.`);
            } else if (response === 'n') {
                await client.sendMessage(from, 'No changes made to the file.');
            } else {
                await client.sendMessage(from, 'Unrecognized answer. No changes made to the file.');
            }
            delete pendingValidationConfirmations[from];
            saveClientsData();
            return;
        }

        // Confirmation for /hapus
        if (pendingDeletions[from]) {
            const response = body.toLowerCase();
            const { filename, type, numbersToDelete } = pendingDeletions[from];

            if (response === 'y') {
                if (type === 'delete_all') {
                    const success = deleteFile(filename);
                    if (success) {
                        await client.sendMessage(from, `File ${filename} has been deleted.`);
                        console.log(`[${clientId}] File ${filename} deleted at ${from}'s request.`);
                    } else {
                        await client.sendMessage(from, `Failed to delete file ${filename}.`);
                    }
                } else if (type === 'delete_some') {
                    let currentNumbers = readNumbersFromFile(filename);
                    const beforeCount = currentNumbers.length;
                    currentNumbers = currentNumbers.filter(num => !numbersToDelete.includes(num));
                    const afterCount = currentNumbers.length;
                    writeNumbersToFile(filename, currentNumbers);
                    await client.sendMessage(from, `${beforeCount - afterCount} numbers have been deleted from file ${filename}.`);
                    console.log(`[${clientId}] ${beforeCount - afterCount} numbers deleted from ${filename} at ${from}'s request.`);
                }
            } else if (response === 'n') {
                await client.sendMessage(from, 'No changes made to the file.');
            } else {
                await client.sendMessage(from, 'Unrecognized answer. No changes made to the file.');
            }
            delete pendingDeletions[from];
            saveClientsData();
            return;
        }

        // /add_bulk
        if (body.startsWith('/add_bulk')) {
            const parts = body.split(' ');
            if (parts.length < 3) {
                await client.sendMessage(from, 'Invalid format. Example: /add_bulk filename 6281234567890,6282345678901');
                return;
            }
            const filename = parts[1];
            const nomorString = parts.slice(2).join(' ');
            const nomorArr = nomorString.split(',');

            let validNumbers = [];
            for (let nomor of nomorArr) {
                const cleanNumber = nomor.replace(/[^0-9]/g, '');
                if (cleanNumber.length > 0) {
                    validNumbers.push(cleanNumber);
                }
            }

            if (validNumbers.length === 0) {
                await client.sendMessage(from, 'No valid numbers to add.');
                return;
            }

            appendNumbersToFile(filename, validNumbers);
            await client.sendMessage(from, `${validNumbers.length} numbers added to file ${filename}!`);
            console.log(`[${clientId}] ${validNumbers.length} numbers added to ${filename} by ${from}.`);
            saveClientsData();
            return;
        }

        // /list
        if (body.startsWith('/list')) {
            const parts = body.split(' ');
            if (parts.length < 2) {
                await client.sendMessage(from, 'Invalid format. Example: /list filename.txt');
                return;
            }

            const filename = parts[1];
            const numbers = readNumbersFromFile(filename);

            if (numbers.length === 0) {
                await client.sendMessage(from, `File ${filename} is empty or cannot be read.`);
            } else {
                let listMsg = `List of numbers in ${filename}:\n`;
                numbers.forEach((num, i) => {
                    listMsg += `${i + 1}. ${num}\n`;
                });
                await client.sendMessage(from, listMsg.trim());
            }
            return;
        }

        // /hapus
        if (body.startsWith('/hapus ')) {
            const parts = body.split(' ');
            if (parts.length < 3) {
                await client.sendMessage(from, 'Invalid format. Examples:\n/hapus filename.txt *\n/hapus filename.txt 6281234,6285678');
                return;
            }

            const filename = parts[1];
            const commandParam = parts.slice(2).join(' ');

            const numbers = readNumbersFromFile(filename);
            if (numbers.length === 0) {
                await client.sendMessage(from, `File ${filename} is empty or cannot be read.`);
                return;
            }

            if (commandParam === '*') {
                await client.sendMessage(from, `You are about to delete all numbers from file ${filename} (file will be deleted). Continue? Y/N`);
                pendingDeletions[from] = {
                    filename,
                    type: 'delete_all',
                    numbersToDelete: []
                };
            } else {
                const nomorArr = commandParam.split(',').map(n => n.trim().replace(/[^0-9]/g, '')).filter(n => n.length > 0);
                if (nomorArr.length === 0) {
                    await client.sendMessage(from, 'No valid numbers to delete.');
                    return;
                }

                const validToDelete = nomorArr.filter(num => numbers.includes(num));
                if (validToDelete.length === 0) {
                    await client.sendMessage(from, 'The numbers you want to delete are not in the file.');
                    return;
                }

                await client.sendMessage(from, `You are about to delete ${validToDelete.length} numbers from file ${filename}. Continue? Y/N`);
                pendingDeletions[from] = {
                    filename,
                    type: 'delete_some',
                    numbersToDelete: validToDelete
                };
            }
            saveClientsData();
            return;
        }

        // /ping
        if (body === '/ping' || body.toLowerCase() === 'ping') {
            await client.sendMessage(from, 'Pong🏓');
            return;
        }

        // /send
        if (body.startsWith('/send ')) {
            const parts = body.split(' ');
            if (parts.length < 4) {
                await client.sendMessage(from, 'Invalid format. Example: /send numbers.txt message.txt 10');
                return;
            }

            const nomorFile = parts[1];
            const pesanFile = parts[2];
            const delaySec = parseInt(parts[3], 10);

            if (isNaN(delaySec)) {
                await client.sendMessage(from, 'Delay must be a number. Example: /send numbers.txt message.txt 10');
                return;
            }

            const nomorList = readNumbersFromFile(nomorFile);
            if (nomorList.length === 0) {
                await client.sendMessage(from, `File ${nomorFile} is empty or cannot be read.`);
                return;
            }

            let rawData;
            try {
                rawData = fs.readFileSync(path.resolve(__dirname, pesanFile), 'utf-8');
            } catch (err) {
                await client.sendMessage(from, `Failed to read file ${pesanFile}. Ensure the file exists.`);
                return;
            }

            if (!rawData || rawData.trim().length === 0) {
                await client.sendMessage(from, `File ${pesanFile} is empty or contains invalid content.`);
                return;
            }

            const pesanList = rawData.split('|').map(p => p.trim()).filter(p => p.length > 0);
            if (pesanList.length === 0) {
                await client.sendMessage(from, `No valid messages found in ${pesanFile}.`);
                return;
            }

            clients[clientId].isSending = true;
            saveClientsData();
            await client.sendMessage(from, 'Sending messages...');

            for (let i = 0; i < pesanList.length; i++) {
                if (!clients[clientId].isSending) {
                    await client.sendMessage(from, 'Sending process stopped by /stop_send.');
                    break;
                }

                const pesan = pesanList[i];

                for (let nomorTujuan of nomorList) {
                    if (!clients[clientId].isSending) break;
                    const waNumber = nomorTujuan + '@c.us';
                    await client.sendMessage(waNumber, pesan);
                }

                if (i < pesanList.length - 1 && clients[clientId].isSending) {
                    await delay(delaySec * 1000);
                }
            }

            if (clients[clientId].isSending) {
                await client.sendMessage(from, 'All messages have been sent.');
            }

            clients[clientId].isSending = false;
            saveClientsData();
            return;
        }

        // /stop_send
        if (body === '/stop_send') {
            if (clients[clientId].isSending) {
                clients[clientId].isSending = false;
                await client.sendMessage(from, 'Sending process has been stopped.');
            } else {
                await client.sendMessage(from, 'No sending process is currently running.');
            }
            saveClientsData();
            return;
        }

        // /valid
        if (body.startsWith('/valid ')) {
            const parts = body.split(' ');
            if (parts.length < 2) {
                await client.sendMessage(from, 'Invalid format. Example: /valid filename.txt');
                return;
            }

            const filename = parts[1];
            const nomorList = readNumbersFromFile(filename);
            if (nomorList.length === 0) {
                await client.sendMessage(from, `File ${filename} is empty or cannot be read.`);
                return;
            }

            await client.sendMessage(from, `Validating ${nomorList.length} numbers. Please wait...`);

            let resultMsg = '';
            let validNumbers = [];
            let invalidNumbers = [];

            for (let nomor of nomorList) {
                const waNumber = nomor + '@c.us';
                const isRegistered = await client.isRegisteredUser(waNumber);
                if (isRegistered) {
                    validNumbers.push(nomor);
                    resultMsg += `${nomor}: Valid\n`;
                } else {
                    invalidNumbers.push(nomor);
                    resultMsg += `${nomor}: Invalid\n`;
                }
            }

            await client.sendMessage(from, resultMsg.trim());

            if (invalidNumbers.length > 0) {
                await client.sendMessage(from, '(Delete invalid numbers? Y/N)');
                pendingValidationConfirmations[from] = {
                    filename,
                    validNumbers,
                    invalidNumbers
                };
            } else {
                await client.sendMessage(from, 'All numbers are valid. No deletions necessary.');
            }
            saveClientsData();
            return;
        }

        // Tambahkan ini di dalam fungsi handleMessage(message) sebelum bagian akhir fungsi
        if (body.startsWith('/help') || body.toLowerCase() === 'help') {
            const helpMessage = `
        *Daftar Perintah yang Tersedia:*

        1. *\/add_bulk*  
        *Format:* \`/add_bulk filename number1,number2,...\`  
        *Penjelasan:* Menambahkan beberapa nomor ke file tertentu.

        2. *\/autoping*  
        *Format:* \`/autoping [delay]\`  
        *Penjelasan:* Mengirim pesan otomatis dengan delay tertentu (10-45 detik).

        3. *\/send*  
        *Format:* \`/send numbers.txt message.txt delaySec\`  
        *Penjelasan:* Mengirim pesan dari \`message.txt\` ke nomor di \`numbers.txt\` dengan delay dalam detik.

        4. *\/list*  
        *Format:* \`/list filename.txt\`  
        *Penjelasan:* Menampilkan daftar nomor dalam file tertentu.

        5. *\/hapus*  
        *Format:* \`/hapus filename.txt [* atau number1,number2,...]\`  
        *Penjelasan:* Menghapus semua atau beberapa nomor dari file tertentu.

        6. *\/valid*  
        *Format:* \`/valid filename.txt\`  
        *Penjelasan:* Memvalidasi nomor dalam file tertentu dan menghapus nomor yang tidak valid.

        7. *\/ping*  
        *Format:* \`/ping\` atau \`ping\`  
        *Penjelasan:* Mengirim balasan "Pong🏓".

        8. *\/stop_send*  
        *Format:* \`/stop_send\`  
        *Penjelasan:* Menghentikan proses pengiriman pesan.

        9. *\/help* atau *help*  
        *Format:* \`/help\` atau \`help\`  
        *Penjelasan:* Menampilkan daftar perintah yang tersedia.

        *Catatan:* Pastikan Anda mengikuti format yang benar untuk setiap perintah agar berfungsi dengan baik.
            `;
            await client.sendMessage(from, helpMessage);
            return;
        }

        
        // No matching command found
        // Optionally, you can send a help message or ignore
    }

    client.on('message', handleMessage);

    client.on('auth_failure', msg => {
        console.error(`[${clientId}] Authentication failed:`, msg);
        clients[clientId].logs.push('Authentication failed: ' + msg);
        saveClientsData();
    });

    client.on('authenticated', () => {
        addLog('Authentication successful.');
    });

    client.on('auth_success', () => {
        addLog('Authentication success.');
    });

    client.on('ready', () => {
        addLog('Client is ready.');
    });

    client.initialize();
}

// Load clients data from file
const loadedData = loadClientsData();

// If there is data, load clients from it
const loadedClientIds = Object.keys(loadedData);
if (loadedClientIds.length > 0) {
    for (const cid of loadedClientIds) {
        createClient(cid);
        // Restore name and logs
        clients[cid].name = loadedData[cid].name || cid;
        clients[cid].logs = loadedData[cid].logs || [];
    }
} else {
    // If no data, create client_1
    createClient('client_1');
}

// Endpoint to add a new account
app.post('/add', (req, res) => {
    const clientId = 'client_' + Date.now();
    createClient(clientId);
    saveClientsData();
    res.json({ success: true, clientId });
});

// Endpoint to logout an account
app.post('/delete-session', (req, res) => {
    const { clientId } = req.body;
    if (!clientId || !clients[clientId]) {
        return res.json({ success: false, message: 'Client not found' });
    }

    const sessionPath = path.join(SESSIONS_DIR, `session-${clientId}`);
    try {
        fs.rmSync(sessionPath, { recursive: true, force: true });
    } catch (err) {
        console.log('Error deleting session:', err);
    }

    clients[clientId].client.destroy();
    delete clients[clientId];
    saveClientsData();
    res.json({ success: true });
});

// Endpoint to rename an account
app.post('/rename', (req, res) => {
    const { clientId, newName } = req.body;
    if (!clientId || !clients[clientId]) {
        return res.json({ success: false, message: 'Client not found' });
    }
    if (!newName || newName.trim().length === 0) {
        return res.json({ success: false, message: 'New name is invalid' });
    }

    clients[clientId].name = newName.trim();
    saveClientsData();
    res.json({ success: true, name: clients[clientId].name });
});

// Endpoint to get data of a single account
app.get('/account', (req, res) => {
    const clientId = req.query.clientId;
    if (!clientId || !clients[clientId]) {
        return res.json({ error: 'Client not found' });
    }

    res.json({
        qrData: clients[clientId].qrData,
        logs: clients[clientId].logs,
        ready: clients[clientId].ready
    });
});

// Endpoint to list all accounts
app.get('/list_clients', (req, res) => {
    const list = Object.keys(clients).map(cid => ({
        clientId: cid,
        name: clients[cid].name,
        ready: clients[cid].ready
    }));
    res.json(list);
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});

// Graceful shutdown to ensure sessions are saved properly
process.on('SIGINT', () => {
    console.log('Shutting down gracefully...');
    for (const cid in clients) {
        clients[cid].client.destroy();
    }
    process.exit();
});

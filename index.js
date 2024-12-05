const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const { machineIdSync } = require('node-machine-id');
const jwt = require('jsonwebtoken');
const port = process.env.PORT || 3001
const dotenv = require('dotenv')
dotenv.config()

const app = express();
const secretKey = "ThisIsMyProject";
const userDataFile = path.join(__dirname, 'users.json');
const votesFilePath = path.join(__dirname, 'votes.json');

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const privateKey = fs.readFileSync(path.join(__dirname, 'private_key.pem'), 'utf8');

// Ensure necessary files exist
if (!fs.existsSync(userDataFile)) {
    fs.writeFileSync(userDataFile, JSON.stringify([]));
}
if (!fs.existsSync(votesFilePath)) {
    fs.writeFileSync(votesFilePath, JSON.stringify({
        candidate1: 0,
        candidate2: 0,
        candidate3: 0,
    }));
}

// Serve React Build
const buildPath = path.join(__dirname, 'build');
app.use(express.static(buildPath));

// Root route
app.get('/', (req, res) => {
    res.sendFile(path.join(buildPath, 'index.html'));
});

// Backend API routes
app.get('/totalvotes', (req, res) => {
    try {
        console.log("requrestin coming")
        const votes = JSON.parse(fs.readFileSync(votesFilePath, 'utf8'));
        const totals = votes["candidate1"] + votes["candidate2"] + votes["candidate3"];
        res.json({ success: true, totalVotes: totals });
    } catch (error) {
        console.error('Error fetching total votes:', error);
        res.status(500).json({ success: false, message: "Error fetching total votes" });
    }
});

app.get('/public-key', (req, res) => {
    try {
        const publicKey = fs.readFileSync(path.join(__dirname, 'public_key.pem'), 'utf8');
        res.json({ publicKey });
    } catch (error) {
        console.error('Error reading public key:', error);
        res.status(500).json({ error: 'Failed to retrieve public key' });
    }
});

app.get('/getMacAddress', (req, res) => {
    const macAddress = machineIdSync();
    res.json({ macAddress });
});

const castVote = (candidate) => {
    try {
        const data = fs.readFileSync(votesFilePath, 'utf8');
        const votes = JSON.parse(data);
        if (!votes) return { success: false, message: 'Failed to read votes' };

        votes[candidate] += 1;
        fs.writeFileSync(votesFilePath, JSON.stringify(votes, null, 2));

        return { success: true, message: 'Vote cast successfully', votes: votes["candidate1"] + votes["candidate2"] + votes["candidate3"] };
    } catch (err) {
        console.error('Error casting vote:', err);
        return { success: false, votingproblem: true };
    }
};

app.post('/addusertolist', (req, res) => {
    const { encryptedEmail } = req.body;
    const mail = decryptData(encryptedEmail);

    fs.readFile(userDataFile, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({ error: 'Error reading user list' });
        }

        const users = JSON.parse(data);
        users.push({ email: mail });

        fs.writeFile(userDataFile, JSON.stringify(users, null, 2), 'utf8', (err) => {
            if (err) {
                return res.status(500).json({ error: 'Error writing to user list' });
            }
            res.status(200).json({ message: 'User added to the list' });
        });
    });
});

app.get('/getresult', (req, res) => {
    try {
        fs.readFile(votesFilePath, 'utf8', (err, data) => {
            if (err) return res.json({ success: false, message: 'Failed to read votes' });

            const votes = JSON.parse(data);
            const votings = [votes["candidate1"], votes["candidate2"], votes["candidate3"]];
            res.json({ success: true, data: votings });
        });
    } catch (error) {
        res.json({ success: false });
    }
});

app.post('/newvote', (req, res) => {
    const { token, encryptedCandi } = req.body;
    if (!token || !encryptedCandi) return res.json({ success: false });

    const verifytoken = tokenverificaton(token);
    if (!verifytoken.success) return res.json({ success: true, tampered: true });

    const Candi = decryptData(encryptedCandi);
    let dummy = "candidate1";
    if (Candi == 2) dummy = "candidate2";
    else if (Candi == 3) dummy = "candidate3";

    const response = castVote(dummy);
    if (!response.success) return res.json({ success: true, votingproblem: true, message: "Something went wrong with server" });

    res.json({ success: true, votes: response.votes });
});

app.post('/getToken', (req, res) => {
    console.log("new requst")
    const { encryptedEmail, encryptedMac } = req.body.encryptedData;
    if (!encryptedEmail || !encryptedMac) return res.status(400).json({ error: 'No encrypted data provided' });

    try {
        const decryptedMail = decryptData(encryptedEmail);
        const decryptedMac = decryptData(encryptedMac);

        fs.readFile(userDataFile, 'utf8', (err, data) => {
            if (err) return res.status(500).json({ error: 'Failed to read user data' });

            const users = JSON.parse(data);
            const userExists = users.some(user => user.email === decryptedMail);

            if (userExists) {
                res.json({ success: true, token: null });
            } else {
                const token = generateToken(decryptedMail, decryptedMac);
                res.json({ success: true, token: token });
            }
        });
    } catch (error) {
        console.error('Error during decryption:', error);
        res.status(500).json({ success: false, error: 'Decryption failed' });
    }
});

function generateToken(email, macAddress) {
    const payload = { macAddress };

    const token = jwt.sign(payload, secretKey, {
        expiresIn: '1h'
    });

    return token;
}

function tokenverificaton(token) {
    try {
        const decoded = jwt.verify(token, secretKey);
        return { success: true, payload: decoded };
    } catch (error) {
        return { success: false, message: 'Invalid or expired token' };
    }
}

function decryptData(encryptedData) {
    try {
        const bufferEncryptedData = Buffer.from(encryptedData, 'base64');
        const decrypted = crypto.privateDecrypt(
            {
                key: privateKey,
                passphrase: '1111',
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            bufferEncryptedData
        );
        return decrypted.toString('utf8');
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Decryption failed');
    }
}

// HTTPS Setup
const privateKeyserver = fs.readFileSync('private.key', 'utf8');
const certificate = fs.readFileSync('mydomain.crt', 'utf8');
const credentials = { key: privateKeyserver, cert: certificate };

https.createServer(credentials, app).listen(port, '0.0.0.0', () => {
    console.log('HTTPS server running on port 8080');
});

// Catch-all for React Routes
app.get('*', (req, res) => {
    res.sendFile(path.join(buildPath, 'index.html'));
});

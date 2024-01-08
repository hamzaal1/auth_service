// index.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const cookie = require('cookie');

const app = express();
const prisma = new PrismaClient();

app.use(express.json());




// Routes
app.post('/register', async (req, res) => {
    const { email, username, password } = req.body;

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create a user in the database
    const user = await prisma.users.create({
        data: {
            email,
            username,
            password: hashedPassword,
        },
    });
    const accessToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
        expiresIn: '1h',
    });

    // Generate Refresh token
    const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '2160h' });

    await prisma.refreshTokens.create({
        data: {
            userId: user.id,
            token: refreshToken,
            active: true
        },
    });

    res.setHeader('Set-Cookie', cookie.serialize('token', accessToken, {
        httpOnly: true,
        maxAge: 60 * 60, // 1 hour in seconds
        sameSite: 'strict',
        path: '/',
    }));

    res.json({ message: 'user is loged in successfully' });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}/`);
});


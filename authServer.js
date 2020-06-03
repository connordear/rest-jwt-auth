require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());


// MOVE REFRESH TOKENS AND USERS TO DATABASE
let refreshTokens = [];
const users = [];

app.get('/users', (req, res) => {
    res.json(users);
})

app.post('/users', async (req, res) => {
    // Salt & Hash the password
    // hash(salt + 'password') // dddddd
    // hash(salt2 + 'password') // eeeeee
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { name: req.body.name, password: hashedPassword };
        
        users.push(user);
        res.status(201).send();
    } catch {
        res.sendStatus(500);
    }
})


app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken });
    })
})

app.post('/login', async (req, res) => {
    // Authenticate User
    console.log('Searching for user with name', req.body.username);
    const user = users.find(user => user.name === req.body.username);
    if (user == null) {
        return res.status(400).send('Cannot find user')
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            // Successful Authentication
            const accessToken = generateAccessToken(user);
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
            refreshTokens.push(refreshToken);
            res.json({
                accessToken: accessToken,
                refreshToken: refreshToken
            });
        } else {
            res.send('Not Allowed');
        }
    } catch {
        res.status(500).send();
    }
})

app.delete('/logout', (req, res) => {
    // Delete the refresh token from the "database" of tokens
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
}



const PORT = 4000;
app.listen(PORT);
console.log('Authentication Server now listening at port:', PORT)
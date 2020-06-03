require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');


const app = express();
app.use(express.json());


const posts = [
    {
        username: 'Kim',
        title: 'Post 1'
    },
    {
        username: 'Connor',
        title: 'Post 2'
    }
]

app.get('/posts', authenticateToken, (req, res) => {
    // the user has been added to the request now
    if (!req.user.name) {
        res.sendStatus(403) // Not logged in
    } else {
        res.json(posts.filter(post => post.username === req.user.name))
    }
})


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // Token Format: Bearer TOKEN...
    const token = authHeader && authHeader.split(' ')[1]; // Split at space and take the token
    if (token === null) return res.sendStatus(401); // Unauthorized Client

    // user is the user object that was extracted inside the /login endpoint
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403) // Forbidden
        req.user = user;
        next();
    });

}


const PORT = 3000;
app.listen(PORT);
console.log('Application now listening at port:', PORT)
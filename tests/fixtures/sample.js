const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;
    exec(`grep ${query} /var/log/app.log`, (err, stdout) => {
        res.send(stdout);
    });
    document.getElementById('result').innerHTML = query;
});

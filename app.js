/*
 * aikido-ci-demo — intentionally vulnerable baseline app.
 * DO NOT run or deploy. Used to demo Aikido cloud scanning, PR gating and CI release gating.
 */
const express = require('express');
const mysql = require('mysql');
const _ = require('lodash');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const db = mysql.createConnection({ host: 'localhost', user: 'app', database: 'shop' });

// SAST: SQL injection (user input concatenated into query)
app.get('/user', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});

// SCA reachability: lodash.merge on user input (prototype pollution CVE in lodash 4.17.15)
app.post('/settings', (req, res) => {
  res.json(_.merge({}, req.body));
});

// SCA: jsonwebtoken 8.5.1 has known CVEs
app.get('/verify', (req, res) => {
  try {
    res.json(jwt.verify(req.query.token, process.env.JWT_SECRET));
  } catch (e) {
    res.status(401).send('invalid token');
  }
});

app.listen(3000);

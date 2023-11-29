const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const uuid = require('uuid');

const db = require('../lib/db.js');
const userMiddleware = require('../middleware/users.js');
const blacklist = new Set();

// http://localhost:3000/api/sign-up
router.post('/sign-up', userMiddleware.validateRegister, (req, res, next) => {
  db.query(
    'SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)',
    [req.body.username, req.body.email],
    (err, result) => {
      if (result && result.length) {
        // error
        return res.status(409).send({
          message: 'This username or email is already in use!',
        });
      } else {
        // username and email not in use
        bcrypt.hash(req.body.password, 10, (err, hash) => {
          if (err) {
            return res.status(500).send({
              message: err,
            });
          } else {
            db.query(
              'INSERT INTO users (id, username, email, password, registered) VALUES (?, ?, ?, ?, now());',
              [uuid.v4(), req.body.username, req.body.email, hash],
              (err, result) => {
                if (err) {
                  return res.status(400).send({
                    message: err,
                  });
                }
                return res.status(201).send({
                  message: 'Registered!',
                });
              }
            );
          }
        });
      }
    }
  );
});


// http://localhost:3000/api/login
router.post('/login', (req, res, next) => {
  const loginIdentifier = req.body.usernameOrEmail; // Add a field in your login form to input either username or email

  db.query(
    `SELECT * FROM users WHERE username = ? OR email = ?;`,
    [loginIdentifier, loginIdentifier],
    (err, result) => {
      if (err) {
        return res.status(400).send({
          message: err,
        });
      }
      if (!result.length) {
        return res.status(400).send({
          message: 'Username or email or password incorrect!',
        });
      }

      bcrypt.compare(
        req.body.password,
        result[0]['password'],
        (bErr, bResult) => {
          if (bErr) {
            return res.status(400).send({
              message: 'Username or email or password incorrect!',
            });
          }
          if (bResult) {
            // password match
            const token = jwt.sign(
              {
                username: result[0].username,
                userId: result[0].id,
              },
              'SECRETKEY',
              { expiresIn: '7d' }
            );
            db.query(`UPDATE users SET last_login = now() WHERE id = ?;`, [
              result[0].id,
            ]);
            return res.status(200).send({
              message: 'Logged in!',
              token,
              user: result[0],
            });
          }
          return res.status(400).send({
            message: 'Username or email or password incorrect!',
          });
        }
      );
    }
  );
});


// http://localhost:3000/api/secret-route
router.get('/secret-route', userMiddleware.isLoggedIn, (req, res, next) => {
  console.log(req.userData);
  res.send('This is secret content!');
});

// http://localhost:3000/api/change-username
router.post('/change-username', userMiddleware.isLoggedIn, (req, res) => {
  const userId = req.userData.userId;
  const newUsername = req.body.newUsername;

  // Lakukan validasi dan perubahan nama pengguna di dalam database
  if (newUsername.length < 3) {
    return res.status(400).json({ message: 'New username must be at least 3 characters long' });
  }

  db.query('UPDATE users SET username = ? WHERE id = ?', [newUsername, userId], (err, result) => {
    if (err) {
      console.error('Error:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }

    if (result.affectedRows > 0) {
      return res.status(200).json({ message: 'Username changed successfully' });
    } else {
      return res.status(400).json({ message: 'Failed to change username' });
    }
  });

  // return res.status(200).json({ message: 'Username changed successfully' });
});


// router.post('/logout', userMiddleware.isLoggedIn, (req, res) => {
//   // Optionally: Add the user's token to a blacklist on the server
//   const userToken = req.headers.authorization.split(' ')[1];
//   blacklist.add(userToken);

//   // Clear the token on the client side (assuming it's stored in localStorage)
//   res.status(200).send({ message: 'Logout successful' });
// });

router.delete('/logout', userMiddleware.isLoggedIn, (req, res) => {
  // Optionally: Add the user's token to a blacklist on the server
  const userToken = req.headers.authorization.split(' ')[1];

  // Check if the token is already in the blacklist
  if (blacklist.has(userToken)) {
    return res.status(401).json({ message: 'Token already blacklisted' });
  }

  // Add the token to the blacklist
  blacklist.add(userToken);

  // Clear the token on the client side (assuming it's stored in localStorage)
  res.status(200).json({ message: 'Logout successful' });
});



module.exports = router;
const jwt = require('jsonwebtoken');

module.exports = {
  validateRegister: (req, res, next) => {
    // username min length 3
    if (!req.body.username || req.body.username.length < 3) {
      return res.status(400).send({
        message: 'Please enter a username with min. 3 chars',
      });
    }

    // email validation
    if (!req.body.email || !isValidEmail(req.body.email)) {
      return res.status(400).send({
        message: 'Please enter a valid email address',
      });
    }

    // password min 6 chars
    if (!req.body.password || req.body.password.length < 6) {
      return res.status(400).send({
        message: 'Please enter a password with min. 6 chars',
      });
    }

    // password (repeat) must match
    if (
      !req.body.password_repeat ||
      req.body.password !== req.body.password_repeat
    ) {
      return res.status(400).send({
        message: 'Both passwords must match',
      });
    }

    next();
  },

  isLoggedIn: (req, res, next) => {
    if (!req.headers.authorization) {
      return res.status(400).send({
        message: 'Your session is not valid!',
      });
    }

    try {
      const authHeader = req.headers.authorization;
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, process.env.SECRET_KEY);
      req.userData = decoded;
      next();
    } catch (err) {
      return res.status(400).send({
        message: 'Your session is not valid!',
      });
    }
  },
};

function isValidEmail(email) {
  // Use a regular expression to validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function changeUsername(newUsername) {
  const token = localStorage.getItem('token'); // Ambil token dari local storage
  const userId = localStorage.getItem('userId'); // Ambil ID pengguna dari local storage atau state aplikasi

  fetch('http://localhost:3000/api/change-username', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      userId: userId,
      newUsername: newUsername,
    }),
  })
  .then(response => {
    if (!response.ok) {
      throw new Error('Failed to change username');
    }
    return response.json();
  })
  .then(data => {
    console.log(data);
  })
  .catch(error => console.error('Error:', error));
  
}

function logout() {
  const token = localStorage.getItem('token');

  fetch('http://localhost:3000/api/logout', {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  })
    .then(response => {
      if (!response.ok) {
        throw new Error('Failed to logout');
      }
      localStorage.removeItem('token');
      console.log('Logout successful');
    })
    .catch(error => console.error('Error:', error));
}


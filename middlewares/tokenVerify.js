const jwt = require('jsonwebtoken');

const tokenVerify = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ message: 'Authorization header missing or invalid' });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send({ message: 'Invalid token' });
        }

        req.user = decoded; // Attach user info to the request
        next();
    });
};

module.exports = tokenVerify;

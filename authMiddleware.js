const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Accès refusé. Aucun token fourni.' });
    }

    const token = authHeader.split(' ')[1];
    const secret = process.env.JWT_SECRET || 'fallback_secret_pour_soutenance';

    const decodedToken = jwt.verify(token, secret);
    
    req.auth = {
      userId: decodedToken.id,
      role: decodedToken.role
    };

    next();

  } catch (error) {
    console.error("❌ ERREUR TOKEN :", error.message);
    return res.status(401).json({ message: 'Token invalide ou expiré.' });
  }
};

module.exports = authMiddleware;
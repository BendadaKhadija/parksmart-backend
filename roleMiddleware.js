// On importe l'outil JWT
const jwt = require('jsonwebtoken');

// C'est notre "Gardien"
const authMiddleware = (req, res, next) => {
  try {
    // 1. Récupérer le token en toute sécurité (sans faire crasher le serveur s'il est absent)
    const authHeader = req.headers.authorization || req.headers.Authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Accès refusé. Aucun token fourni.' });
    }

    // 2. Extraire le token
    const token = authHeader.split(' ')[1];

    // 3. 🚨 LA CORRECTION EST ICI : Le même secret de secours que dans server.js !
    const secret = process.env.JWT_SECRET || 'fallback_secret_pour_soutenance';

    // 4. Vérifier si le token est valide
    const decodedToken = jwt.verify(token, secret);

    // 5. Ajouter ces infos à l'objet "req"
    req.auth = {
      userId: decodedToken.id,
      role: decodedToken.role
    };

    // 6. Tout est bon, on laisse passer à la suite !
    next();

  } catch (error) {
    console.error("Erreur Middleware :", error.message);
    res.status(401).json({ message: 'Accès non autorisé. Token invalide ou expiré.' });
  }
};

module.exports = authMiddleware;
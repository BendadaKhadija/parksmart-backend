const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  console.log(`\n=== 🚨 TENTATIVE D'ACCÈS À : ${req.method} ${req.originalUrl || req.url} ===`);
  
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    console.log("1. Header reçu :", authHeader ? "OUI" : "NON");

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log("❌ ERREUR : Aucun token Bearer trouvé dans l'en-tête.");
      return res.status(401).json({ message: 'Accès refusé. Aucun token fourni.' });
    }

    const token = authHeader.split(' ')[1];
    const secret = process.env.JWT_SECRET || 'fallback_secret_pour_soutenance';

    console.log("2. Token extrait, vérification en cours...");
    
    // C'est ici que ça plante normalement, voyons pourquoi !
    const decodedToken = jwt.verify(token, secret);

    console.log("3. ✅ Succès ! Token valide pour l'utilisateur ID :", decodedToken.id, "| Rôle :", decodedToken.role);
    
    req.auth = {
      userId: decodedToken.id,
      role: decodedToken.role
    };

    next();

  } catch (error) {
    console.error("❌ ERREUR FATALE MIDDLEWARE :", error.message);
    // On renvoie la vraie raison au Frontend !
    return res.status(401).json({ 
        message: 'Token invalide ou expiré.', 
        raison_exacte: error.message 
    });
  }
};

module.exports = authMiddleware;
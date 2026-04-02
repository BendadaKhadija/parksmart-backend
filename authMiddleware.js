// On importe l'outil JWT
const jwt = require('jsonwebtoken');
// On s'assure que les variables d'environnement sont chargées
require('dotenv').config();

// C'est notre "Gardien"
const authMiddleware = (req, res, next) => {
  try {
    // 1. Récupérer le token dans l'en-tête de la requête
    // Le format est "Bearer VOTRE_LONG_TOKEN"
    const token = req.headers.authorization.split(' ')[1];

    // 2. Vérifier si le token est valide en utilisant le secret depuis .env
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    // 3. Extraire l'ID et le rôle de l'utilisateur du token
    const userId = decodedToken.id;
    const userRole = decodedToken.role;

    // 4. Ajouter ces infos à l'objet "req" pour que la prochaine fonction puisse les utiliser
    req.auth = {
      userId: userId,
      role: userRole
    };

    // 5. Tout est bon, on laisse passer à la suite !
    next();

  } catch (error) {
    // S'il n'y a pas de token, ou s'il est faux, on renvoie une erreur
    res.status(401).json({ message: 'Accès non autorisé. Token invalide ou manquant.' });
  }
};

// On exporte le gardien pour que server.js puisse l'utiliser
module.exports = authMiddleware;
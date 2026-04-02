// Middleware pour vérifier les rôles
const roleMiddleware = (allowedRoles) => {
  return (req, res, next) => {
    try {
      // On vérifie si req.auth existe (il a été créé par authMiddleware juste avant)
      if (!req.auth || !req.auth.role) {
        return res.status(403).json({ message: "Accès interdit. Impossible de vérifier votre rôle." });
      }

      // On vérifie si le rôle de l'utilisateur est dans la liste des rôles autorisés
      if (!allowedRoles.includes(req.auth.role)) {
        return res.status(403).json({ message: "Accès refusé. Vous n'avez pas les droits nécessaires." });
      }

      // Si tout est bon, on le laisse passer
      next();
    } catch (error) {
      console.error("Erreur Role Middleware :", error);
      return res.status(500).json({ message: "Erreur interne lors de la vérification des droits." });
    }
  };
};

module.exports = roleMiddleware;
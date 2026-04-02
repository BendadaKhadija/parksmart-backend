const roleMiddleware = (allowedRoles) => {
  return (req, res, next) => {
    try {
      // On vérifie si le videur (authMiddleware) a bien validé le badge avant
      if (!req.auth || !req.auth.role) {
        return res.status(403).json({ message: "Accès interdit. Impossible de lire votre rôle." });
      }

      // On vérifie si le rôle est autorisé pour cette action
      if (!allowedRoles.includes(req.auth.role)) {
        return res.status(403).json({ message: "Accès refusé. Vous n'avez pas les droits nécessaires." });
      }

      // C'est bon, tu passes !
      next();
    } catch (error) {
      console.error("Erreur Role Middleware :", error);
      return res.status(500).json({ message: "Erreur interne de vérification." });
    }
  };
};

module.exports = roleMiddleware;
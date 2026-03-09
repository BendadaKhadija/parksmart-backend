// C'est un "créateur" de gardien.
// Il prend une liste de rôles autorisés...
const roleMiddleware = (roles) => {
  
  // ...et il renvoie un gardien (middleware)
  return (req, res, next) => {
    
    // On suppose que le gardien "authMiddleware" a déjà tourné avant
    // et qu'il nous a donné le rôle de l'utilisateur dans "req.auth.role"
    
    // Si le rôle de l'utilisateur n'est PAS dans la liste des rôles autorisés...
    if (!roles.includes(req.auth.role)) {
      // ...on le bloque !
      return res.status(403).json({ message: 'Accès refusé. Vous n\'avez pas les droits nécessaires.' });
    }
    
    // C'est bon, il a le bon rôle. On le laisse passer.
    next();
  };
};

// On exporte notre "créateur" de gardien
module.exports = roleMiddleware;
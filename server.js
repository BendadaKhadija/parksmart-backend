// Forcer le redéploiement Railway - v2
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const admin = require('firebase-admin');
const cron = require('node-cron');
// Remplacez : const serviceAccount = require('./firebase-key.json');
// Par ceci 👇
require('dotenv').config(); 
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);


admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const app = express();
app.use(express.json());
app.use(cors());
// Création du dossier 'uploads' s'il n'existe pas
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Configuration du stockage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        // Nom unique : date + nom original
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// IMPORTANT : Rendre le dossier accessible publiquement
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
const port = process.env.PORT || 8000;

// ==========================================
// 1. CONNEXION BDD
// ==========================================
const db = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '', 
  database: process.env.DB_NAME || 'parksmart_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test de connexion au démarrage
db.getConnection()
    .then(connection => {
        console.log("✅ Connecté à la base de données MySQL !");
        connection.release();
    })
    .catch(err => {
        console.error("❌ Erreur de connexion BDD :", err.message);
    });

// ==========================================
// 2. MIDDLEWARE D'AUTHENTIFICATION
// ==========================================
const authMiddleware = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Accès refusé. Token manquant.' });

  try {
    const decoded = jwt.verify(token, 'MON_SUPER_SECRET');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: 'Token invalide.' });
  }
};
// --- MIDDLEWARE D'AUTHENTIFICATION ---
function authenticateToken(req, res, next) {
    // Récupérer le header "Authorization: Bearer <TOKEN>"
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401); // Pas de token envoyé

    // Vérifier le token
    // ATTENTION : 'MON_SUPER_SECRET' doit être le même que celui utilisé dans /login
    jwt.verify(token, 'MON_SUPER_SECRET', (err, user) => {
        if (err) return res.sendStatus(403); // Token invalide ou expiré
        req.user = user; // On attache l'utilisateur à la requête
        next(); // On passe à la suite (la route)
    });
}
// ==========================================
// 3. ROUTES AUTHENTIFICATION
// ==========================================

// INSCRIPTION 
app.post('/api/auth/signup', upload.single('image'), async (req, res) => {
  try {
    // req.body contient le texte (nom, email...)
    const { nom,prenom, email, password, role } = req.body; 
    
    // req.file contient l'image (si envoyée)
    // Si il y a une image, on crée le chemin, sinon on met null
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    if (!nom || !prenom || !email || !password) {
      return res.status(400).json({ message: 'Champs manquants' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    if (role === 'gestionnaire') {
        // ⚠️ AJOUT de la colonne photo dans la requête SQL
        await db.query(
            'INSERT INTO GESTIONNAIRE (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
            [nom,prenom, email, hashedPassword, photoPath]
        );
    } else {
        // ⚠️ AJOUT de la colonne photo dans la requête SQL
        await db.query(
            'INSERT INTO CONDUCTEUR (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
            [nom,prenom, email, hashedPassword, photoPath]
        );
    }
    
    res.status(201).json({ message: 'Compte créé avec succès !' });

  } catch (error) {
    console.error("Erreur Inscription :", error);
    res.status(500).json({ message: "Erreur serveur ou Email déjà utilisé." });
  }
});

// CONNEXION
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    let user = null;
    let role = '';
    let userId = null;
    

    // 1. Chercher dans CONDUCTEUR
    const [conds] = await db.query('SELECT * FROM CONDUCTEUR WHERE email = ?', [email]);
    if (conds.length > 0) {
      user = conds[0];
      role = 'conducteur';
      userId = user.id_cond;
    } else {
      // 2. Chercher dans GESTIONNAIRE
      const [gests] = await db.query('SELECT * FROM GESTIONNAIRE WHERE email = ?', [email]);
      if (gests.length > 0) {
        user = gests[0];
        role = 'gestionnaire';
        userId = user.id_gest; 
      }
    }

    if (!user) return res.status(404).json({ message: 'Email inconnu.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Mot de passe incorrect.' });

    const token = jwt.sign({ id: userId, role: role }, 'MON_SUPER_SECRET', { expiresIn: '24h' });

    res.json({ 
      token, 
      user: { id: userId, nom: user.nom, email: user.email, role: role,photo: user.photo} 
    });

  } catch (error) {
    console.error("Erreur Login :", error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});
app.post('/api/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    
    // 1. Demander à Firebase de vérifier si le token est un vrai
    const decodedToken = await admin.auth().verifyIdToken(token);
    
    // On récupère les infos sécurisées de Google
    const email = decodedToken.email;
    const nomComplet = decodedToken.name || 'Utilisateur Google';
    const photo = decodedToken.picture || null;

    // Petite astuce pour séparer Nom et Prénom (si Google donne tout d'un coup)
    const [prenom, ...nomArray] = nomComplet.split(' ');
    const nom = nomArray.join(' ') || prenom; 

    let user = null;
    let role = '';
    let userId = null;

    // 2. Chercher dans CONDUCTEUR
    const [conds] = await db.query('SELECT * FROM CONDUCTEUR WHERE email = ?', [email]);
    if (conds.length > 0) {
      user = conds[0];
      role = 'conducteur';
      userId = user.id_cond;
    } else {
      // 3. Chercher dans GESTIONNAIRE
      const [gests] = await db.query('SELECT * FROM GESTIONNAIRE WHERE email = ?', [email]);
      if (gests.length > 0) {
        user = gests[0];
        role = 'gestionnaire';
        userId = user.id_gest;
      }
    }

    // 4. SI L'UTILISATEUR N'EXISTE PAS : On le crée automatiquement !
    if (!user) {
      console.log("Nouvel utilisateur Google détecté, création du compte...");
      
      const [result] = await db.query(
        'INSERT INTO CONDUCTEUR (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
        [nom, prenom, email, 'google_sso_no_password', photo] 
      );
      
      userId = result.insertId;
      role = 'conducteur';
      user = { id_cond: userId, nom: nom, prenom: prenom, email: email, photo: photo };
    }

    // 5. Générer TON token
    const jwtToken = jwt.sign({ id: userId, role: role }, 'MON_SUPER_SECRET', { expiresIn: '24h' });

    console.log(`✅ Connexion Google réussie pour : ${email}`);

    // 6. Renvoyer au front
    res.json({ 
      token: jwtToken, 
      user: { 
          id: userId, 
          nom: user.nom, 
          email: user.email, 
          role: role, 
          photo: user.photo || photo 
      } 
    });

  } catch (error) {
    console.error("❌ Erreur Google Login Backend :", error);
    res.status(401).json({ message: 'Token Google invalide, expiré ou refusé.' });
  }
});

// ==========================================
// 4. ROUTES ADMIN (GESTIONNAIRE)
// ==========================================

// AJOUTER PARKING + GENERER PLACES
app.post('/api/admin/parking', authMiddleware, async (req, res) => {
    // Vérification de sécurité
    if (req.user.role !== 'gestionnaire') return res.status(403).json({ message: "Interdit." });

    // 🔴 CORRECTION ICI : On ajoute latitude, longitude et image_url dans la récupération
    const { 
        nom, 
        adresse, 
        tarif_heure, 
        nb_rangees, 
        nb_places_par_rangee, 
        latitude,   // <--- Ajouté
        longitude,  // <--- Ajouté
        image_url   // <--- Ajouté (le front envoie souvent image_url, pas image)
    } = req.body;

    const id_gest = req.user.id;
    
    // DEBUG: On log tout le body pour être sûr
    console.log("📥 DONNÉES REÇUES COMPLÈTES :", req.body); 

    // Validation des données (Ajoutez latitude/longitude si obligatoire)
    if (!nom || !adresse || !tarif_heure) {
        return res.status(400).json({ message: "Champs obligatoires manquants" });
    }

    const connection = await db.getConnection(); 
    try {
        await connection.beginTransaction();

        // 🔴 CORRECTION DANS LA REQUÊTE SQL
        // On mappe 'image_url' (du front) vers la colonne 'image' (de la BDD)
        const [result] = await connection.query(
            "INSERT INTO PARKING (nom, adresse, tarif_heure, image, latitude, longitude, nb_rangees, nb_places_par_rangee, id_gest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                nom, 
                adresse, 
                tarif_heure,
                image_url ?? null, // Garder null si non défini
                latitude ?? null,  // Garder null si non défini
                longitude ?? null, // Garder null si non défini
                nb_rangees || 0, 
                nb_places_par_rangee || 0, 
                id_gest
            ]
        );
        
        // Générer les places
        const places = [];
        for (let rangee = 1; rangee <= nb_rangees; rangee++) {
            for (let place = 1; place <= nb_places_par_rangee; place++) {
                places.push({
                    numero: `${rangee}-${place}`,
                    id_park: result.insertId,
                    disponibilite: 1
                });
            }
        }

        if (places.length > 0) {
            await connection.query(
                "INSERT INTO PLACE (numero, id_park, disponibilite) VALUES ?",
                [places.map(p => [p.numero, p.id_park, p.disponibilite])]
            );
        }

        await connection.commit();
        res.status(201).json({ message: "✅ Parking créé avec succès !", id_parking: result.insertId });
    } catch (error) {
        await connection.rollback();
        console.error("❌ Erreur création parking :", error);
        res.status(500).json({ error: "Erreur lors de la création du parking" });
    } finally {
        connection.release();
    }
});

// LISTER MES PARKINGS (GESTIONNAIRE) - C'est la route qui te manquait !
app.get('/api/my-parkings/:id', async (req, res) => {
    try {
        const idGest = req.params.id;
        const [results] = await db.query("SELECT * FROM PARKING WHERE id_gest = ?", [idGest]);
        res.status(200).json(results);
    } catch (error) {
        console.error("Erreur récupération mes parkings:", error);
        res.status(500).json({ error: "Erreur base de données" });
    }
});

// 1. SUPPRIMER UN PARKING (CORRIGÉ AVEC PAIEMENTS ET AVIS)
app.delete('/api/parkings/:id', async (req, res) => {
    const id = req.params.id;
    
    try {
        console.log(`Tentative de suppression du parking ${id}...`);

        // ÉTAPE 1 : Supprimer les PAIEMENTS liés aux réservations de ce parking
        await db.query(`
            DELETE FROM PAIEMENT 
            WHERE id_resa IN (
                SELECT id_resa FROM RESERVATION 
                WHERE id_place IN (SELECT id_place FROM PLACE WHERE id_park = ?)
            )
        `, [id]);

        // ÉTAPE 2 : Supprimer les RÉSERVATIONS liées aux places de ce parking
        await db.query(`
            DELETE FROM RESERVATION 
            WHERE id_place IN (SELECT id_place FROM PLACE WHERE id_park = ?)
        `, [id]);

        // ÉTAPE 3 : Supprimer les PLACES de ce parking
        await db.query("DELETE FROM PLACE WHERE id_park = ?", [id]);

        // ÉTAPE 4 (NOUVELLE) : Supprimer les AVIS liés à ce parking
        await db.query("DELETE FROM AVIS WHERE id_park = ?", [id]);

        // ÉTAPE 5 : Enfin, supprimer le PARKING
        const [result] = await db.query("DELETE FROM PARKING WHERE id_park = ?", [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Parking introuvable." });
        }

        console.log("✅ Parking, places, réservations, paiements et avis supprimés avec succès !");
        res.json({ message: "Parking et toutes ses données supprimés avec succès !" });

    } catch (error) {
        console.error("❌ Erreur SQL lors de la suppression :", error);
        res.status(500).json({ error: "Erreur interne (voir terminal pour détails)" });
    }
});
// --- Route pour MODIFIER un parking (Sécurisée) ---
// J'ai ajouté 'authMiddleware' ici pour protéger la route
app.put('/api/parkings/:id', authMiddleware, async (req, res) => {
    const id = req.params.id;
    // 1. On ne récupère PLUS nb_rangees et nb_places_par_rangee
    const { nom, adresse, tarif_heure } = req.body;

    console.log(`📡 MODIFICATION PARKING ${id}`);

    const tarif = parseFloat(tarif_heure);

    try {
        // 2. On met à jour uniquement le nom, l'adresse et le tarif
        const sql = `
            UPDATE PARKING 
            SET nom = ?, 
                adresse = ?, 
                tarif_heure = ?
            WHERE id_park = ?`;

        const [result] = await db.query(sql, [nom, adresse, tarif, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Parking introuvable (ID incorrect)" });
        }

        res.json({ message: "✅ Parking modifié avec succès" });

    } catch (error) {
        console.error("❌ Erreur SQL Update :", error);
        res.status(500).json({ error: "Erreur serveur lors de la modification" });
    }
});
// MISE À JOUR PROFIL GESTIONNAIRE (CORRIGÉE)
app.put('/api/manager/update', authMiddleware, upload.single('image'), async (req, res) => {
    console.log("📝 Update Profil demandé...");

    // Le front envoie 'id_user', 'nom', 'email' via FormData
    const { id_user, nom, email } = req.body; 
    
    // Si une nouvelle image est uploadée
    const newPhotoPath = req.file ? `/uploads/${req.file.filename}` : null;

    if (!id_user) return res.status(400).json({ error: "ID utilisateur manquant" });

    try {
        let sql;
        let params;

        if (newPhotoPath) {
            // Mise à jour AVEC photo (Attention: colonne 'photo' ou 'image' ? Vérifie ta BDD. Je mets 'photo' comme dans ton signup)
            sql = "UPDATE GESTIONNAIRE SET nom=?, email=?, photo=? WHERE id_gest=?";
            params = [nom, email, newPhotoPath, id_user];
        } else {
            // Mise à jour SANS photo
            sql = "UPDATE GESTIONNAIRE SET nom=?, email=? WHERE id_gest=?";
            params = [nom, email, id_user];
        }

        const [result] = await db.query(sql, params);

        if (result.affectedRows === 0) return res.status(404).json({ message: "Utilisateur non trouvé" });

        res.json({ message: "Mise à jour réussie", newImage: newPhotoPath });

    } catch (error) {
        console.error("❌ Erreur Update Profil:", error);
        res.status(500).json({ error: "Erreur base de données" });
    }
});
// --- ROUTE PUBLIQUE : RECUPERER TOUS LES PARKINGS (POUR LE CLIENT) ---
app.get('/api/parkings', async (req, res) => {
    try {
        console.log("Client demande la liste des parkings...");
        const [rows] = await db.query("SELECT * FROM PARKING");
        res.json(rows);
    } catch (error) {
        console.error("Erreur récupération tous les parkings :", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// ==========================================
// ROUTE : MISE À JOUR PROFIL 
// ==========================================
app.post('/api/user/update', authMiddleware, upload.single('avatar'), async (req, res) => {
    console.log("📝 Demande de mise à jour profil reçue...");

    const userId = req.user.id; 
    const userRole = req.user.role; // 'conducteur' ou 'gestionnaire'

    // 1. On récupère TOUS les champs (nom, prenom, email)
    const { nom, prenom, email } = req.body;
    
    // Chemin image
    const newPhotoPath = req.file ? `/uploads/${req.file.filename}` : null;

    if (!userId) return res.status(400).json({ error: "Utilisateur non identifié." });

    try {
        let sql;
        let params;
        
        // --- LOGIQUE SPÉCIFIQUE CONDUCTEUR (Avec Prénom) ---
        if (userRole === 'conducteur' || userRole === 'client') { 
            // Note: Vérifiez si votre rôle s'appelle 'conducteur' ou 'client' dans le token
            
            let querySet = "UPDATE CONDUCTEUR SET nom=?, prenom=?, email=?";
            let queryParams = [nom, prenom, email];

            if (newPhotoPath) {
                querySet += ", photo=?"; // ou image=? selon votre BDD
                queryParams.push(newPhotoPath);
            }

            sql = `${querySet} WHERE id_cond=?`;
            params = [...queryParams, userId];
        } 
        // --- LOGIQUE GESTIONNAIRE (Sans Prénom, si applicable) ---
        else {
            let querySet = "UPDATE GESTIONNAIRE SET nom=?, email=?";
            let queryParams = [nom, email];

            if (newPhotoPath) {
                querySet += ", photo=?";
                queryParams.push(newPhotoPath);
            }

            sql = `${querySet} WHERE id_gest=?`;
            params = [...queryParams, userId];
        }

        const [result] = await db.query(sql, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Utilisateur introuvable." });
        }

        console.log(`✅ Profil ${userRole} mis à jour avec succès !`);
        
        res.json({ 
            message: "Mise à jour réussie", 
            avatar: newPhotoPath,
            user: { nom, prenom, email }
        });

    } catch (error) {
        console.error("❌ Erreur Update Profil:", error);
        res.status(500).json({ error: "Erreur base de données", details: error.message });
    }
});
// ==========================================
// 5. ROUTES CLIENT (MAP & RESERVATION)
// ==========================================

// Récupérer la MAP (Configuration + État des places)
app.get('/api/parking-map/:id', async (req, res) => {
    try {
        const parkingId = req.params.id;

        // 1. Récupérer config
        const [parkingInfo] = await db.query(
            "SELECT nb_rangees, nb_places_par_rangee FROM PARKING WHERE id_park = ?", // Vérifie si c'est 'id' ou 'id_park' dans ta base
            [parkingId]
        );

        if (parkingInfo.length === 0) return res.status(404).json({message: "Parking introuvable"});

        // 2. Récupérer places + statuts
        const query = `
            SELECT 
                p.id_place, 
                p.numero, 
                CASE 
                    WHEN r.id_resa IS NOT NULL THEN 'occupé' 
                    ELSE 'libre' 
                END as statut_actuel
            FROM PLACE p
            LEFT JOIN RESERVATION r ON p.id_place = r.id_place AND r.date_depart IS NULL
            WHERE p.id_park = ?
            ORDER BY p.id_place ASC
        `;
        
        const [places] = await db.query(query, [parkingId]);

        res.json({
            config: parkingInfo[0],
            places: places 
        });

    } catch (err) {
        console.error("Erreur Map :", err);
        res.status(500).json({ error: err.message });
    }
});
app.get('/api/places/:id_park', async (req, res) => {
    try {
        const id = req.params.id_park;
        // AJOUT DE "ORDER BY id_place ASC" POUR GARANTIR L'ORDRE DE LA GRILLE
        const [rows] = await db.query("SELECT * FROM PLACE WHERE id_park = ? ORDER BY id_place ASC", [id]);
        res.json(rows);
    } catch (err) {
        console.error("Erreur récupération places:", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Démarrer une réservation (Client)
app.post('/api/reservation/start', authenticateToken, async (req, res) => {
    // Vérification du rôle
    if (req.user.role !== 'conducteur') return res.sendStatus(403);

    const { id_place } = req.body;
    const id_cond = req.user.id; 

    try {
        // 1. Vérifier si le conducteur a DÉJÀ une réservation active
        const [activeRes] = await db.query(
            'SELECT * FROM RESERVATION WHERE id_cond = ? AND date_depart IS NULL',
            [id_cond]
        );

        if (activeRes.length > 0) {
            return res.status(400).json({ message: "Vous avez déjà une réservation en cours." });
        }

        // 2. Vérifier si la place est libre et récupérer l'ID du parking
        // CORRECTION : On utilise 'disponibilite' (pas 'statu')
        const [placeStatus] = await db.query(
            'SELECT disponibilite, id_park FROM PLACE WHERE id_place = ?', 
            [id_place]
        );

        if (placeStatus.length === 0) {
            return res.status(404).json({ message: "Place introuvable." });
        }

        // Si disponibilite == 0, c'est occupé (selon ta logique ailleurs dans le code)
        if (placeStatus[0].disponibilite == 0) {
            return res.status(400).json({ message: "Cette place est déjà occupée." });
        }

        const id_park = placeStatus[0].id_park;

        // 3. Créer la réservation
        const [result] = await db.query(
            'INSERT INTO RESERVATION (date_arrivee, id_cond, id_place) VALUES (NOW(), ?, ?)',
            [id_cond, id_place]
        );

        // 4. Mettre la place en 'occupé'
        // CORRECTION : On met 'disponibilite' à 0
        await db.query('UPDATE PLACE SET disponibilite = 0 WHERE id_place = ?', [id_place]);

        res.json({ 
            message: "Réservation démarrée !", 
            id_res: result.insertId,
            place: id_place
        });

    } catch (err) {
        console.error("Erreur Reservation Start :", err); // Le log sera plus précis
        res.status(500).json({ message: "Erreur serveur lors de la réservation." });
    }
});
// ==========================================
// ROUTE : Vérifier réservation active (HYBRIDE)
// ==========================================
app.get('/api/reservation/active', async (req, res) => {
    try {
        let userId = null;

        // 1. On essaie de lire l'ID depuis l'URL (?userId=3)
        if (req.query.userId) {
            userId = req.query.userId;
        } 
        // 2. Sinon, on essaie de lire depuis le Token (si envoyé)
        else if (req.headers['authorization']) {
             // Décoder le token manuellement ou via middleware si tu préfères
             const token = req.headers['authorization'].split(' ')[1];
             const decoded = jwt.verify(token, 'MON_SUPER_SECRET');
             userId = decoded.id;
        }

        if (!userId) {
            return res.status(400).json({ message: "ID utilisateur manquant (via token ou ?userId=)" });
        }

        const [rows] = await db.query(
            "SELECT *, TIMESTAMPDIFF(SECOND, date_arrivee, NOW()) AS temps_ecoule_secondes FROM RESERVATION WHERE id_cond = ? AND date_depart IS NULL ORDER BY date_arrivee DESC LIMIT 1",
            [userId]
        );

        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            // Important : Renvoyer 404 est normal si pas de réservation, le front le gère
            res.status(404).json({ message: "Aucune réservation active" });
        }
    } catch (err) {
        console.error("Erreur Active Resa:", err.message);
        // On renvoie 404 pour ne pas bloquer le front s'il y a un souci technique
        res.status(404).send("Erreur ou pas de réservation");
    }
});
// ==========================================
//  STOP RESERVATION + LIBÉRATION PLACE
// ==========================================
app.post('/api/reservation/stop', async (req, res) => {
    const { id_resa } = req.body;

    console.log("🛑 Tentative d'arrêt réservation ID :", id_resa);

    if (!id_resa) {
        return res.status(400).json({ error: "ID réservation manquant" });
    }

    const connection = await db.getConnection(); // On prend une connexion dédiée pour la transaction

    try {
        await connection.beginTransaction(); // Début transaction (sécurité)

        // 1. Récupérer les infos de la réservation (Date début + ID Place)
        const [rows] = await connection.query(
            "SELECT * FROM RESERVATION WHERE id_resa = ?", 
            [id_resa]
        );

        if (rows.length === 0) {
            await connection.rollback();
            return res.status(404).json({ error: "Réservation introuvable" });
        }

        const resa = rows[0];

        // Vérification si déjà terminée
        if (resa.date_depart !== null) {
            await connection.rollback();
            return res.status(400).json({ message: "Cette réservation est déjà terminée." });
        }

        // 2. Calcul du prix
        const dateDebut = new Date(resa.date_arrivee);
        const dateFin = new Date();
        
        // Calcul durée en millisecondes
        let diffMs = dateFin - dateDebut;
        if (diffMs < 0) diffMs = 0; 

        // Conversion en heures (arrondi supérieur)
        const diffSeconds = Math.floor(diffMs / 1000);
        const hours = Math.ceil(diffSeconds / 3600); // Ex: 1h05 = 2h payantes
        const minutes = Math.floor((diffSeconds % 3600) / 60);

        // Tarif fixe ou récupéré du parking (ici je mets ton calcul hardcodé 4.00 DH/h)
        // Idéalement, il faudrait faire une jointure avec PARKING pour avoir le vrai tarif_heure
        const tarifHoraire = 4.00; 
        const montant = (Math.max(1, hours) * tarifHoraire).toFixed(2); // Minimum 1h facturée

        console.log(`💰 Calcul: ${hours}h * ${tarifHoraire} = ${montant} DH`);

        // 3. Mettre à jour la Réservation (Date fin + Prix)
        await connection.query(
            "UPDATE RESERVATION SET date_depart = ?, prix_total = ? WHERE id_resa = ?",
            [dateFin, montant, id_resa]
        );

        // 4. LIBÉRER LA PLACE (C'était l'oubli critique !)
        // On remet disponibilite à 1 (Libre)
        await connection.query(
            "UPDATE PLACE SET disponibilite = 1 WHERE id_place = ?",
            [resa.id_place]
        );

        await connection.commit(); // Valider tout
        connection.release();

        console.log("✅ Réservation terminée et place libérée.");

        res.json({
            success: true,
            id_resa: id_resa,
            montant: montant,
            duree: `${Math.floor(diffSeconds / 3600)}h ${minutes}m`,
            date_fin: dateFin
        });

    } catch (error) {
        await connection.rollback(); // Annuler si erreur
        connection.release();
        console.error("❌ Erreur Stop Réservation :", error);
        res.status(500).json({ error: "Erreur serveur lors de l'arrêt" });
    }
});
// CONFIRMATION PAIEMENT + CLÔTURE RÉSERVATION + LIBÉRATION PLACE
app.post('/api/paiement/confirm', async (req, res) => {
    console.log("💳 Validation finale du paiement...");
    const { id_resa, montant, mode } = req.body;

    if (!id_resa || !montant) {
        return res.status(400).json({ success: false, message: "Données manquantes." });
    }

    try {
        const datePaiement = new Date();

        // 1. Enregistrer le PAIEMENT
        await db.query(
            "INSERT INTO PAIEMENT (id_resa, montant, date, mode) VALUES (?, ?, ?, ?)",
            [id_resa, montant, datePaiement, mode]
        );

        // 2. Mettre à jour la RÉSERVATION (Date de fin et Prix final)
        // NOW() permet d'avoir l'heure exacte du serveur SQL
        await db.query(
            "UPDATE RESERVATION SET date_depart = NOW(), prix_total = ? WHERE id_resa = ?",
            [montant, id_resa]
        );

        // 3. Libérer la PLACE (Remettre disponibilite à 1)
        // On cherche d'abord quelle place correspond à cette réservation
        await db.query(
            `UPDATE PLACE 
             JOIN RESERVATION ON PLACE.id_place = RESERVATION.id_place 
             SET PLACE.disponibilite = 1 
             WHERE RESERVATION.id_resa = ?`,
            [id_resa]
        );

        console.log("✅ Cycle complet terminé : Payé, Fermé, Libéré.");
        res.json({ success: true, message: "Paiement validé et réservation clôturée !" });

    } catch (err) {
        console.error("❌ Erreur SQL Finale :", err);
        res.status(500).json({ success: false, message: "Erreur serveur", details: err.sqlMessage });
    }
});
// ==========================================
// ROUTE : Historique Visuel (SÉCURISÉE 🔒)
// ==========================================
// 1. On ajoute 'authMiddleware' pour forcer la vérification du Token
app.get('/api/reservations/history/:id', authMiddleware, async (req, res) => {
    
    // 2. LE SECRET EST ICI : On ignore req.params.id (l'URL)
    // On prend l'ID directement depuis le token de la personne connectée !
    const idConducteur = req.user.id; 

    try {
        const sql = `
            SELECT 
                pk.id_park,
                r.id_resa,
                r.date_arrivee,
                r.date_depart,
                pk.nom,          
                pk.adresse,      
                pk.image,        
                pk.tarif_heure,  
                r.prix_total     
            FROM RESERVATION r
            JOIN PLACE pl ON r.id_place = pl.id_place
            JOIN PARKING pk ON pl.id_park = pk.id_park
            WHERE r.id_cond = ? 
            ORDER BY r.date_arrivee DESC
        `;

        const [results] = await db.query(sql, [idConducteur]);
        
        res.json(results);

    } catch (err) {
        console.error("❌ Erreur historique :", err);
        res.status(500).json({ error: "Erreur serveur lors de la récupération de l'historique" });
    }
});
app.get('/api/notifications/:id_cond', async (req, res) => {
    try {
        console.log("--- NOUVEAU TEST (VERSION ASYNC) ---");
        const id_cond = req.params.id_cond;
        const sql = "SELECT * FROM notification WHERE id_cond = ? ORDER BY date_notif DESC";
        
        console.log("1. Lancement de la requête...");
        
        // On utilise "await" pour forcer Node.js à attendre la réponse de MySQL
        const [results] = await db.query(sql, [id_cond]);
        
        console.log("2. SUCCÈS ! Voici les données :", results);
        res.status(200).json(results);
        
    } catch (err) {
        console.error("ERREUR SQL :", err);
        res.status(500).json({ erreur: "Erreur serveur" });
    }
});

app.put('/api/notifications/marquer-lu/:id_notif', async (req, res) => {
    try {
        const id_notif = req.params.id_notif;
        const sql = "UPDATE notification SET lu = 1 WHERE id_notif = ?";
        await db.query(sql, [id_notif]);
        res.status(200).json({ message: "Notification lue avec succès" });
    } catch (err) {
        console.error("ERREUR SQL PUT :", err);
        res.status(500).json({ erreur: "Erreur serveur" });
    }
});
// ==========================================
// ROUTE MANAGER : TOUTES LES RÉSERVATIONS
// ==========================================
app.get('/api/manager/reservations/:idGest', authMiddleware, async (req, res) => {
    const idGest = req.params.idGest;

    // Vérification de sécurité
    if (req.user.role !== 'gestionnaire') return res.status(403).json({ message: "Accès interdit" });

    try {
        const sql = `
            SELECT 
                r.id_resa as id_reservation,
                c.nom as nom_conducteur,
                r.date_arrivee as date_debut,
                r.date_depart as date_fin,
                pl.numero as numero_place,
                r.prix_total as montant_total,
                CASE 
                    WHEN r.date_depart IS NULL THEN 'En cours' 
                    ELSE 'Terminé' 
                END as statut
            FROM RESERVATION r
            JOIN PLACE pl ON r.id_place = pl.id_place
            JOIN PARKING pk ON pl.id_park = pk.id_park
            JOIN CONDUCTEUR c ON r.id_cond = c.id_cond
            WHERE pk.id_gest = ?
            ORDER BY r.date_arrivee DESC
        `;

        const [rows] = await db.query(sql, [idGest]);
        res.json(rows);

    } catch (error) {
        console.error("Erreur Manager Reservations:", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});
// ==========================================
// ROUTE MANAGER : REVENUS (PAIEMENTS)
// ==========================================
app.get('/api/manager/earnings/:idGest', authMiddleware, async (req, res) => {
    const idGest = req.params.idGest;

    try {
        const sql = `
            SELECT 
                pay.date,
                pay.mode as type_carte,
                pay.montant,
                c.nom,       
                c.prenom     
            FROM PAIEMENT pay
            JOIN RESERVATION r ON pay.id_resa = r.id_resa
            JOIN PLACE pl ON r.id_place = pl.id_place
            JOIN PARKING pk ON pl.id_park = pk.id_park
            JOIN CONDUCTEUR c ON r.id_cond = c.id_cond  -- ✅ La jointure manquante
            WHERE pk.id_gest = ?
            ORDER BY pay.date DESC
        `;

        const [rows] = await db.query(sql, [idGest]);
        res.json(rows);

    } catch (error) {
        console.error("Erreur Manager Earnings:", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});
// ==========================================
// ROUTES : AVIS / REVIEWS
// ==========================================

// 1. Lire les avis d'un parking (Pour le Gestionnaire et le Client)
app.get('/api/parkings/:id/reviews', async (req, res) => {
    const idPark = req.params.id;
    try {
        const sql = `
            SELECT a.note, a.message, a.date_avis, c.nom as user_name
            FROM AVIS a
            JOIN CONDUCTEUR c ON a.id_cond = c.id_cond
            WHERE a.id_park = ?
            ORDER BY a.date_avis DESC
        `;
        const [rows] = await db.query(sql, [idPark]);
        res.json(rows);
    } catch (error) {
        console.error("Erreur lecture avis:", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ROUTE : Ajouter un avis (Corrigée)
app.post('/api/reviews', async (req, res) => {
    // On récupère les données envoyées par React
    // Note : React envoie "commentaire", mais votre base semble attendre "message"
    const { id_park, id_user, note, commentaire } = req.body; 

    console.log("Tentative d'ajout d'avis :", { id_park, id_user, note, commentaire });

    try {
        // ÉTAPE 1 : Trouver l'ID du gestionnaire (id_gest) qui possède ce parking
        const sqlGetGest = "SELECT id_gest FROM PARKING WHERE id_park = ?";
        const [rows] = await db.query(sqlGetGest, [id_park]);

        if (rows.length === 0) {
            return res.status(404).json({ message: "Parking introuvable, impossible d'ajouter l'avis." });
        }

        const id_gest = rows[0].id_gest; // On a trouvé le gestionnaire !

        // ÉTAPE 2 : Insérer l'avis avec TOUTES les infos (y compris id_gest)
        // Attention : J'utilise 'message' car votre log montrait que la colonne s'appelle ainsi.
        const sqlInsert = `
            INSERT INTO AVIS (id_park, id_cond, id_gest, note, message, date_avis) 
            VALUES (?, ?, ?, ?, ?, NOW())
        `;

        await db.query(sqlInsert, [id_park, id_user, id_gest, note, commentaire]);

        res.status(201).json({ message: "Avis ajouté avec succès !" });

    } catch (err) {
        console.error("❌ Erreur ajout avis:", err);
        res.status(500).json({ 
            message: "Erreur serveur lors de l'ajout de l'avis",
            details: err.message 
        });
    }
});

// =========================================================
// 🤖 TÂCHE PLANIFIÉE : RAPPEL DES 1 MINUTES + FIREBASE (FINAL)
// =========================================================

cron.schedule('* * * * *', async () => {
    try {
        // NOUVEAUTÉ : On fait une JOINTURE (JOIN) pour récupérer le fcm_token du conducteur !
        const querySelect = `
            SELECT r.id_resa, r.id_cond, r.date_arrivee, c.fcm_token 
            FROM RESERVATION r
            JOIN CONDUCTEUR c ON r.id_cond = c.id_cond
            WHERE TIMESTAMPDIFF(MINUTE, r.date_arrivee, NOW()) >= 1
            AND r.date_depart IS NULL
        `;

        const [reservations] = await db.query(querySelect);

        for (const resa of reservations) {
            const titre = "Rappel de stationnement ⏱️";
            const message = `Attention : Cela fait plus de 1 minute que votre stationnement (Réservation n°${resa.id_resa}) a commencé.`;

            const checkNotifQuery = `SELECT id_notif FROM notification WHERE id_cond = ? AND message = ?`;
            const [notifs] = await db.query(checkNotifQuery, [resa.id_cond, message]);

            if (notifs.length === 0) {
                // 1. Sauvegarder dans la base de données
                const insertQuery = `INSERT INTO notification (id_cond, titre, message, lu) VALUES (?, ?, ?, 0)`;
                await db.query(insertQuery, [resa.id_cond, titre, message]);
                console.log(`✅ [CRON] Notification BDD enregistrée (Réservation n°${resa.id_resa})`);

                // 2. FIREBASE : ENVOYER LA NOTIFICATION PUSH AU TÉLÉPHONE !
                if (resa.fcm_token) {
                    const payload = {
                        notification: { 
                            title: titre, 
                            body: message 
                        },
                        token: resa.fcm_token // On utilise le Token qu'on a récupéré de la BDD !
                    };
                    
                    try {
                        await admin.messaging().send(payload);
                        console.log(`📲 Notification Push envoyée au téléphone du client ${resa.id_cond} !`);
                    } catch (pushError) {
                        console.error(`❌ Erreur Push Firebase pour le client ${resa.id_cond} :`, pushError.message);
                    }
                } else {
                    console.log(`⚠️ Client ${resa.id_cond} n'a pas de Token FCM. Notification push ignorée.`);
                }
            }
        }

    } catch (error) {
        console.error("🚨 [CRON] Erreur :", error);
    }
});
// ==========================================
// ROUTE : SAUVEGARDER LE TOKEN FIREBASE (FCM)
// ==========================================
app.post('/api/user/fcm-token', authMiddleware, async (req, res) => {
    const userId = req.user.id;
    const userRole = req.user.role; // 'conducteur' ou 'gestionnaire'
    const { fcmToken } = req.body;

    if (!fcmToken) return res.status(400).json({ error: "Token FCM manquant" });

    try {
        let sql = "";
        // On vérifie le rôle pour mettre à jour la bonne table
        if (userRole === 'conducteur' || userRole === 'client') {
            sql = "UPDATE CONDUCTEUR SET fcm_token = ? WHERE id_cond = ?";
        } else {
            sql = "UPDATE GESTIONNAIRE SET fcm_token = ? WHERE id_gest = ?";
        }

        await db.query(sql, [fcmToken, userId]);
        console.log(`📱 Token FCM sauvegardé pour le ${userRole} ID ${userId}`);
        
        res.json({ success: true, message: "Token Firebase enregistré avec succès !" });

    } catch (error) {
        console.error("❌ Erreur lors de la sauvegarde du Token FCM :", error);
        res.status(500).json({ error: "Erreur base de données" });
    }
});
//=========================================
// 6. LANCEMENT
// ==========================================
app.listen(port, () => {
  console.log(`🚀 Serveur Backend prêt sur http://localhost:${port}`);
});

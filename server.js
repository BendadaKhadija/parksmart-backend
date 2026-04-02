// Forcer le redÃ©ploiement Railway - v2
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
require('dotenv').config(); 
const authMiddleware = require('./authMiddleware');
const roleMiddleware = require('./roleMiddleware');

const serviceAccountString = process.env.FIREBASE_SERVICE_ACCOUNT;
if (serviceAccountString) {
  try {
    const serviceAccount = JSON.parse(serviceAccountString);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log("âœ… Firebase Admin SDK initialisÃ©.");
  } catch (error) {
    console.error("âŒ Erreur lors de l'initialisation de Firebase Admin. VÃ©rifiez la variable d'environnement FIREBASE_SERVICE_ACCOUNT.", error.message);
  }
} else {
  console.warn("âš ï¸ La variable d'environnement FIREBASE_SERVICE_ACCOUNT est manquante. Les fonctionnalitÃ©s liÃ©es Ã  Firebase (Google Auth, Push Notifications) seront dÃ©sactivÃ©es.");
}

const app = express();
app.use(express.json());
app.use(cors());
// CrÃ©ation du dossier 'uploads' s'il n'existe pas
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
// 1. CONNEXION BDD (Compatible Railway + Local)
// ==========================================
let db;
if (process.env.MYSQL_URL) {
  // Railway : utilise l'URL de connexion complÃ¨te (la plus fiable)
  console.log("ðŸ“¡ Connexion via MYSQL_URL (Railway)");
  db = mysql.createPool(process.env.MYSQL_URL);
} else {
  // Local : utilise les variables individuelles
  console.log("ðŸ’» Connexion locale");
  db = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '', 
    database: process.env.DB_NAME || 'parksmart_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
}

// Test de connexion au dÃ©marrage
db.getConnection()
    .then(connection => {
        console.log("âœ… ConnectÃ© Ã  la base de donnÃ©es MySQL !");
        connection.release();
    })
    .catch(err => {
        console.error("âŒ Erreur de connexion BDD :", err.message);
    });

// ==========================================
// 3. ROUTES AUTHENTIFICATION
// ==========================================

// INSCRIPTION 
app.post('/api/auth/signup', upload.single('image'), async (req, res) => {
  try {
    // req.body contient le texte (nom, email...)
    const { nom,prenom, email, password, role } = req.body; 
    
    // req.file contient l'image (si envoyÃ©e)
    // Si il y a une image, on crÃ©e le chemin, sinon on met null
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    if (!nom || !prenom || !email || !password) {
      return res.status(400).json({ message: 'Champs manquants' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    if (role === 'gestionnaire') {
        // âš ï¸ AJOUT de la colonne photo dans la requÃªte SQL
        await db.query(
            'INSERT INTO gestionnaire (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
            [nom,prenom, email, hashedPassword, photoPath]
        );
    } else {
        // âš ï¸ AJOUT de la colonne photo dans la requÃªte SQL
        await db.query(
            'INSERT INTO conducteur (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
            [nom,prenom, email, hashedPassword, photoPath]
        );
    }
    
    res.status(201).json({ message: 'Compte crÃ©Ã© avec succÃ¨s !' });

  } catch (error) {
    console.error("Erreur Inscription :", error);
    res.status(500).json({ message: "Erreur serveur ou Email dÃ©jÃ  utilisÃ©." });
  }
});

// CONNEXION
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    let user = null;
    let role = '';
    let userId = null;
    

    // 1. Chercher dans conducteur
    const [conds] = await db.query('SELECT * FROM conducteur WHERE email = ?', [email]);
    if (conds.length > 0) {
      user = conds[0];
      role = 'conducteur';
      userId = user.id_cond;
    } else {
      // 2. Chercher dans gestionnaire
      const [gests] = await db.query('SELECT * FROM gestionnaire WHERE email = ?', [email]);
      if (gests.length > 0) {
        user = gests[0];
        role = 'gestionnaire';
        userId = user.id_gest; 
      }
    }

    if (!user) return res.status(404).json({ message: 'Email inconnu.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Mot de passe incorrect.' });

    const token = jwt.sign({ id: userId, role: role }, process.env.JWT_SECRET, { expiresIn: '24h' });

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
    
    // 1. Demander Ã  Firebase de vÃ©rifier si le token est un vrai
    const decodedToken = await admin.auth().verifyIdToken(token);
    
    // On rÃ©cupÃ¨re les infos sÃ©curisÃ©es de Google
    const email = decodedToken.email;
    const nomComplet = decodedToken.name || 'Utilisateur Google';
    const photo = decodedToken.picture || null;

    // Petite astuce pour sÃ©parer Nom et PrÃ©nom (si Google donne tout d'un coup)
    const [prenom, ...nomArray] = nomComplet.split(' ');
    const nom = nomArray.join(' ') || prenom; 

    let user = null;
    let role = '';
    let userId = null;

    // 2. Chercher dans conducteur
    const [conds] = await db.query('SELECT * FROM conducteur WHERE email = ?', [email]);
    if (conds.length > 0) {
      user = conds[0];
      role = 'conducteur';
      userId = user.id_cond;
    } else {
      // 3. Chercher dans gestionnaire
      const [gests] = await db.query('SELECT * FROM gestionnaire WHERE email = ?', [email]);
      if (gests.length > 0) {
        user = gests[0];
        role = 'gestionnaire';
        userId = user.id_gest;
      }
    }

    // 4. SI L'UTILISATEUR N'EXISTE PAS : On le crÃ©e automatiquement !
    if (!user) {
      console.log("Nouvel utilisateur Google dÃ©tectÃ©, crÃ©ation du compte...");
      
      const [result] = await db.query(
        'INSERT INTO conducteur (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
        [nom, prenom, email, 'google_sso_no_password', photo] 
      );
      
      userId = result.insertId;
      role = 'conducteur';
      user = { id_cond: userId, nom: nom, prenom: prenom, email: email, photo: photo };
    }

    // 5. GÃ©nÃ©rer TON token
    const jwtToken = jwt.sign({ id: userId, role: role }, process.env.JWT_SECRET, { expiresIn: '24h' });

    console.log(`âœ… Connexion Google rÃ©ussie pour : ${email}`);

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
    console.error("âŒ Erreur Google Login Backend :", error);
    res.status(401).json({ message: 'Token Google invalide, expirÃ© ou refusÃ©.' });
  }
});

// ==========================================
// 4. ROUTES ADMIN (gestionnaire)
// ==========================================

// AJOUTER parking + GENERER placeS
app.post('/api/admin/parking', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    // ðŸ”´ CORRECTION ICI : On ajoute latitude, longitude et image_url dans la rÃ©cupÃ©ration
    const { 
        nom, 
        adresse, 
        tarif_heure, 
        nb_rangees, 
        nb_places_par_rangee, 
        latitude,   // <--- AjoutÃ©
        longitude,  // <--- AjoutÃ©
        image_url   // <--- AjoutÃ© (le front envoie souvent image_url, pas image)
    } = req.body;

    const id_gest = req.auth.userId;
    
    // DEBUG: On log tout le body pour Ãªtre sÃ»r
    console.log("ðŸ“¥ DONNÃ‰ES REÃ‡UES COMPLÃˆTES :", req.body); 

    // Validation des donnÃ©es (Ajoutez latitude/longitude si obligatoire)
    if (!nom || !adresse || !tarif_heure) {
        return res.status(400).json({ message: "Champs obligatoires manquants" });
    }

    const connection = await db.getConnection(); 
    try {
        await connection.beginTransaction();

        // ðŸ”´ CORRECTION DANS LA REQUÃŠTE SQL
        // On mappe 'image_url' (du front) vers la colonne 'image' (de la BDD)
        const [result] = await connection.query(
            "INSERT INTO parking (nom, adresse, tarif_heure, image, latitude, longitude, nb_rangees, nb_places_par_rangee, id_gest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                nom, 
                adresse, 
                tarif_heure,
                image_url ?? null, // Garder null si non dÃ©fini
                latitude ?? null,  // Garder null si non dÃ©fini
                longitude ?? null, // Garder null si non dÃ©fini
                nb_rangees || 0, 
                nb_places_par_rangee || 0, 
                id_gest
            ]
        );
        
        // GÃ©nÃ©rer les places
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
                "INSERT INTO place (numero, id_park, disponibilite) VALUES ?",
                [places.map(p => [p.numero, p.id_park, p.disponibilite])]
            );
        }

        await connection.commit();
        res.status(201).json({ message: "âœ… parking crÃ©Ã© avec succÃ¨s !", id_parking: result.insertId });
    } catch (error) {
        await connection.rollback();
        console.error("âŒ Erreur crÃ©ation parking :", error);
        res.status(500).json({ error: "Erreur lors de la crÃ©ation du parking" });
    } finally {
        connection.release();
    }
});

// LISTER MES parkingS (gestionnaire) - C'est la route qui te manquait !
app.get('/api/my-parkings/:id', async (req, res) => {
    try {
        const idGest = req.params.id;
        const [results] = await db.query("SELECT * FROM parking WHERE id_gest = ?", [idGest]);
        res.status(200).json(results);
    } catch (error) {
        console.error("Erreur rÃ©cupÃ©ration mes parkings:", error);
        res.status(500).json({ error: "Erreur base de donnÃ©es" });
    }
});

// 1. SUPPRIMER UN parking (CORRIGÃ‰ AVEC paiementS ET avis)
app.delete('/api/parkings/:id', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    const id = req.params.id;
    const id_gest = req.auth.userId;

    // TODO: Ajouter une vÃ©rification pour s'assurer que le gestionnaire est bien le propriÃ©taire du parking
    // const [parking] = await db.query("SELECT id_gest FROM parking WHERE id_park = ?", [id]);
    
    try {
        console.log(`Tentative de suppression du parking ${id}...`);

        // Ã‰TAPE 1 : Supprimer les paiementS liÃ©s aux rÃ©servations de ce parking
        await db.query(`
            DELETE FROM paiement 
            WHERE id_resa IN (
                SELECT id_resa FROM reservation 
                WHERE id_place IN (SELECT id_place FROM place WHERE id_park = ?)
            )
        `, [id]);

        // Ã‰TAPE 2 : Supprimer les RÃ‰SERVATIONS liÃ©es aux places de ce parking
        await db.query(`
            DELETE FROM reservation 
            WHERE id_place IN (SELECT id_place FROM place WHERE id_park = ?)
        `, [id]);

        // Ã‰TAPE 3 : Supprimer les placeS de ce parking
        await db.query("DELETE FROM place WHERE id_park = ?", [id]);

        // Ã‰TAPE 4 (NOUVELLE) : Supprimer les avis liÃ©s Ã  ce parking
        await db.query("DELETE FROM avis WHERE id_park = ?", [id]);

        // Ã‰TAPE 5 : Enfin, supprimer le parking
        const [result] = await db.query("DELETE FROM parking WHERE id_park = ?", [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "parking introuvable." });
        }

        console.log("âœ… parking, places, rÃ©servations, paiements et avis supprimÃ©s avec succÃ¨s !");
        res.json({ message: "parking et toutes ses donnÃ©es supprimÃ©s avec succÃ¨s !" });

    } catch (error) {
        console.error("âŒ Erreur SQL lors de la suppression :", error);
        res.status(500).json({ error: "Erreur interne (voir terminal pour dÃ©tails)" });
    }
});
// --- Route pour MODIFIER un parking (SÃ©curisÃ©e) ---
// J'ai ajoutÃ© 'authMiddleware' ici pour protÃ©ger la route
app.put('/api/parkings/:id', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    const id = req.params.id;
    const id_gest = req.auth.userId;
    // 1. On ne rÃ©cupÃ¨re PLUS nb_rangees et nb_places_par_rangee
    const { nom, adresse, tarif_heure } = req.body;

    // TODO: Ajouter une vÃ©rification pour s'assurer que le gestionnaire est bien le propriÃ©taire du parking
    // const [parking] = await db.query("SELECT id_gest FROM parking WHERE id_park = ? AND id_gest = ?", [id, id_gest]);

    console.log(`ðŸ“¡ MODIFICATION parking ${id}`);

    const tarif = parseFloat(tarif_heure);

    try {
        // 2. On met Ã  jour uniquement le nom, l'adresse et le tarif
        const sql = `
            UPDATE parking 
            SET nom = ?, 
                adresse = ?, 
                tarif_heure = ?
            WHERE id_park = ?`;

        const [result] = await db.query(sql, [nom, adresse, tarif, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "parking introuvable (ID incorrect)" });
        }

        res.json({ message: "âœ… parking modifiÃ© avec succÃ¨s" });

    } catch (error) {
        console.error("âŒ Erreur SQL Update :", error);
        res.status(500).json({ error: "Erreur serveur lors de la modification" });
    }
});
// MISE Ã€ JOUR PROFIL gestionnaire (CORRIGÃ‰E)
app.put('/api/manager/update', authMiddleware, roleMiddleware(['gestionnaire']), upload.single('image'), async (req, res) => {
    console.log("ðŸ“ Update Profil demandÃ©...");

    const id_user = req.auth.userId;
    const { nom, email } = req.body; 
    
    // Si une nouvelle image est uploadÃ©e
    const newPhotoPath = req.file ? `/uploads/${req.file.filename}` : null;

    try {
        let sql;
        let params;

        if (newPhotoPath) {
            // Mise Ã  jour AVEC photo (Attention: colonne 'photo' ou 'image' ? VÃ©rifie ta BDD. Je mets 'photo' comme dans ton signup)
            sql = "UPDATE gestionnaire SET nom=?, email=?, photo=? WHERE id_gest=?";
            params = [nom, email, newPhotoPath, id_user];
        } else {
            // Mise Ã  jour SANS photo
            sql = "UPDATE gestionnaire SET nom=?, email=? WHERE id_gest=?";
            params = [nom, email, id_user];
        }

        const [result] = await db.query(sql, params);

        if (result.affectedRows === 0) return res.status(404).json({ message: "Utilisateur non trouvÃ©" });

        res.json({ message: "Mise Ã  jour rÃ©ussie", newImage: newPhotoPath });

    } catch (error) {
        console.error("âŒ Erreur Update Profil:", error);
        res.status(500).json({ error: "Erreur base de donnÃ©es" });
    }
});
// --- ROUTE PUBLIQUE : RECUPERER TOUS LES parkingS (POUR LE CLIENT) ---
app.get('/api/parkings', async (req, res) => {
    try {
        console.log("Client demande la liste des parkings...");
        const [rows] = await db.query("SELECT * FROM parking");
        res.json(rows);
    } catch (error) {
        console.error("Erreur rÃ©cupÃ©ration tous les parkings :", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// ==========================================
// ROUTE : MISE Ã€ JOUR PROFIL 
// ==========================================
app.post('/api/user/update', authMiddleware, upload.single('photo'), async (req, res) => {
    console.log("ðŸ“ Demande de mise Ã  jour profil reÃ§ue...");

    const userId = req.auth.userId; 
    const userRole = req.auth.role; // 'conducteur' ou 'gestionnaire'

    // 1. On rÃ©cupÃ¨re TOUS les champs (nom, prenom, email)
    const { nom, prenom, email } = req.body;
    
    // Chemin image
    const newPhotoPath = req.file ? `/uploads/${req.file.filename}` : null;

    try {
        let sql;
        let params;
        
        // --- LOGIQUE SPÃ‰CIFIQUE conducteur (Avec PrÃ©nom) ---
        if (userRole === 'conducteur' || userRole === 'client') { 
            // Note: VÃ©rifiez si votre rÃ´le s'appelle 'conducteur' ou 'client' dans le token
            
            let querySet = "UPDATE conducteur SET nom=?, prenom=?, email=?";
            let queryParams = [nom, prenom, email];

            if (newPhotoPath) {
                querySet += ", photo=?"; // ou image=? selon votre BDD
                queryParams.push(newPhotoPath);
            }

            sql = `${querySet} WHERE id_cond=?`;
            params = [...queryParams, userId];
        } 
        // --- LOGIQUE gestionnaire (Sans PrÃ©nom, si applicable) ---
        else {
            let querySet = "UPDATE gestionnaire SET nom=?, email=?";
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

        console.log(`âœ… Profil ${userRole} mis Ã  jour avec succÃ¨s !`);
        
        res.json({ 
            message: "Mise Ã  jour rÃ©ussie", 
            photo: newPhotoPath,
            user: { nom, prenom, email }
        });

    } catch (error) {
        console.error("âŒ Erreur Update Profil:", error);
        res.status(500).json({ error: "Erreur base de donnÃ©es", details: error.message });
    }
});
// ==========================================
// 5. ROUTES CLIENT (MAP & reservation)
// ==========================================

// RÃ©cupÃ©rer la MAP (Configuration + Ã‰tat des places)
app.get('/api/parking-map/:id', async (req, res) => {
    try {
        const parkingId = req.params.id;

        // 1. RÃ©cupÃ©rer config
        const [parkingInfo] = await db.query(
            "SELECT nb_rangees, nb_places_par_rangee FROM parking WHERE id_park = ?", // VÃ©rifie si c'est 'id' ou 'id_park' dans ta base
            [parkingId]
        );

        if (parkingInfo.length === 0) return res.status(404).json({message: "parking introuvable"});

        // 2. RÃ©cupÃ©rer places + statuts
        const query = `
            SELECT 
                p.id_place, 
                p.numero, 
                CASE 
                    WHEN r.id_resa IS NOT NULL THEN 'occupÃ©' 
                    ELSE 'libre' 
                END as statut_actuel
            FROM place p
            LEFT JOIN reservation r ON p.id_place = r.id_place AND r.date_depart IS NULL
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
        const [rows] = await db.query("SELECT * FROM place WHERE id_park = ? ORDER BY id_place ASC", [id]);
        res.json(rows);
    } catch (err) {
        console.error("Erreur rÃ©cupÃ©ration places:", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// DÃ©marrer une rÃ©servation (Client)
app.post('/api/reservation/start', authMiddleware, roleMiddleware(['conducteur']), async (req, res) => {
    const { id_place } = req.body;
    const id_cond = req.auth.userId; 

    try {
        // 1. VÃ©rifier si le conducteur a DÃ‰JÃ€ une rÃ©servation active
        const [activeRes] = await db.query(
            'SELECT * FROM reservation WHERE id_cond = ? AND date_depart IS NULL',
            [id_cond]
        );

        if (activeRes.length > 0) {
            return res.status(400).json({ message: "Vous avez dÃ©jÃ  une rÃ©servation en cours." });
        }

        // 2. VÃ©rifier si la place est libre et rÃ©cupÃ©rer l'ID du parking
        // CORRECTION : On utilise 'disponibilite' (pas 'statu')
        const [placeStatus] = await db.query(
            'SELECT disponibilite, id_park FROM place WHERE id_place = ?', 
            [id_place]
        );

        if (placeStatus.length === 0) {
            return res.status(404).json({ message: "place introuvable." });
        }

        // Si disponibilite == 0, c'est occupÃ© (selon ta logique ailleurs dans le code)
        if (placeStatus[0].disponibilite == 0) {
            return res.status(400).json({ message: "Cette place est dÃ©jÃ  occupÃ©e." });
        }

        const id_park = placeStatus[0].id_park;

        // 3. CrÃ©er la rÃ©servation
        const [result] = await db.query(
            'INSERT INTO reservation (date_arrivee, id_cond, id_place) VALUES (NOW(), ?, ?)',
            [id_cond, id_place]
        );

        // 4. Mettre la place en 'occupÃ©'
        // CORRECTION : On met 'disponibilite' Ã  0
        await db.query('UPDATE place SET disponibilite = 0 WHERE id_place = ?', [id_place]);

        res.json({ 
            message: "RÃ©servation dÃ©marrÃ©e !", 
            id_res: result.insertId,
            place: id_place
        });

    } catch (err) {
        console.error("Erreur reservation Start :", err); // Le log sera plus prÃ©cis
        res.status(500).json({ message: "Erreur serveur lors de la rÃ©servation." });
    }
});
// ==========================================
// ROUTE : VÃ©rifier rÃ©servation active (HYBRIDE)
// ==========================================
app.get('/api/reservation/active', authMiddleware, async (req, res) => {
    try {
        const userId = req.auth.userId;

        const [rows] = await db.query(
            "SELECT *, TIMESTAMPDIFF(SECOND, date_arrivee, NOW()) AS temps_ecoule_secondes FROM reservation WHERE id_cond = ? AND date_depart IS NULL ORDER BY date_arrivee DESC LIMIT 1",
            [userId]
        );

        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            // Important : Renvoyer 404 est normal si pas de rÃ©servation, le front le gÃ¨re
            res.status(404).json({ message: "Aucune rÃ©servation active" });
        }
    } catch (err) {
        console.error("Erreur Active Resa:", err.message);
        // On renvoie 404 pour ne pas bloquer le front s'il y a un souci technique
        res.status(404).send("Erreur ou pas de rÃ©servation");
    }
});
// ==========================================
//  STOP reservation + LIBÃ‰RATION place
// ==========================================
app.post('/api/reservation/stop', async (req, res) => {
    const { id_resa } = req.body;

    console.log("ðŸ›‘ Tentative d'arrÃªt rÃ©servation ID :", id_resa);

    if (!id_resa) {
        return res.status(400).json({ error: "ID rÃ©servation manquant" });
    }

    const connection = await db.getConnection(); // On prend une connexion dÃ©diÃ©e pour la transaction

    try {
        await connection.beginTransaction(); // DÃ©but transaction (sÃ©curitÃ©)

        // 1. RÃ©cupÃ©rer les infos de la rÃ©servation (Date dÃ©but + ID place)
        const [rows] = await connection.query(
            "SELECT * FROM reservation WHERE id_resa = ?", 
            [id_resa]
        );

        if (rows.length === 0) {
            await connection.rollback();
            return res.status(404).json({ error: "RÃ©servation introuvable" });
        }

        const resa = rows[0];

        // VÃ©rification si dÃ©jÃ  terminÃ©e
        if (resa.date_depart !== null) {
            await connection.rollback();
            return res.status(400).json({ message: "Cette rÃ©servation est dÃ©jÃ  terminÃ©e." });
        }

        // 2. Calcul du prix
        const dateDebut = new Date(resa.date_arrivee);
        const dateFin = new Date();
        
        // Calcul durÃ©e en millisecondes
        let diffMs = dateFin - dateDebut;
        if (diffMs < 0) diffMs = 0; 

        // Conversion en heures (arrondi supÃ©rieur)
        const diffSeconds = Math.floor(diffMs / 1000);
        const hours = Math.ceil(diffSeconds / 3600); // Ex: 1h05 = 2h payantes
        const minutes = Math.floor((diffSeconds % 3600) / 60);

        // Tarif fixe ou rÃ©cupÃ©rÃ© du parking (ici je mets ton calcul hardcodÃ© 4.00 DH/h)
        // IdÃ©alement, il faudrait faire une jointure avec parking pour avoir le vrai tarif_heure
        const tarifHoraire = 4.00; 
        const montant = (Math.max(1, hours) * tarifHoraire).toFixed(2); // Minimum 1h facturÃ©e

        console.log(`ðŸ’° Calcul: ${hours}h * ${tarifHoraire} = ${montant} DH`);

        // 3. Mettre Ã  jour la RÃ©servation (Date fin + Prix)
        await connection.query(
            "UPDATE reservation SET date_depart = ?, prix_total = ? WHERE id_resa = ?",
            [dateFin, montant, id_resa]
        );

        // 4. LIBÃ‰RER LA place (C'Ã©tait l'oubli critique !)
        // On remet disponibilite Ã  1 (Libre)
        await connection.query(
            "UPDATE place SET disponibilite = 1 WHERE id_place = ?",
            [resa.id_place]
        );

        await connection.commit(); // Valider tout
        connection.release();

        console.log("âœ… RÃ©servation terminÃ©e et place libÃ©rÃ©e.");

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
        console.error("âŒ Erreur Stop RÃ©servation :", error);
        res.status(500).json({ error: "Erreur serveur lors de l'arrÃªt" });
    }
});
// CONFIRMATION paiement + CLÃ”TURE RÃ‰SERVATION + LIBÃ‰RATION place
app.post('/api/paiement/confirm', async (req, res) => {
    console.log("ðŸ’³ Validation finale du paiement...");
    const { id_resa, montant, mode } = req.body;

    if (!id_resa || !montant) {
        return res.status(400).json({ success: false, message: "DonnÃ©es manquantes." });
    }

    try {
        const datepaiement = new Date();

        // 1. Enregistrer le paiement
        await db.query(
            "INSERT INTO paiement (id_resa, montant, date, mode) VALUES (?, ?, ?, ?)",
            [id_resa, montant, datepaiement, mode]
        );

        // 2. Mettre Ã  jour la RÃ‰SERVATION (Date de fin et Prix final)
        // NOW() permet d'avoir l'heure exacte du serveur SQL
        await db.query(
            "UPDATE reservation SET date_depart = NOW(), prix_total = ? WHERE id_resa = ?",
            [montant, id_resa]
        );

        // 3. LibÃ©rer la place (Remettre disponibilite Ã  1)
        // On cherche d'abord quelle place correspond Ã  cette rÃ©servation
        await db.query(
            `UPDATE place 
             JOIN reservation ON place.id_place = reservation.id_place 
             SET place.disponibilite = 1 
             WHERE reservation.id_resa = ?`,
            [id_resa]
        );

        console.log("âœ… Cycle complet terminÃ© : PayÃ©, FermÃ©, LibÃ©rÃ©.");
        res.json({ success: true, message: "paiement validÃ© et rÃ©servation clÃ´turÃ©e !" });

    } catch (err) {
        console.error("âŒ Erreur SQL Finale :", err);
        res.status(500).json({ success: false, message: "Erreur serveur", details: err.sqlMessage });
    }
});
// ==========================================
// ROUTE : Historique Visuel (SÃ‰CURISÃ‰E ðŸ”’)
// ==========================================
// 1. On ajoute 'authMiddleware' pour forcer la vÃ©rification du Token
app.get('/api/reservations/history', authMiddleware, async (req, res) => {
    
    // 2. LE SECRET EST ICI : On ignore req.params.id (l'URL)
    // On prend l'ID directement depuis le token de la personne connectÃ©e !
    const idconducteur = req.auth.userId; 

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
            FROM reservation r
            JOIN place pl ON r.id_place = pl.id_place
            JOIN parking pk ON pl.id_park = pk.id_park
            WHERE r.id_cond = ? 
            ORDER BY r.date_arrivee DESC
        `;

        const [results] = await db.query(sql, [idconducteur]);
        
        res.json(results);

    } catch (err) {
        console.error("âŒ Erreur historique :", err);
        res.status(500).json({ error: "Erreur serveur lors de la rÃ©cupÃ©ration de l'historique" });
    }
});
app.get('/api/notifications/:id_cond', async (req, res) => {
    try {
        console.log("--- NOUVEAU TEST (VERSION ASYNC) ---");
        const id_cond = req.params.id_cond;
        const sql = "SELECT * FROM notification WHERE id_cond = ? ORDER BY date_notif DESC";
        
        console.log("1. Lancement de la requÃªte...");
        
        // On utilise "await" pour forcer Node.js Ã  attendre la rÃ©ponse de MySQL
        const [results] = await db.query(sql, [id_cond]);
        
        console.log("2. SUCCÃˆS ! Voici les donnÃ©es :", results);
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
        res.status(200).json({ message: "notification lue avec succÃ¨s" });
    } catch (err) {
        console.error("ERREUR SQL PUT :", err);
        res.status(500).json({ erreur: "Erreur serveur" });
    }
});
// ==========================================
// ROUTE MANAGER : TOUTES LES RÃ‰SERVATIONS
// ==========================================
app.get('/api/manager/reservations', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    // On utilise l'ID du token pour sÃ©curiser la route
    const idGest = req.auth.userId;

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
                    ELSE 'TerminÃ©' 
                END as statut
            FROM reservation r
            JOIN place pl ON r.id_place = pl.id_place
            JOIN parking pk ON pl.id_park = pk.id_park
            JOIN conducteur c ON r.id_cond = c.id_cond
            WHERE pk.id_gest = ?
            ORDER BY r.date_arrivee DESC
        `;

        const [rows] = await db.query(sql, [idGest]);
        res.json(rows);

    } catch (error) {
        console.error("Erreur Manager reservations:", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});
// ==========================================
// ROUTE MANAGER : REVENUS (paiementS)
// ==========================================
app.get('/api/manager/earnings', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    // On utilise l'ID du token pour sÃ©curiser la route
    const idGest = req.auth.userId;

    try {
        const sql = `
            SELECT 
                pay.date,
                pay.mode as type_carte,
                pay.montant,
                c.nom,       
                c.prenom     
            FROM paiement pay
            JOIN reservation r ON pay.id_resa = r.id_resa
            JOIN place pl ON r.id_place = pl.id_place
            JOIN parking pk ON pl.id_park = pk.id_park
            JOIN conducteur c ON r.id_cond = c.id_cond  -- âœ… La jointure manquante
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
// ROUTES : avis / REVIEWS
// ==========================================

// 1. Lire les avis d'un parking (Pour le gestionnaire et le Client)
app.get('/api/parkings/:id/reviews', async (req, res) => {
    const idPark = req.params.id;
    try {
        const sql = `
            SELECT a.note, a.message, a.date_avis, c.nom as user_name
            FROM avis a
            JOIN conducteur c ON a.id_cond = c.id_cond
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

// ROUTE : Ajouter un avis (CorrigÃ©e)
app.post('/api/reviews', async (req, res) => {
    // On rÃ©cupÃ¨re les donnÃ©es envoyÃ©es par React
    // Note : React envoie "commentaire", mais votre base semble attendre "message"
    const { id_park, id_user, note, commentaire } = req.body; 

    console.log("Tentative d'ajout d'avis :", { id_park, id_user, note, commentaire });

    try {
        // Ã‰TAPE 1 : Trouver l'ID du gestionnaire (id_gest) qui possÃ¨de ce parking
        const sqlGetGest = "SELECT id_gest FROM parking WHERE id_park = ?";
        const [rows] = await db.query(sqlGetGest, [id_park]);

        if (rows.length === 0) {
            return res.status(404).json({ message: "parking introuvable, impossible d'ajouter l'avis." });
        }

        const id_gest = rows[0].id_gest; // On a trouvÃ© le gestionnaire !

        // Ã‰TAPE 2 : InsÃ©rer l'avis avec TOUTES les infos (y compris id_gest)
        // Attention : J'utilise 'message' car votre log montrait que la colonne s'appelle ainsi.
        const sqlInsert = `
            INSERT INTO avis (id_park, id_cond, id_gest, note, message, date_avis) 
            VALUES (?, ?, ?, ?, ?, NOW())
        `;

        await db.query(sqlInsert, [id_park, id_user, id_gest, note, commentaire]);

        res.status(201).json({ message: "avis ajoutÃ© avec succÃ¨s !" });

    } catch (err) {
        console.error("âŒ Erreur ajout avis:", err);
        res.status(500).json({ 
            message: "Erreur serveur lors de l'ajout de l'avis",
            details: err.message 
        });
    }
});

// =========================================================
// ðŸ¤– TÃ‚CHE PLANIFIÃ‰E : RAPPEL DES 1 MINUTES + FIREBASE (FINAL)
// =========================================================

cron.schedule('* * * * *', async () => {
    try {
        // NOUVEAUTÃ‰ : On fait une JOINTURE (JOIN) pour rÃ©cupÃ©rer le fcm_token du conducteur !
        const querySelect = `
            SELECT r.id_resa, r.id_cond, r.date_arrivee, c.fcm_token 
            FROM reservation r
            JOIN conducteur c ON r.id_cond = c.id_cond
            WHERE TIMESTAMPDIFF(MINUTE, r.date_arrivee, NOW()) >= 1
            AND r.date_depart IS NULL
        `;

        const [reservations] = await db.query(querySelect);

        for (const resa of reservations) {
            const titre = "Rappel de stationnement â±ï¸";
            const message = `Attention : Cela fait plus de 1 minute que votre stationnement (RÃ©servation nÂ°${resa.id_resa}) a commencÃ©.`;

            const checkNotifQuery = `SELECT id_notif FROM notification WHERE id_cond = ? AND message = ?`;
            const [notifs] = await db.query(checkNotifQuery, [resa.id_cond, message]);

            if (notifs.length === 0) {
                // 1. Sauvegarder dans la base de donnÃ©es
                const insertQuery = `INSERT INTO notification (id_cond, titre, message, lu) VALUES (?, ?, ?, 0)`;
                await db.query(insertQuery, [resa.id_cond, titre, message]);
                console.log(`âœ… [CRON] notification BDD enregistrÃ©e (RÃ©servation nÂ°${resa.id_resa})`);

                // 2. FIREBASE : ENVOYER LA notification PUSH AU TÃ‰LÃ‰PHONE !
                if (resa.fcm_token) {
                    const payload = {
                        notification: { 
                            title: titre, 
                            body: message 
                        },
                        token: resa.fcm_token // On utilise le Token qu'on a rÃ©cupÃ©rÃ© de la BDD !
                    };
                    
                    try {
                        await admin.messaging().send(payload);
                        console.log(`ðŸ“² notification Push envoyÃ©e au tÃ©lÃ©phone du client ${resa.id_cond} !`);
                    } catch (pushError) {
                        console.error(`âŒ Erreur Push Firebase pour le client ${resa.id_cond} :`, pushError.message);
                    }
                } else {
                    console.log(`âš ï¸ Client ${resa.id_cond} n'a pas de Token FCM. notification push ignorÃ©e.`);
                }
            }
        }

    } catch (error) {
        console.error("ðŸš¨ [CRON] Erreur :", error);
    }
});
// ==========================================
// ROUTE : SAUVEGARDER LE TOKEN FIREBASE (FCM)
// ==========================================
app.post('/api/user/fcm-token', authMiddleware, async (req, res) => {
    const userId = req.auth.userId;
    const userRole = req.auth.role; // 'conducteur' ou 'gestionnaire'
    const { fcmToken } = req.body;

    if (!fcmToken) return res.status(400).json({ error: "Token FCM manquant" });

    try {
        let sql = "";
        // On vÃ©rifie le rÃ´le pour mettre Ã  jour la bonne table
        if (userRole === 'conducteur' || userRole === 'client') {
            sql = "UPDATE conducteur SET fcm_token = ? WHERE id_cond = ?";
        } else {
            sql = "UPDATE gestionnaire SET fcm_token = ? WHERE id_gest = ?";
        }

        await db.query(sql, [fcmToken, userId]);
        console.log(`ðŸ“± Token FCM sauvegardÃ© pour le ${userRole} ID ${userId}`);
        
        res.json({ success: true, message: "Token Firebase enregistrÃ© avec succÃ¨s !" });

    } catch (error) {
        console.error("âŒ Erreur lors de la sauvegarde du Token FCM :", error);
        res.status(500).json({ error: "Erreur base de donnÃ©es" });
    }
});
//=========================================
// 6. LANCEMENT
// ==========================================
app.listen(port, () => {
  console.log(`ðŸš€ Serveur Backend prÃªt sur http://localhost:${port}`);
});

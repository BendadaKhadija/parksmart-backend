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
require('dotenv').config(); 
const authMiddleware = require('./authMiddleware');
const roleMiddleware = require('./roleMiddleware');

const serviceAccountString = process.env.FIREBASE_SERVICE_ACCOUNT;
if (serviceAccountString) {
  try {
    const serviceAccount = JSON.parse(serviceAccountString);
    
    // 👇 LA LIGNE MAGIQUE POUR SAUVER LA CLÉ SUR RAILWAY 👇
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log("Firebase Admin SDK initialisé.");
  } catch (error) {
    console.error("Erreur d'initialisation Firebase :", error.message);
  }
} else {
  console.warn("Variable FIREBASE_SERVICE_ACCOUNT manquante.");
}

const app = express();
app.use(express.json());

// --- CONFIGURATION CORS COMPLÈTE ---
app.use(cors({
    origin: [
        'https://parksmart-frontend.vercel.app', // Autorise ton site en ligne
        'http://localhost:5173',                 // Autorise ton frontend local
        'http://localhost:3000'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Création du dossier 'uploads' s'il n'existe pas// Création du dossier 'uploads' s'il n'existe pas
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
const port = process.env.PORT || 3000;

// ==========================================
// 1. CONNEXION BDD (Compatible Railway+Local)
// ==========================================
let db;
if (process.env.MYSQL_URL) {
  // Railway : utilise l'URL de connexion complète (la plus fiable)
  console.log("Connexion via MYSQL_URL (Railway)");
  db = mysql.createPool(process.env.MYSQL_URL);
} else {
  // Local : utilise les variables individuelles
  console.log("Connexion locale");
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

// Test de connexion au démarrage
db.getConnection()
    .then(connection => {
        console.log("Connecté à la base de données MySQL !");
        connection.release();
    })
    .catch(err => {
        console.error("Erreur de connexion BDD :", err.message);
    });

// ==========================================
// 2. HELPERS
// ==========================================

/**
 * Trouve un utilisateur par email dans les tables conducteur et gestionnaire.
 * @param {string} email L'email de l'utilisateur à trouver.
 * @returns {Promise<Object|null>} Un objet contenant l'utilisateur, son rôle et son ID, ou null si non trouvé ou en cas d'erreur.
 */
const findUserByEmail = async (email) => {
  try {
    const [conds] = await db.query('SELECT id_cond, nom, prenom, email, password, photo FROM conducteur WHERE email = ?', [email]);
    if (conds.length > 0) {
      return { user: conds[0], role: 'conducteur', userId: conds[0].id_cond };
    }
    
    const [gests] = await db.query('SELECT id_gest, nom, prenom, email, password, photo FROM gestionnaire WHERE email = ?', [email]);
    if (gests.length > 0) {
      // Les gestionnaires pourraient ne pas avoir de prénom par défaut dans la BDD, on s'assure qu'il soit présent
      gests[0].prenom = gests[0].prenom || null; 
      return { user: gests[0], role: 'gestionnaire', userId: gests[0].id_gest };
    }
    return null;
  } catch (error) {
    console.error("Erreur lors de la recherche d'utilisateur par email:", error);
    // Renvoyer null pour indiquer qu'aucun utilisateur n'a été trouvé (ou qu'une erreur DB est survenue)
    return null; 
  }
};

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
        // AJOUT de la colonne photo dans la requête SQL
        await db.query(
            'INSERT INTO gestionnaire (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
            [nom,prenom, email, hashedPassword, photoPath]
        );
    } else {
        // AJOUT de la colonne photo dans la requête SQL
        await db.query(
            'INSERT INTO conducteur (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
            [nom,prenom, email, hashedPassword, photoPath]
        );
    }
    
    res.status(201).json({ message: 'Compte créé avec succès !' });

  } catch (error) {
    console.error("🚨 ERREUR INSCRIPTION CRITIQUE :", error);
    res.status(500).json({ message: "Erreur serveur ou email déjà utilisé." });
  }
});
// CONNEXION
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await findUserByEmail(email);

    if (!result) {
      return res.status(401).json({ message: 'Email ou mot de passe incorrect.' });
    }

    const { user, role, userId } = result;

    // --- CORRECTION 1 : On ajoute 'google_auth' dans la vérification ---
    if (!user.password || user.password === 'google_sso_no_password' || user.password === 'google_auth') {
        console.warn(`Tentative classique pour l'utilisateur SSO : ${email}`);
        return res.status(400).json({ message: "Ce compte a été créé avec Google. Veuillez utiliser le bouton 'Sign in with Google'." });
    }

    let isMatch = false;
    try {
        isMatch = await bcrypt.compare(password, user.password);
    } catch (bcryptError) {
        console.error(`Erreur Bcrypt :`, bcryptError.message);
    }

    if (!isMatch) {
      return res.status(401).json({ message: 'Email ou mot de passe incorrect.' });
    }

    // --- CORRECTION 2 : La même sécurité JWT que pour Google ---
    const secret = process.env.JWT_SECRET || 'fallback_secret_pour_soutenance';
    const token = jwt.sign({ id: userId, role: role }, secret, { expiresIn: '24h' });

    if (user.password) delete user.password;

    res.json({ 
      token, 
      user: { ...user, id: userId, role: role, prenom: user.prenom || null }
    });

  } catch (error) {
    console.error('================================================');
    console.error('❌ CRASH SUR LA ROUTE DE CONNEXION CLASSIQUE ❌');
    console.error('Email:', req.body.email); 
    console.error(error); 
    console.error('================================================');
    
    res.status(500).json({ message: "Erreur interne du serveur." });
  }
});
// --- INITIALISATION SÉCURISÉE ---
try {
  if (!admin.apps.length) {
    const serviceAccountString = process.env.FIREBASE_SERVICE_ACCOUNT;
    
    if (serviceAccountString) {
      const serviceAccount = JSON.parse(serviceAccountString);
      // Correction vitale pour Railway
      if (serviceAccount.private_key) {
        serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
      }
      
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
      });
      console.log("✅ Firebase Admin initialisé avec succès.");
    } else {
      console.error("❌ Variable FIREBASE_SERVICE_ACCOUNT manquante !");
    }
  }
} catch (e) {
  console.error("🚨 Erreur critique initialisation Firebase:", e.message);
}

// --- LA ROUTE GOOGLE BÉTONNÉE ---
app.post('/api/auth/google', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Token manquant' });
    }

    const token = authHeader.split(' ')[1];
    
    // Vérification Firebase
    const decodedToken = await admin.auth().verifyIdToken(token);
    const email = decodedToken.email;

    // REQUÊTE DB (On utilise un bloc Try/Catch interne pour éviter de crash tout le serveur)
    let user, role, userId;
    try {
      // Modifie ces requêtes selon tes noms de tables exacts
      const [rows] = await db.query('SELECT * FROM conducteur WHERE email = ?', [email]);
      
      if (rows.length === 0) {
        // Création si inexistant
        const nomComplet = decodedToken.name || 'Utilisateur';
        const [prenom, ...nomRest] = nomComplet.split(' ');
        const nom = nomRest.join(' ') || prenom;
        const photo = decodedToken.picture || null;

        const [insert] = await db.query(
          'INSERT INTO conducteur (nom, prenom, email, password, photo) VALUES (?, ?, ?, ?, ?)',
          [nom, prenom, email, 'google_auth', photo]
        );
        userId = insert.insertId;
        role = 'conducteur';
        user = { nom, prenom, email, photo };
      } else {
        user = rows[0];
        userId = user.id_cond;
        role = 'conducteur';
      }
    } catch (dbError) {
      console.error("🚨 Erreur Base de données:", dbError.message);
      return res.status(500).json({ message: "Erreur de base de données" });
    }

    // GÉNÉRATION JWT (Vérifie que JWT_SECRET est sur Railway !)
    const secret = process.env.JWT_SECRET || 'fallback_secret_pour_soutenance';
    const jwtToken = jwt.sign({ id: userId, role: role }, secret, { expiresIn: '24h' });

    res.json({
      token: jwtToken,
      user: { id: userId, email, role, nom: user.nom, photo: user.photo }
    });

  } catch (error) {
    console.error("🚨 Erreur Auth Google:", error.message);
    res.status(401).json({ message: "Authentification échouée", detail: error.message });
  }
});

// ==========================================
// 4. ROUTES ADMIN (gestionnaire)
// ==========================================

// AJOUTER parking + GENERER places
app.post('/api/admin/parking', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    // CORRECTION ICI : On ajoute latitude, longitude et image_url dans la récupération
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

    const id_gest = req.auth.userId;
    
    // DEBUG: On log tout le body pour être sûr
    console.log("DONNÉES REÇUES COMPLÈTES :", req.body); 

    // Validation des données (Ajoutez latitude/longitude si obligatoire)
    if (!nom || !adresse || !tarif_heure) {
        return res.status(400).json({ message: "Champs obligatoires manquants." });
    }

    const connection = await db.getConnection(); 
    try {
        await connection.beginTransaction();

        // CORRECTION DANS LA REQUÊTE SQL
        // On mappe 'image_url' (du front) vers la colonne 'image' (de la BDD)
        const [result] = await connection.query(
            "INSERT INTO parking (nom, adresse, tarif_heure, image, latitude, longitude, nb_rangees, nb_places_par_rangee, id_gest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                "INSERT INTO place (numero, id_park, disponibilite) VALUES ?",
                [places.map(p => [p.numero, p.id_park, p.disponibilite])]
            );
        }

        await connection.commit();
        res.status(201).json({ message: "Parking créé avec succès !", id_parking: result.insertId });
    } catch (error) {
        await connection.rollback();
        console.error("Erreur création parking :", error);
        res.status(500).json({ error: "Erreur lors de la création du parking" });
    } finally {
        connection.release();
    }
});

// LISTER MES parkings (gestionnaire) - Route sécurisée
app.get('/api/my-parkings', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    try {
        // On récupère l'ID du gestionnaire depuis le token, pas de l'URL. C'est plus sécurisé.
        const idGest = req.auth.userId;
        const [results] = await db.query("SELECT * FROM parking WHERE id_gest = ?", [idGest]);
        res.status(200).json(results);
    } catch (error) {
        console.error("Erreur récupération mes parkings:", error);
        res.status(500).json({ error: "Erreur base de données" });
    }
});

// 1. SUPPRIMER UN parking (CORRIGÉ AVEC paiements ET avis)
app.delete('/api/parkings/:id', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    const id = req.params.id;
    const id_gest_token = req.auth.userId;
    
    try {
        // VÉRIFICATION DE PROPRIÉTÉ : On s'assure que le parking appartient bien au gestionnaire qui fait la demande.
        const [parking] = await db.query("SELECT id_gest FROM parking WHERE id_park = ?", [id]);

        if (parking.length === 0) {
            return res.status(404).json({ error: "Parking introuvable." });
        }

        if (parking[0].id_gest !== id_gest_token) {
            // Ce n'est pas son parking, on refuse l'accès.
            return res.status(403).json({ error: "Accès refusé. Vous n'êtes pas le propriétaire de ce parking." });
        }

        console.log(`Tentative de suppression du parking ${id}...`);

        // ÉTAPE 1 : Supprimer les paiements liés aux réservations de ce parking
        await db.query(`
            DELETE FROM paiement 
            WHERE id_resa IN (
                SELECT id_resa FROM reservation 
                WHERE id_place IN (SELECT id_place FROM place WHERE id_park = ?)
            )
        `, [id]);

        // ÉTAPE 2 : Supprimer les RÉSERVATIONS liées aux places de ce parking
        await db.query(`
            DELETE FROM reservation 
            WHERE id_place IN (SELECT id_place FROM place WHERE id_park = ?)
        `, [id]);

        // ÉTAPE 3 : Supprimer les places de ce parking
        await db.query("DELETE FROM place WHERE id_park = ?", [id]);

        // ÉTAPE 4 (NOUVELLE) : Supprimer les avis liés à ce parking
        await db.query("DELETE FROM avis WHERE id_park = ?", [id]);

        // ÉTAPE 5 : Enfin, supprimer le parking
        const [result] = await db.query("DELETE FROM parking WHERE id_park = ?", [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Parking introuvable." });
        }

        console.log("parking, places, réservations, paiements et avis supprimés avec succès !");
        res.json({ message: "parking et toutes ses données supprimés avec succès !" });

    } catch (error) {
        console.error("Erreur SQL lors de la suppression :", error);
        res.status(500).json({ error: "Erreur interne (voir terminal pour détails)" });
    }
});
// --- Route pour MODIFIER un parking (Sécurisée) ---
// J'ai ajouté 'authMiddleware' ici pour protéger la route
app.put('/api/parkings/:id', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    const parkingId = req.params.id;
    const id_gest = req.auth.userId;
    // 1. On ne récupère PLUS nb_rangees et nb_places_par_rangee
    const { nom, adresse, tarif_heure } = req.body;

    console.log(`MODIFICATION parking ${parkingId}`);

    const tarif = parseFloat(tarif_heure);

    try {
        // VÉRIFICATION DE PROPRIÉTÉ
        const [parking] = await db.query("SELECT id_gest FROM parking WHERE id_park = ? AND id_gest = ?", [parkingId, id_gest]);

        if (parking.length === 0) {
            return res.status(403).json({ error: "Accès refusé ou parking introuvable." });
        }

        // 2. On met à jour uniquement le nom, l'adresse et le tarif
        const sql = `
            UPDATE parking 
            SET nom = ?, 
                adresse = ?, 
                tarif_heure = ?
            WHERE id_park = ?`;

        const [result] = await db.query(sql, [nom, adresse, tarif, parkingId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Parking introuvable (ID incorrect)" });
        }

        res.json({ message: "Parking modifié avec succès" });

    } catch (error) {
        console.error("Erreur SQL Update :", error);
        res.status(500).json({ error: "Erreur serveur lors de la modification" });
    }
});
// --- ROUTE PUBLIQUE : RECUPERER TOUS LES parkingS (POUR LE CLIENT) ---
app.get('/api/parkings', async (req, res) => {
    try {
        console.log("Client demande la liste des parkings...");
        const [rows] = await db.query("SELECT * FROM parking");
        res.json(rows);
    } catch (error) {
        console.error("Erreur récupération tous les parkings :", error);
        res.status(500).json({ error: "Erreur serveur" });
    }
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// ==========================================
// ROUTE : MISE À JOUR PROFIL (Unifiée & Dynamique)
// ==========================================

app.put('/api/profile', authMiddleware, upload.single('photo'), async (req, res) => {
    console.log("Demande de mise à jour de profil reçue...", req.body);

    const userId = req.auth.userId; 
    const userRole = req.auth.role;
    
    // On récupère toutes les données possibles envoyées par le frontend
    const { nom, prenom, email, password } = req.body;
    const newPhotoPath = req.file ? `/uploads/${req.file.filename}` : null;

    try {
        let fieldsToUpdate = [];
        let params = [];

        // 1. Construction dynamique de la requête : On n'ajoute que ce qui a été envoyé !
        if (nom) { fieldsToUpdate.push("nom = ?"); params.push(nom); }
        if (prenom) { fieldsToUpdate.push("prenom = ?"); params.push(prenom); }
        if (email) { fieldsToUpdate.push("email = ?"); params.push(email); }
        if (newPhotoPath) { fieldsToUpdate.push("photo = ?"); params.push(newPhotoPath); }
        
        // 2. Gestion du mot de passe
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            fieldsToUpdate.push("password = ?"); 
            params.push(hashedPassword);
        }
        // Si on a appelé la route mais sans aucune donnée
        if (fieldsToUpdate.length === 0) {
            return res.status(400).json({ message: "Aucune donnée à mettre à jour." });
        }

        // On assemble les morceaux de la requête SQL
        const querySet = fieldsToUpdate.join(", ");
        let sql = "";

        // 3. Application selon le rôle
        if (userRole === 'conducteur') {
            sql = `UPDATE conducteur SET ${querySet} WHERE id_cond = ?`;
            params.push(userId);
        } else if (userRole === 'gestionnaire') {
            sql = `UPDATE gestionnaire SET ${querySet} WHERE id_gest = ?`;
            params.push(userId);
        } else {
            return res.status(403).json({ message: "Rôle non autorisé." });
        }

        // 4. Exécution de la requête
        const [result] = await db.query(sql, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Utilisateur introuvable." });
        }

        console.log(`Profil ${userRole} (ID: ${userId}) mis à jour avec succès !`);
        
        res.json({ 
            message: "Mise à jour réussie", 
            photo: newPhotoPath,
            // On renvoie ce qui a été mis à jour
            updatedFields: Object.keys(req.body) 
        });

    } catch (error) {
        console.error("Erreur Update Profil:", error);
        res.status(500).json({ error: "Erreur base de données", details: error.message });
    }
});
// ==========================================
// 5. ROUTES CLIENT (MAP & réservation)
// ==========================================

// Récupérer la MAP (Configuration + État des places)
app.get('/api/parking-map/:id', async (req, res) => {
    try {
        const parkingId = req.params.id;

        // 1. Récupérer config
        const [parkingInfo] = await db.query(
            "SELECT nb_rangees, nb_places_par_rangee FROM parking WHERE id_park = ?", // Vérifie si c'est 'id' ou 'id_park' dans ta base
            [parkingId]
        );

        if (parkingInfo.length === 0) return res.status(404).json({message: "parking introuvable"});

        // 2. Récupérer places + statuts
        const query = `
            SELECT 
                p.id_place, 
                p.numero, 
                CASE 
                    WHEN r.id_resa IS NOT NULL THEN 'occupé' 
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
        console.error("Erreur récupération places:", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Démarrer une réservation (Client)
app.post('/api/reservation/start', authMiddleware, roleMiddleware(['conducteur']), async (req, res) => {
    const { id_place } = req.body;
    const id_cond = req.auth.userId; 

    try {
        // 1. Vérifier si le conducteur a DÉJÀ une réservation active
        const [activeRes] = await db.query(
            'SELECT * FROM reservation WHERE id_cond = ? AND date_depart IS NULL',
            [id_cond]
        );

        if (activeRes.length > 0) {
            return res.status(400).json({ message: "Vous avez déjà une réservation en cours." });
        }

        // 2. Vérifier si la place est libre et récupérer l'ID du parking
        // CORRECTION : On utilise 'disponibilite' (pas 'statu')
        const [placeStatus] = await db.query(
            'SELECT disponibilite, id_park FROM place WHERE id_place = ?', 
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
            'INSERT INTO reservation (date_arrivee, id_cond, id_place) VALUES (NOW(), ?, ?)',
            [id_cond, id_place]
        );

        // 4. Mettre la place en 'occupé'
        // CORRECTION : On met 'disponibilite' à 0
        await db.query('UPDATE place SET disponibilite = 0 WHERE id_place = ?', [id_place]);

        res.json({ 
            message: "Réservation démarrée !", 
            id_res: result.insertId,
            place: id_place
        });

    } catch (err) {
        console.error("Erreur reservation Start :", err); // Le log sera plus précis
        res.status(500).json({ message: "Erreur serveur lors de la réservation." });
    }
});
// ==========================================
// ROUTE : Vérifier réservation active
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
            // Important : Renvoyer 404 est normal si pas de réservation, le front le gère
            res.status(404).json({ message: "Aucune réservation active" });
        }
    } catch (err) {
        console.error("Erreur Active Resa:", err.message);
        // On renvoie 404 pour ne pas bloquer le front en cas de souci
        res.status(404).send("Erreur ou pas de réservation");
    }
});
// ==========================================
//  STOP reservation + LIBÉRATION place
// ==========================================
app.post('/api/reservation/stop', authMiddleware, async (req, res) => {
    const { id_resa } = req.body;
    const id_cond_token = req.auth.userId;

    console.log(`Tentative d'arrêt de la réservation ${id_resa} par l'utilisateur ${id_cond_token}`);

    if (!id_resa) {
        return res.status(400).json({ error: "ID de réservation manquant" });
    }

    const connection = await db.getConnection(); // On prend une connexion dédiée pour la transaction

    try {
        await connection.beginTransaction(); // Début transaction (sécurité)

        // 1. Récupérer les infos de la réservation (Date début + ID place)
        const [rows] = await connection.query(
            "SELECT * FROM reservation WHERE id_resa = ?", 
            [id_resa]
        );

        if (rows.length === 0) {
            await connection.rollback();
            return res.status(404).json({ error: "Réservation introuvable" });
        }

        const resa = rows[0];

        // CONTRÔLE DE SÉCURITÉ : L'utilisateur authentifié doit être le propriétaire de la réservation
        if (resa.id_cond !== id_cond_token) {
            await connection.rollback();
            return res.status(403).json({ message: "Accès non autorisé à cette réservation." });
        }

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

        // RÉCUPÉRATION DU VRAI TARIF HORAIRE
        const [parking] = await connection.query(
            `SELECT p.tarif_heure FROM parking p 
             JOIN place pl ON p.id_park = pl.id_park 
             WHERE pl.id_place = ?`,
            [resa.id_place]
        );

        // Utilise le tarif du parking, ou 4.00 comme valeur par défaut si non trouvé
        const tarifHoraire = parking.length > 0 ? parking[0].tarif_heure : 4.00;
        const montant = (Math.max(1, hours) * tarifHoraire).toFixed(2); // Minimum 1h facturée

        console.log(`Calcul: ${hours}h * ${tarifHoraire}DH/h = ${montant} DH`);

        // 3. Mettre à jour la Réservation (Date fin + Prix)
        await connection.query(
            "UPDATE reservation SET date_depart = ?, prix_total = ? WHERE id_resa = ?",
            [dateFin, montant, id_resa]
        );

        // 4. LIBÉRER LA place (C'était l'oubli critique !)
        // On remet disponibilite à 1 (Libre)
        await connection.query(
            "UPDATE place SET disponibilite = 1 WHERE id_place = ?",
            [resa.id_place]
        );

        await connection.commit(); // Valider tout
        connection.release();

        console.log("Réservation terminée et place libérée.");

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
        console.error("Erreur Stop Réservation:", error);
        res.status(500).json({ error: "Erreur serveur lors de l'arrêt" });
    }
});
// CONFIRMATION paiement + CLÔTURE RÉSERVATION + LIBÉRATION place
app.post('/api/paiement/confirm', authMiddleware, async (req, res) => {
    console.log("Validation finale du paiement...");
    const { id_resa, montant, mode } = req.body;
    const id_cond_token = req.auth.userId;

    if (!id_resa || !montant) {
        return res.status(400).json({ success: false, message: "Données manquantes." });
    }

    try {
        // CONTRÔLE DE SÉCURITÉ : Vérifier que la réservation appartient à l'utilisateur qui confirme le paiement
        const [resa] = await db.query('SELECT id_cond FROM reservation WHERE id_resa = ?', [id_resa]);
        if (resa.length === 0) {
            return res.status(404).json({ success: false, message: "Réservation non trouvée." });
        }
        if (resa[0].id_cond !== id_cond_token) {
            return res.status(403).json({ success: false, message: "Accès non autorisé à cette réservation." });
        }

        // SIMPLIFICATION : La route 'stop' a déjà mis fin à la réservation et libéré la place.
        // Cette route ne fait plus qu'une seule chose : enregistrer que le paiement a bien été effectué.
        await db.query(
            "INSERT INTO paiement (id_resa, montant, date, mode) VALUES (?, ?, ?, ?)",
            [id_resa, montant, new Date(), mode]
        );

        console.log(`Paiement de ${montant} pour la réservation ${id_resa} enregistré.`);
        res.json({ success: true, message: "Paiement enregistré avec succès !" });

    } catch (err) {
        console.error("Erreur SQL Finale :", err);
        // Gestion d'erreur si le paiement existe déjà (si id_resa est une clé unique dans la table paiement)
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ success: false, message: "Un paiement a déjà été enregistré pour cette réservation." });
        }
        res.status(500).json({ success: false, message: "Erreur serveur", details: err.message });
    }
});
// ==========================================
// ROUTE : Historique Visuel (SÉCURISÉE)
// ==========================================
// 1. On ajoute 'authMiddleware' pour forcer la vérification du Token
app.get('/api/reservations/history', authMiddleware, async (req, res) => {
    
    // 2. LE SECRET EST ICI : On ignore req.params.id (l'URL)
    // On prend l'ID directement depuis le token de la personne connectée !
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
        console.error("Erreur historique :", err);
        res.status(500).json({ error: "Erreur serveur lors de la récupération de l'historique" });
    }
});

// Route sécurisée pour récupérer les notifications de l'utilisateur connecté
app.get('/api/notifications', authMiddleware, async (req, res) => {
    try {
        const id_cond = req.auth.userId; // ID sécurisé depuis le token
        const sql = "SELECT * FROM notification WHERE id_cond = ? ORDER BY date_notif DESC";
        
        console.log(`Récupération des notifications pour l'utilisateur ${id_cond}`);
        const [results] = await db.query(sql, [id_cond]);
        
        res.status(200).json(results);
        
    } catch (err) {
        console.error("ERREUR SQL :", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Route sécurisée pour marquer une notification comme lue
app.put('/api/notifications/marquer-lu/:id_notif', authMiddleware, async (req, res) => {
    try {
        const id_notif = parseInt(req.params.id_notif, 10);
        const id_cond_token = req.auth.userId;

        // CONTRÔLE DE SÉCURITÉ : Vérifier que la notification appartient à l'utilisateur connecté
        const [notif] = await db.query("SELECT id_cond FROM notification WHERE id_notif = ?", [id_notif]);

        if (notif.length === 0) {
            return res.status(404).json({ message: "Notification non trouvée." });
        }

        if (notif[0].id_cond !== id_cond_token) {
            return res.status(403).json({ message: "Accès non autorisé à cette notification." });
        }

        const sql = "UPDATE notification SET lu = 1 WHERE id_notif = ?";
        await db.query(sql, [id_notif]); // La condition WHERE est suffisante ici
        res.status(200).json({ message: "Notification lue avec succès" });
    } catch (err) {
        console.error("ERREUR SQL PUT :", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});
// ==========================================
// ROUTE MANAGER : TOUTES LES RÉSERVATIONS
// ==========================================
app.get('/api/manager/reservations', authMiddleware, roleMiddleware(['gestionnaire']), async (req, res) => {
    // On utilise l'ID du token pour sécuriser la route
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
                    ELSE 'Terminé' 
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
    // On utilise l'ID du token pour sécuriser la route
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
            JOIN conducteur c ON r.id_cond = c.id_cond  -- La jointure manquante
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
// Route Backend (index.js)
app.put('/api/manager/update', authMiddleware, upload.single('image'), async (req, res) => {
    const idGest = req.auth.userId; // Sécurité : on prend l'ID du token
    const { nom, email } = req.body;
    let imagePath = null;

    if (req.file) {
        imagePath = `/uploads/${req.file.filename}`; // Chemin de la nouvelle photo
    }

    try {
        let sql = "UPDATE gestionnaire SET nom = ?, email = ?";
        let params = [nom, email];

        if (imagePath) {
            sql += ", photo = ?"; // Assure-toi que la colonne s'appelle 'photo' ou 'image'
            params.push(imagePath);
        }

        sql += " WHERE id_gest = ?";
        params.push(idGest);

        await db.query(sql, params);

        res.json({ 
            success: true, 
            newImage: imagePath // Très important : ton front attend 'newImage'
        });
    } catch (error) {
        res.status(500).json({ error: "Erreur DB" });
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

// ROUTE : Ajouter un avis (Corrigée)
app.post('/api/reviews', authMiddleware, roleMiddleware(['conducteur']), async (req, res) => {
    // On récupère les données envoyées par React
    const { id_park, note, commentaire } = req.body; 
    // On utilise l'ID de l'utilisateur authentifié, pas celui envoyé par le client. C'est plus sûr.
    const id_user = req.auth.userId;

    console.log("Tentative d'ajout d'avis :", { id_park, id_user: id_user, note, commentaire });

    try {
        // AMÉLIORATION : Vérifier si l'utilisateur a déjà une réservation terminée pour ce parking.
        // Cela évite les faux avis.
        const checkResaSql = `
            SELECT r.id_resa 
            FROM reservation r
            JOIN place pl ON r.id_place = pl.id_place
            WHERE r.id_cond = ? AND pl.id_park = ? AND r.date_depart IS NOT NULL
            LIMIT 1
        `;
        const [reservationsPassees] = await db.query(checkResaSql, [id_user, id_park]);

        if (reservationsPassees.length === 0) {
            return res.status(403).json({ message: "Vous ne pouvez laisser un avis que sur les parkings que vous avez utilisés." });
        }

        // ÉTAPE 1 : Trouver l'ID du gestionnaire (id_gest) qui possède ce parking
        const sqlGetGest = "SELECT id_gest FROM parking WHERE id_park = ?";
        const [rows] = await db.query(sqlGetGest, [id_park]);

        if (rows.length === 0) {
            return res.status(404).json({ message: "parking introuvable, impossible d'ajouter l'avis." });
        }

        const id_gest = rows[0].id_gest; // On a trouvé le gestionnaire !

        // ÉTAPE 2 : Insérer l'avis avec TOUTES les infos (y compris id_gest)
        // Attention : J'utilise 'message' car votre log montrait que la colonne s'appelle ainsi.
        const sqlInsert = `
            INSERT INTO avis (id_park, id_cond, id_gest, note, message, date_avis) 
            VALUES (?, ?, ?, ?, ?, NOW())
        `;

        await db.query(sqlInsert, [id_park, id_user, id_gest, note, commentaire]);

        res.status(201).json({ message: "Avis ajouté avec succès !" });

    } catch (err) {
        console.error("Erreur ajout avis:", err);
        res.status(500).json({ 
            message: "Erreur serveur lors de l'ajout de l'avis",
            details: err.message 
        });
    }
});

// =========================================================
// TÂCHE PLANIFIÉE : RAPPEL DES 1 MINUTES + FIREBASE (FINAL)
// =========================================================

cron.schedule('* * * * *', async () => {
    try {
        // NOUVEAUTÉ : On fait une JOINTURE (JOIN) pour récupérer le fcm_token du conducteur !
        const querySelect = `
            SELECT r.id_resa, r.id_cond, r.date_arrivee, c.fcm_token 
            FROM reservation r
            JOIN conducteur c ON r.id_cond = c.id_cond
            WHERE TIMESTAMPDIFF(MINUTE, r.date_arrivee, NOW()) >= 1
            AND r.date_depart IS NULL
        `;

        const [reservations] = await db.query(querySelect);

        for (const resa of reservations) {
            const titre = "Rappel de stationnement "; // Changed emoji for consistency with "1 minute"
            const message = `Attention : Cela fait plus de 1 minute que votre stationnement (Réservation n°${resa.id_resa}) a commencé.`;

            const checkNotifQuery = `SELECT id_notif FROM notification WHERE id_cond = ? AND message = ?`;
            const [notifs] = await db.query(checkNotifQuery, [resa.id_cond, message]);

            if (notifs.length === 0) {
                // 1. Sauvegarder dans la base de données
                const insertQuery = `INSERT INTO notification (id_cond, titre, message, lu) VALUES (?, ?, ?, 0)`;
                await db.query(insertQuery, [resa.id_cond, titre, message]);
                console.log(`[CRON] Notification BDD enregistrée (Réservation n°${resa.id_resa})`);

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
                        console.log(`Notification Push envoyée au téléphone du client ${resa.id_cond} !`);
                    } catch (pushError) {
                        console.error(`Erreur Push Firebase pour le client ${resa.id_cond} :`, pushError.message);
                    }
                } else {
                    console.log(`Client ${resa.id_cond} n'a pas de Token FCM. Notification push ignorée.`);
                }
            }
        }

    } catch (error) {
        console.error("[CRON] Erreur :", error);
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
        // On vérifie le rôle pour mettre à jour la bonne table
        if (userRole === 'conducteur' || userRole === 'client') {
            sql = "UPDATE conducteur SET fcm_token = ? WHERE id_cond = ?";
        } else {
            sql = "UPDATE gestionnaire SET fcm_token = ? WHERE id_gest = ?";
        }

        await db.query(sql, [fcmToken, userId]);
        console.log(`Token FCM sauvegardé pour l'utilisateur ${userRole} (ID: ${userId})`);
        
        res.json({ success: true, message: "Token Firebase enregistré avec succès !" });

    } catch (error) {
        console.error("Erreur lors de la sauvegarde du Token FCM :", error);
        res.status(500).json({ error: "Erreur base de données" });
    }
});
//=========================================
// 6. LANCEMENT
// ==========================================
app.listen(port, () => {
  console.log(`Serveur Backend prêt sur http://localhost:${port}`);
});

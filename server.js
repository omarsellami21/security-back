const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Chiffrement Affine
function affineEncrypt(text, a, b) {
  return text
    .split('')
    .map((char) => {
      if (/[a-z]/i.test(char)) {
        const base = char.toLowerCase() === char ? 97 : 65;
        return String.fromCharCode(((a * (char.charCodeAt(0) - base) + b) % 26) + base);
      }
      return char;
    })
    .join('');
}

// Déchiffrement Affine
function affineDecrypt(text, a, b) {
  // Inverse of a in modular arithmetic (multiplicative inverse)
  const aInverse = modInverse(a, 26);
  if (aInverse === -1) throw new Error("Clé invalide pour le déchiffrement Affine");

  return text
    .split('')
    .map((char) => {
      if (/[a-z]/i.test(char)) {
        const base = char.toLowerCase() === char ? 97 : 65;
        return String.fromCharCode(((aInverse * (char.charCodeAt(0) - base - b + 26)) % 26) + base);
      }
      return char;
    })
    .join('');
}

// Calcul de l'inverse modulaire
function modInverse(a, m) {
  for (let i = 1; i < m; i++) {
    if ((a * i) % m === 1) return i;
  }
  return -1; // Si l'inverse modulaire n'existe pas
}

// Chiffrement César
function cesarEncrypt(text, shift) {
  if (isNaN(shift)) {
    throw new Error("Clé invalide pour le chiffrement César (clé doit être un nombre)");
  }
  return text
    .split('')
    .map((char) => {
      if (/[a-z]/i.test(char)) {
        const base = char.toLowerCase() === char ? 97 : 65;
        return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26) + base);
      }
      return char;
    })
    .join('');
}

// Déchiffrement César
function cesarDecrypt(text, shift) {
  if (isNaN(shift)) {
    throw new Error("Clé invalide pour le déchiffrement César (clé doit être un nombre)");
  }
  return text
    .split('')
    .map((char) => {
      if (/[a-z]/i.test(char)) {
        const base = char.toLowerCase() === char ? 97 : 65;
        return String.fromCharCode(((char.charCodeAt(0) - base - shift + 26) % 26) + base);
      }
      return char;
    })
    .join('');
}

// Chiffrement Vigenère
function vigenereEncrypt(text, key) {
  let keyIndex = 0;
  return text
    .split('')
    .map((char) => {
      if (/[a-z]/i.test(char)) {
        const base = char.toLowerCase() === char ? 97 : 65;
        const shift = key[keyIndex % key.length].toLowerCase().charCodeAt(0) - 97;
        keyIndex++;
        return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26) + base);
      }
      return char;
    })
    .join('');
}

// Déchiffrement Vigenère
function vigenereDecrypt(text, key) {
  let keyIndex = 0;
  return text
    .split('')
    .map((char) => {
      if (/[a-z]/i.test(char)) {
        const base = char.toLowerCase() === char ? 97 : 65;
        const shift = key[keyIndex % key.length].toLowerCase().charCodeAt(0) - 97;
        keyIndex++;
        return String.fromCharCode(((char.charCodeAt(0) - base - shift + 26) % 26) + base);
      }
      return char;
    })
    .join('');
}

// Chiffrement AES
function aesEncrypt(text, key) {
  const iv = crypto.randomBytes(16); // Initialization vector
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted; // Prepend IV for decryption
}

// Déchiffrement AES
function aesDecrypt(encryptedText, key) {
  const parts = encryptedText.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedTextBuffer = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedTextBuffer, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// API pour le chiffrement
app.post('/encrypt', (req, res) => {
  const { text, key, algorithm } = req.body;
  let result;

  try {
    switch (algorithm) {
      case 'affine':
        const [a, b] = key.split(',').map(Number); // Exemple de clé : "5,8"
        if (!a || !b) throw new Error("Clé invalide pour le chiffrement Affine");
        result = affineEncrypt(text, a, b);
        break;

      case 'cesar':
        if (!key) throw new Error("Clé invalide pour le chiffrement César");
        result = cesarEncrypt(text, parseInt(key));
        break;

      case 'vigenere':
        if (!key) throw new Error("Clé invalide pour le chiffrement Vigenère");
        result = vigenereEncrypt(text, key);
        break;

      case 'aes':
        if (key.length !== 32) throw new Error("Clé invalide pour le chiffrement AES (doit être de 32 octets)");
        result = aesEncrypt(text, key);
        break;

      default:
        throw new Error("Algorithme inconnu");
    }
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// API pour le déchiffrement
app.post('/decrypt', (req, res) => {
  const { text, key, algorithm } = req.body;
  let result;

  try {
    switch (algorithm) {
      case 'affine':
        const [a, b] = key.split(',').map(Number);
        if (!a || !b) throw new Error("Clé invalide pour le déchiffrement Affine");
        result = affineDecrypt(text, a, b);
        break;

      case 'cesar':
        if (!key) throw new Error("Clé invalide pour le déchiffrement César");
        result = cesarDecrypt(text, parseInt(key));
        break;

      case 'vigenere':
        if (!key) throw new Error("Clé invalide pour le déchiffrement Vigenère");
        result = vigenereDecrypt(text, key);
        break;

      case 'aes':
          if (key.length !== 32) throw new Error("Clé invalide pour le déchiffrement AES (doit être de 32 octets)");
          result = aesDecrypt(text, key);
          break;

      default:
        throw new Error("Algorithme inconnu");
    }
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Démarrage du serveur
app.listen(5000, () => {
  console.log('Serveur backend lancé sur http://localhost:5000');
});

// Requiere la biblioteca crypto-js y elliptic
// CryptoJS: https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js
// Elliptic: https://cdnjs.cloudflare.com/ajax/libs/elliptic/6.5.4/elliptic.min.js

const EC = elliptic.ec;
const ec = new EC('secp256k1');

// Función para desplazar caracteres en la tabla ASCII
function shiftCharacters(text, shift) {
    return text.split('').map(char => String.fromCharCode(char.charCodeAt(0) + shift)).join('');
}

// Función para cifrar un mensaje con AES y modificaciones personalizadas
function customEncrypt(message, key) {
    if (!message) return "";

    // Cifra el mensaje usando AES
    let encrypted = CryptoJS.AES.encrypt(message, key).toString();

    // Guarda la primera y última letra
    const firstChar = encrypted[0];
    const lastChar = encrypted[encrypted.length - 1];

    // Elimina la primera y última letra del mensaje cifrado
    encrypted = encrypted.slice(1, -1);

    // Mueve el carácter penúltimo a una posición aleatoria
    let randomIndex = -1;
    if (encrypted.length > 1) {
        const chars = encrypted.split("");
        const penultimateChar = chars.splice(chars.length - 1, 1)[0]; // Penúltimo carácter original
        randomIndex = Math.floor(Math.random() * chars.length); // Posición aleatoria
        chars.splice(randomIndex, 0, penultimateChar); // Inserta el carácter en posición aleatoria
        encrypted = chars.join("");
    }

    // Si el mensaje original tiene más de 5 caracteres, añade un `#`
    if (message.length > 5) {
        encrypted += "#";
    }

    // Invertir el mensaje cifrado
    encrypted = encrypted.split('').reverse().join('');

    // Desplazar caracteres en el mensaje cifrado
    encrypted = shiftCharacters(encrypted, 1);

    // Crear metadatos (sin incluir el #)
    let metadata = `${randomIndex}|${firstChar}|${lastChar}`;

    // Modificar metadatos desplazando números en 2 y letras en 2
    metadata = metadata.split('').map(char => {
        if (char >= '0' && char <= '9') {
            return String.fromCharCode(char.charCodeAt(0) + 2);
        } else if ((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')) {
            return String.fromCharCode(char.charCodeAt(0) + 2);
        }
        return char;
    }).join('');

    // Cifra los metadatos
    const encryptedMetadata = CryptoJS.AES.encrypt(metadata, key).toString();

    // Adjunta los metadatos cifrados al final del mensaje cifrado
    encrypted += `|${encryptedMetadata}`;

    return encrypted;
}

// Función para descifrar un mensaje cifrado con AES y modificaciones personalizadas
function customDecrypt(encryptedMessage, key) {
    if (!encryptedMessage) return "";

    // Separa los metadatos cifrados del mensaje cifrado
    const parts = encryptedMessage.split("|");
    if (parts.length < 2) {
        throw new Error("El mensaje cifrado no contiene los metadatos necesarios.");
    }

    // Extraemos el mensaje cifrado y los metadatos cifrados
    let encryptedContent = parts.slice(0, -1).join("|");
    const encryptedMetadata = parts[parts.length - 1];

    // Descifra los metadatos
    let metadata;
    try {
        const bytesMetadata = CryptoJS.AES.decrypt(encryptedMetadata, key);
        metadata = bytesMetadata.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        throw new Error("No se pudieron descifrar los metadatos. Verifica la clave.");
    }

    // Restaurar los metadatos a sus valores originales
    metadata = metadata.split('').map(char => {
        if (char >= '2' && char <= '9') {
            return String.fromCharCode(char.charCodeAt(0) - 2);
        } else if ((char >= 'c' && char <= 'z') || (char >= 'C' && char <= 'Z')) {
            return String.fromCharCode(char.charCodeAt(0) - 2);
        }
        return char;
    }).join('');

    // Extraemos los metadatos originales
    const [randomIndex, firstChar, lastChar] = metadata.split("|");

    // Restaurar el desplazamiento de caracteres en el mensaje cifrado
    encryptedContent = shiftCharacters(encryptedContent, -1);

    // Restaurar la inversión del mensaje cifrado
    encryptedContent = encryptedContent.split('').reverse().join('');

    // Elimina el `#` si está presente
    if (encryptedContent.endsWith("#")) {
        encryptedContent = encryptedContent.slice(0, -1);
    }

    // Restaura el carácter penúltimo desde la posición aleatoria
    if (randomIndex !== "-1" && encryptedContent.length > 1) {
        const chars = encryptedContent.split("");
        const penultimateChar = chars.splice(randomIndex, 1)[0];
        chars.push(penultimateChar); // Reubica en la última posición
        encryptedContent = chars.join("");
    }

    // Restaura la primera y última letra eliminadas
    encryptedContent = firstChar + encryptedContent + lastChar;

    // Descifra el mensaje final usando AES
    try {
        const bytes = CryptoJS.AES.decrypt(encryptedContent, key);
        return bytes.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        throw new Error("No se pudo descifrar el mensaje. Verifica la clave y el formato del mensaje.");
    }
}
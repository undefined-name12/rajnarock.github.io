// Requiere la biblioteca crypto-js: https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js

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

    // Crear metadatos (sin incluir el #)
    const metadata = `${randomIndex}|${firstChar}|${lastChar}`;

    // Cifra los metadatos de forma segura (utilizando AES o base64)
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
    const encryptedContent = parts.slice(0, -1).join("|");
    const encryptedMetadata = parts[parts.length - 1];

    // Descifra los metadatos
    let metadata;
    try {
        const bytesMetadata = CryptoJS.AES.decrypt(encryptedMetadata, key);
        metadata = bytesMetadata.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        throw new Error("No se pudieron descifrar los metadatos. Verifica la clave.");
    }

    // Extraemos los metadatos: randomIndex, firstChar, lastChar
    const [randomIndex, firstChar, lastChar] = metadata.split("|");

    // Descifra el mensaje cifrado original
    let decryptedMessage = encryptedContent;

    // Elimina el `#` si está presente
    if (decryptedMessage.endsWith("#")) {
        decryptedMessage = decryptedMessage.slice(0, -1);
    }

    // Restaura el carácter penúltimo desde la posición aleatoria
    if (randomIndex !== -1 && decryptedMessage.length > 1) {
        const chars = decryptedMessage.split("");
        const penultimateChar = chars.splice(randomIndex, 1)[0];
        chars.push(penultimateChar); // Reubica en la última posición
        decryptedMessage = chars.join("");
    }

    // Restaura la primera y última letra eliminadas
    decryptedMessage = firstChar + decryptedMessage + lastChar;

    // Descifra el mensaje final usando AES
    try {
        const bytes = CryptoJS.AES.decrypt(decryptedMessage, key);
        return bytes.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        throw new Error("No se pudo descifrar el mensaje. Verifica la clave y el formato del mensaje.");
    }
}
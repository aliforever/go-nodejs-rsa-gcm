var crypto = require('crypto');

function rsa_public_encrypt(key, data) {
    return crypto.publicEncrypt({
        key: key,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, data);
}

function rsa_private_decrypt(key, data) {
    return crypto.privateDecrypt({
        key: key,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, data);
}

function aes_gcm_encrypt(key, additional_data, data) {
    var iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(additional_data);

    const aesEncrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);

    // Prepend IV & Append Authentication Tag for the Encrypted data to be usable in Go
    return Buffer.concat(
        iv,
        aesEncrypted,
        cipher.getAuthTag(),
    );
}

function aes_gcm_decrypt(key, additional_data, input) {
    // Extract IV & Authentication Tag First
    const inputBuffer = Buffer.from(input, 'base64');
    const iv = Buffer.allocUnsafe(ivLength);
    const tag = Buffer.allocUnsafe(tagLength);
    const data = Buffer.alloc(inputBuffer.length - ivLength - tagLength, 0);

    inputBuffer.copy(iv, 0, 0, ivLength);
    inputBuffer.copy(tag, 0, inputBuffer.length - tagLength);
    inputBuffer.copy(data, 0, ivLength);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag);
    decipher.setAAD(additional_data);

    return Buffer.concat(
        decipher.update(data, null, 'utf8'),
        decipher.final('utf8'),
    );
}

// Load keys from file or use base64 encoded pem of keys
var public_key = "";
var private_key = "";

var key = crypto.randomBytes(32);
var iv = crypto.randomBytes(12);

console.log("Key", key.toString('base64'));
rsa_encrypted = rsa_public_encrypt(public_key, key);
console.log("RSA Encrypted Key", rsa_encrypted.toString('base64'));

// Remember to use Buffer.from(rsa_encrypted_base64).toString('base64') if it working with base64 encoded data & keys
rsa_decrypted = rsa_private_decrypt(private_key, rsa_encrypted);
console.log("RSA Decrypted Key", rsa_decrypted.toString('base64'))

var data = "Hello"
aes_encrypted = aes_gcm_encrypt(key, null, data)
console.log("AES GCM Encrypted", aes_encrypted.toString('base64'))

aes_decrypted = aes_gcm_decrypt(key, null, aes_encrypted)
console.log("AES GCM Decrypted", aes_decrypted.toString())


class Utilities {
    /**
     * 
     * @param {ArrayBuffer} buf 
     * @returns 
     */
    static ab2str(buf) {
        return String.fromCharCode.apply(null, new Uint8Array(buf));
    }
    
    /**
     * 
     * @param {string} str 
     * @returns 
     */
    static str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }

    /**
     * 
     * @param {number} num 
     * @param {number} size 
     * @returns 
     */
    static numToUint8Array(num, size=12) {
        let arr = new Uint8Array(size);
      
        for (let i = 0; i < 8; i++) {
          arr[i] = num % 256;
          num = Math.floor(num / 256);
        }
      
        return arr;
    }
    
    /**
     * 
     * @param {Uint8Array} arr 
     * @returns 
     */
    static uint8ArrayToNum(arr) {
        let num = 0;
        const len = arr.length;
      
        for (let i = len-1; i >= 0; i--) {
          num = num * 256 + arr[i];
        }
      
        return num;
    }
    
    /**
     * 
     * @param {string} message 
     * @returns 
     */
    static encodeMessage(message) {
        const enc = new TextEncoder();
        return enc.encode(message);
    }

    /**
     * 
     * @param {Uint8Array} bytes 
     * @returns 
     */
    static decodeMessage(bytes){
        const decoder = new TextDecoder()
        return decoder.decode(bytes);
    }

    /**
     * 
     * @param {string} str 
     * @returns 
     */
    static base64ToBytes(str) {
        const binaryString = window.atob(str);
        const bytes = Utilities.str2ab(binaryString);
        return bytes;
    }

    /**
     * 
     * @param {ArrayBuffer} bytes 
     * @returns 
     */
    static bytesToBase64(bytes) {
        const exportedAsString = Utilities.ab2str(bytes);
        const base64String = window.btoa(exportedAsString);
        return base64String;
    }
}



// ---------------------------CRYPTO UTILITIES ---------------------------------------------

class CryptoUtilities {
    /**
     * This function generates a pair of `EDCH` Keys of curve `P-384`
     * @returns 
     */
    static async generateECKeyPair(){
        const pair = await crypto.subtle.generateKey({
            name: 'ECDH', 
            namedCurve: 'P-384'
        }, true, ['deriveBits']);
        return pair;
    }
    
    /**
     * 
     * @param {CryptoKey} key 
     * @returns 
     */
    static async exportPublicKey(key){
        const exportedKey = await window.crypto.subtle.exportKey('spki', key);
        const exportedAsString = Utilities.ab2str(exportedKey);
        const exportedAsBase64 = window.btoa(exportedAsString);
        const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
        
        return pemExported;
    }
    
    /**
     * 
     * @param {CryptoKey} key 
     * @returns 
     */
    static async exportPrivateKey(key){
        const exportedKey = await window.crypto.subtle.exportKey('pkcs8', key);
        const exportedAsString = Utilities.ab2str(exportedKey);
        const exportedAsBase64 = window.btoa(exportedAsString);
        const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
        
        return pemExported;
    }
    
    /**
     * 
     * @param {string} pem 
     * @returns 
     */
    static async importPrivateKey(pem) {
      // fetch the part of the PEM string between header and footer
      const pemHeader = "-----BEGIN PRIVATE KEY-----";
      const pemFooter = "-----END PRIVATE KEY-----";
      const pemContents = pem.substring(
        pemHeader.length,
        pem.length - pemFooter.length - 1,
      );
      // base64 decode the string to get the binary data
      const binaryDerString = window.atob(pemContents);
      // convert from a binary string to an ArrayBuffer
      const binaryDer = Utilities.str2ab(binaryDerString);
    
      return await window.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
          name: "ECDH",
          namedCurve: 'P-384'
        },
        true,
        ["deriveBits"],
      );
    }
    
    /**
     * 
     * @param {string} pem 
     * @returns 
     */
    static async importPublicKey(pem) {
      // fetch the part of the PEM string between header and footer
      const pemHeader = "-----BEGIN PUBLIC KEY-----";
      const pemFooter = "-----END PUBLIC KEY-----";
      const pemContents = pem.substring(
        pemHeader.length,
        pem.length - pemFooter.length - 1,
      );
      // base64 decode the string to get the binary data
      const binaryDerString = window.atob(pemContents);
      // convert from a binary string to an ArrayBuffer
      const binaryDer = Utilities.str2ab(binaryDerString);
    
      const key = await window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
          name: "ECDH",
          namedCurve: 'P-384'
        },
        true,
        [],
      );

      return key;
    }
    
    /**
     * 
     * @param {CryptoKey} privateKey 
     * @param {CryptoKey} publicKey 
     * @returns 
     */
    static async deriveSharedSecret(privateKey, publicKey) {
      const sharedSecret = await window.crypto.subtle.deriveBits(
        {
          name: "ECDH",
          namedCurve: "P-384",
          public: publicKey,
        },
        privateKey,
        256,
      );
      
      const key = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "HKDF" },
            false,
            ["deriveKey"]
        );
      
      return [sharedSecret, key];
    }

    static async deriveKeyFromSecret(secret){
        const sharedSecret = Utilities.base64ToBytes(secret);
        const key = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "HKDF" },
            false,
            ["deriveKey"]
        );
      
      return [sharedSecret, key];
    }
    
    /**
     * 
     * @param {CryptoKey} baseKeyMaterial 
     * @param {Uint8Array} salt 
     * @param {Uint8Array} info 
     * @returns
     */
    static async deriveAESGCMEncryptionKey(baseKeyMaterial, salt, info){
        try {
            
            const key = await window.crypto.subtle.deriveKey(
                {
                  name: "HKDF",
                  salt: salt,
                  info: new Uint8Array(info),
                  hash: "SHA-256",
                },
                baseKeyMaterial,
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"],
            );
        
            return key;
        } catch (error) {
            console.log(error);
        }
    }
    
    /**
     * 
     * @param {CryptoKey} baseKeyMaterial 
     * @param {Uint8Array} salt 
     * @param {Uint8Array} info 
     * @returns
     */
    static async deriveMACKey(baseKeyMaterial, salt, info){
        try {
            const key = await window.crypto.subtle.deriveKey(
                {
                  name: "HKDF",
                  salt: salt,
                  info: new Uint8Array(info),
                  hash: "SHA-256",
                },
                baseKeyMaterial,
                { name: "HMAC", hash: 'SHA-256', length: 256 },
                true,
                ["sign", "verify"],
            );
        
            return key;
            
        } catch (error) {
            console.error(error);
        }
    }
       
    /**
     * 
     * @param {ArrayBuffer} encondedMessage 
     * @param {CryptoKey} key 
     * @param {ArrayBuffer} iv 
     * @param {ArrayBuffer} additionalData 
     * @returns 
     */
    static async AESEncrypt(encondedMessage, key, iv, additionalData){
        try {
            const ciphertext = await window.crypto.subtle.encrypt(
                { 
                    name: "AES-GCM", 
                    iv: iv,
                    additionalData: additionalData
                },
                key,
                encondedMessage
            );
            return ciphertext;
            
        } catch (error) {
            console.error(error);
        }
    }
    
    /**
     * 
     * @param {ArrayBuffer} encodedCiphertext 
     * @param {CryptoKey} key 
     * @param {ArrayBuffer} iv 
     * @param {ArrayBuffer} additionalData 
     * @returns 
     */
    static async AESDecrypt(encodedCiphertext, key, iv, additionalData){
        try {
            const plaintext = await window.crypto.subtle.decrypt(
                { 
                    name: "AES-GCM",
                    iv: iv,
                    additionalData: additionalData
                },
                key,
                encodedCiphertext
            );
            return plaintext;
            
        } catch (error) {
            console.error(error);
        }
    }
    
    /**
     * 
     * @param {ArrayBuffer} data 
     * @param {CryptoKey} key 
     * @returns
     */
    static async signHMAC(data, key){
        const signature = await window.crypto.subtle.sign(
            {
                name: 'HMAC',
                hash: 'SHA-256'
            },
            key,
            data
        );
    
        return signature;
    }

    /**
     * 
     * @param {CryptoKey} key 
     * @param {ArrayBuffer} signature 
     * @param {ArrayBuffer} data 
     * @returns
     */
    static async verifyHMAC(key, signature, data){
        const isValid = await window.crypto.subtle.verify(
            'HMAC',
            key,
            signature,
            data
        );
        
        return isValid;
    }
    
}

class ChatManager {
    constructor(own, other){
        this.own = own;
        this.other = other;
        this.status = 'creation';
        this.peerLatestIV = 0;
        this.lastIV = 0;
    }

    async init(){
        await this.loadECKeyPair();
        this.setLastIV(parseInt(localStorage.getItem(`LAST_IV_${this.other}`) || 0));
    }

    setLastIV(iv){
        this.lastIV = iv;
        localStorage.setItem(`LAST_IV_${this.other}`, `${iv}`);
    }

    getLastIV(){
        return this.lastIV;
    }

    /**
     * This function generates a pair of EC Keys; i.e. Private and Public key pair.
     * The derived keys will then be store in localstorage as ```PRIVATE_KEY``` and ```PUBLIC_KEY``` respectively.
     */
    async loadECKeyPair(){
        const publicKeyPem = localStorage.getItem('PUBLIC_KEY');
        const privateKeyPem = localStorage.getItem('PRIVATE_KEY');

        let publicKey, privateKey;

        if( !privateKeyPem || !publicKeyPem){
            const keyPair = await CryptoUtilities.generateECKeyPair();
            privateKey = keyPair.privateKey;
            publicKey = keyPair.publicKey;
            localStorage.setItem('PUBLIC_KEY', await CryptoUtilities.exportPublicKey(publicKey));
            localStorage.setItem('PRIVATE_KEY', await CryptoUtilities.exportPrivateKey(privateKey));
        }
        else{
            privateKey = await CryptoUtilities.importPrivateKey(privateKeyPem);
            publicKey = await CryptoUtilities.importPublicKey(publicKeyPem);
        }

        this.PUBLIC_KEY = publicKey;
        this.PRIVATE_KEY = privateKey;

        this.status = 'init';
    }

    /**
     * This function derives the shared secret and key given a public key of the party.
     * The public key should be in ```PEM``` format
     * @param {string} publicKeyPem 
     */
    async agreeECDH(publicKeyPem){
        const publicKey = await CryptoUtilities.importPublicKey(publicKeyPem);
        const [secret, sharedKey] = await CryptoUtilities.deriveSharedSecret(this.PRIVATE_KEY, publicKey);
        this.sharedKey = sharedKey;
        this.sharedSecret = secret;

        // Resetting parameters for new sets of Key Pairs
        this.setSalt(1);
        this.peerLatestIV = 0;

        // Tentative: For the purpose of key refreshing
        this.peerPublicKey = publicKey;

        localStorage.setItem(`PUBLIC_KEY_${this.other}`, publicKeyPem);
        localStorage.setItem(`SHARED_SECRET_${this.other}`, Utilities.bytesToBase64(secret));
        localStorage.setItem(`SALT_${this.other}`, `${Utilities.uint8ArrayToNum(this.getSalt())}`);

        await this.loadAESKeys();
        await this.loadMACKeys();
        
        this.status = 'ready';
    }

    getSalt(){
        return this.salt;
    }

    setSalt(salt){
        this.salt = Utilities.numToUint8Array(salt, 16);
    }

    incrementSalt(){
        const saltVal = Utilities.uint8ArrayToNum(this.salt);
        this.setSalt(saltVal+1);
    }

    async loadAESKeys(){
        if( !this.sharedKey ){
            console.error("Error: Can't load AES keys. Missing shared secret");
            return;
        }

        const saltBytes = this.getSalt();
        const encryptionKey = await CryptoUtilities.deriveAESGCMEncryptionKey(this.sharedKey, saltBytes, Utilities.encodeMessage(`CHAT_KEY_${this.own}_${this.other}`));
        const decryptionKey = await CryptoUtilities.deriveAESGCMEncryptionKey(this.sharedKey, saltBytes, Utilities.encodeMessage(`CHAT_KEY_${this.other}_${this.own}`));

        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
    }

    async loadMACKeys(){
        if( !this.sharedKey ){
            console.error("Error: Can't load MAC keys. Missing shared secret");
            return;
        }

        const saltBytes = this.getSalt(); // TODO: Change it according to specs. It has to be a counter
        const signatureKey = await CryptoUtilities.deriveMACKey(this.sharedKey, saltBytes, Utilities.encodeMessage(`MAC_KEY_${this.own}_${this.other}`));
        const verificationKey = await CryptoUtilities.deriveMACKey(this.sharedKey, saltBytes, Utilities.encodeMessage(`MAC_KEY_${this.other}_${this.own}`));

        this.signatureKey = signatureKey;
        this.verificationKey = verificationKey;
    }

    /**
     * 
     * @param {string} text 
     * @param {number} iv 
     * @returns
     */
    async encrypt(text, iv){
        const ivBytes = Utilities.numToUint8Array(iv, 12);
        const ciphertext = await CryptoUtilities.AESEncrypt(
            Utilities.encodeMessage(text),
            this.encryptionKey,
            ivBytes,
            Utilities.encodeMessage(`CHAT_MSG_${this.own}_${this.other}`)
        );
        
        const mac = await this.sign(ivBytes);
        const message =  {
            ciphertext: Utilities.bytesToBase64(ciphertext),
            iv,
            mac
        }

        this.setLastIV(iv);

        return message;
    }

    /**
     * 
     * @param {string} ciphertext 
     * @param {number} iv 
     * @param {string} mac 
     * @param {string | number} sender 
     * @returns
     */
    async decrypt(ciphertext, iv, mac, sender){
       const ciphertextBytes = Utilities.base64ToBytes(ciphertext);
       const ivBytes = Utilities.numToUint8Array(iv, 12);

       const plainText = await CryptoUtilities.AESDecrypt(
            ciphertextBytes,
            sender === this.own? this.encryptionKey : this.decryptionKey,
            ivBytes,
            sender === this.own?Utilities.encodeMessage(`CHAT_MSG_${this.own}_${this.other}`):Utilities.encodeMessage(`CHAT_MSG_${this.other}_${this.own}`)
       );

       const signature = Utilities.base64ToBytes(mac);
       const isValid = await this.verify(signature, ivBytes, sender);
       if( !isValid ){
        throw new Error('Invalid message signature');
       }
       
       if(sender === this.other){
            if(this.peerLatestIV < iv){
                this.peerLatestIV = iv;
            }
            else{
                console.error('Replay attack warning', this.peerLatestIV, iv);
                throw new Error('Warning: IV should be in increasing order. IV might have been reused')
            }
       }

       return Utilities.decodeMessage(plainText);
    }

    /**
     * 
     * @param {ArrayBuffer} signature 
     * @param {ArrayBuffer} data 
     * @param {string | number} sender 
     * @returns
     */
    async verify(signature, data, sender){
        const isValid = await CryptoUtilities.verifyHMAC(
            sender === this.own ? this.signatureKey : this.verificationKey,
            signature,
            data
        );

        return isValid;
    }

    /**
     * 
     * @param {ArrayBuffer} message 
     * @returns
     */
    async sign(message){
        const signature = await CryptoUtilities.signHMAC(
            message,
            this.signatureKey
        );
        return Utilities.bytesToBase64(signature);
    }

    async refreshKeys(){
        // Increment salt by one to derive new AES and MAC keys
        this.incrementSalt();

        localStorage.setItem(`SALT_${this.other}`, `${Utilities.uint8ArrayToNum(this.getSalt())}`);

        await this.loadAESKeys();
        await this.loadMACKeys();
        
    }

    async validateKeyChangeMessage(message, oldMacSignature, newMacSignature){
        const context = `MAC_KEY_${this.other}_${this.own}`;
        const newSalt = Utilities.numToUint8Array(Utilities.uint8ArrayToNum(this.getSalt()) + 1);
        const newMacKey = await CryptoUtilities.deriveMACKey(
            this.sharedKey, 
            newSalt,
            Utilities.encodeMessage(context)
        );
        const oldMacKey = this.verificationKey;
        const isValidOld = await CryptoUtilities.verifyHMAC(
            oldMacKey,
            Utilities.base64ToBytes(oldMacSignature),
            Utilities.encodeMessage(message)
        );

        const isValidNew = await CryptoUtilities.verifyHMAC(
            newMacKey,
            Utilities.base64ToBytes(newMacSignature),
            Utilities.encodeMessage(message)
        );

        return isValidNew && isValidOld;
    }

    async getKeyChangeSignatures(message){
        const context = `MAC_KEY_${this.own}_${this.other}`;
        const newSalt = Utilities.numToUint8Array(Utilities.uint8ArrayToNum(this.getSalt()) + 1);
        const newMacKey = await CryptoUtilities.deriveMACKey(
            this.sharedKey, 
            newSalt,
            Utilities.encodeMessage(context)
        );
        const oldMacKey = this.signatureKey;

        const oldSignature = await CryptoUtilities.signHMAC(
            Utilities.encodeMessage(message),
            oldMacKey
        );

        const newSignature = await CryptoUtilities.signHMAC(
            Utilities.encodeMessage(message),
            newMacKey
        );

        return [Utilities.bytesToBase64(oldSignature), Utilities.bytesToBase64(newSignature)];
    }
}

async function test(){
    // const pk = `-----BEGIN PUBLIC KEY-----
    // MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVsJXr9FI2LRDW3VYVAKa/AyyfzLhlw9dCYZ/8N4BQJRBL8mMlft7JyqtZDQABFPjm3bIr5+TTx68cnsbV0su9kcY/u12NIixMX8ioQ7rh4ZTkoSyYN+ERVrSrRzu9ifZ
    // -----END PUBLIC KEY-----`;

    // const pair = await CryptoUtilities.generateECKeyPair();
    // const publicKey = await CryptoUtilities.importPublicKey(pk);
    // const privateKey = pair.privateKey;
    // console.log({publicKey, privateKey});

    // const sharedKey = await CryptoUtilities.deriveSharedSecret(privateKey, publicKey);
    // console.log({sharedKey: sharedKey});

    // const exported = await CryptoUtilities.exportSecretKey(sharedKey);

    // const context = 'CHAT_KEY_USER1to2';
    // const salt = window.crypto.getRandomValues(new Uint8Array(16));

    
    // const encryptionKey = await CryptoUtilities.deriveAESGCMEncryptionKey(sharedKey, salt, Utilities.encodeMessage(context));
    // console.log({encryptionKey});
    
    // const message = "hiiii";
    // const iv = Utilities.numToUint8Array(1);
    // const ciphertext = await CryptoUtilities.AESEncrypt(Utilities.encodeMessage(message), encryptionKey, iv, Utilities.encodeMessage(context));
    // const ct_utf8 = Utilities.bytesToBase64(ciphertext);
    // console.log({ciphertext: ciphertext, ct_utf8});
    // console.log({ct: Utilities.base64ToBytes(ct_utf8)});
    // // console.log('ciphertext', ct_utf8);

    // const plaintext = await CryptoUtilities.AESDecrypt(Utilities.base64ToBytes(ct_utf8), encryptionKey, iv, Utilities.encodeMessage(context));
    // console.log('Plain text:', Utilities.decodeMessage(plaintext));

    // const MACKey = await CryptoUtilities.deriveMACKey(sharedKey, salt, Utilities.encodeMessage(context));
    // const signature = await CryptoUtilities.signHMAC(Utilities.encodeMessage('message'), MACKey);
    // const base64Sign = Utilities.bytesToBase64(signature);
    // console.log({base64Sign});
    
    // const isValid = await CryptoUtilities.verifyHMAC(
    //     MACKey,
    //     Utilities.base64ToBytes(base64Sign),
    //     Utilities.encodeMessage('message')
    // );
    // // console.log({isValid});

    // let manager = new ChatManager('alice', 'Bob');
    // await manager.init();
    // await manager.agreeECDH(pk);

    // console.log(manager);

    // const message = await manager.encrypt('hello', 1);
    // console.log(message);


    // // const valid = await CryptoUtilities.verifyHMAC(manager.signatureKey, Utilities.base64ToBytes(message.mac), Utilities.numToUint8Array(message.iv, 12));
    // const valid = await manager.verify(Utilities.base64ToBytes(message.mac), Utilities.numToUint8Array(message.iv, 12), 'alice');
    
    // console.log({valid});
}

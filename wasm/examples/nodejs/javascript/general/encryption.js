const cryptix = require('../../../../nodejs/cryptix');

cryptix.initConsolePanicHook();

(async () => {

    let encrypted = cryptix.encryptXChaCha20Poly1305("my message", "my_password");
    console.log("encrypted:", encrypted);
    let decrypted = cryptix.decryptXChaCha20Poly1305(encrypted, "my_password");
    console.log("decrypted:", decrypted);

})();

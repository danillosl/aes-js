function encrypt(){
    var mensagem = document.getElementById("mensagem").value;
    var password = document.getElementById("password").value;

    var retorno = encryption(mensagem, password);
    
    document.getElementById("salt").value = retorno.salt;
    document.getElementById("iv").value = retorno.iv;
    document.getElementById("mensagem_criptografada").value = retorno.cipher_text;
    
};

function decrypt(){

    var password = document.getElementById("password").value;
    var salt = document.getElementById("salt").value;
    var iv = document.getElementById("iv").value;
    var mensagem_criptografada = document.getElementById("mensagem_criptografada").value;


    var retorno = decryption(mensagem_criptografada, password, salt, iv);
    
    document.getElementById("mensagem_descriptografada").value = retorno;
    
};

function encryption(message, password) {
        var md = forge.md.sha1.create();
        var salt = forge.random.getBytesSync(32);
        var key = forge.pkcs5.pbkdf2(password, salt, 65536, 32, md);
        var iv = forge.random.getBytesSync(16);
        var cipher = forge.cipher.createCipher('AES-CBC', key);
        cipher.start({iv: iv});
        cipher.update(forge.util.createBuffer(message));
        cipher.finish();
        var cipherText = forge.util.encode64(cipher.output.getBytes());
        return {cipher_text: cipherText, salt: forge.util.encode64(salt), iv: forge.util.encode64(iv)};
       
    }
 
    /*
     * Decrypt cipher text using a password or passphrase and a corresponding salt and iv
     *
     * @param    string (Base64) cipherText
     * @param    string password
     * @param    string (Base64) salt
     * @param    string (Base64) iv
     * @return   string
     */
function decryption(cipherText, password, salt, iv) {
        var md = forge.md.sha1.create();
        var key = forge.pkcs5.pbkdf2(password, forge.util.decode64(salt), 65536, 32, md);
        var decipher = forge.cipher.createDecipher('AES-CBC', key);
        decipher.start({iv: forge.util.decode64(iv)});
        decipher.update(forge.util.createBuffer(forge.util.decode64(cipherText)));
        decipher.finish();
        return decipher.output.toString();
    }
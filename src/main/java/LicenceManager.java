import spark.Request;
import spark.Response;
import spark.Route;

import javax.crypto.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static spark.Spark.*;

public class LicenceManager {
    private final String ENCRYPT = "encrypted";

    private Cipher cipher;

    private PrivateKey privKey;
    private PublicKey pubKey;

    private LicenceManager() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IOException {
        cipher = Cipher.getInstance("RSA");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get("private.key")));
        privKey = kf.generatePrivate(keySpecPKCS8);
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Files.readAllBytes(Paths.get("public.key")));
        pubKey = kf.generatePublic(keySpecX509);
    }

    private String encrypt(String plainText, PublicKey publicKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        System.out.println("Encrypted: " + plainText.getBytes(StandardCharsets.UTF_8).length);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    private String decrypt(String cipherText, PrivateKey privateKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(bytes));
    }

    private String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    private boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    private String hash(String plaintext) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashInBytes = md.digest(plaintext.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(hashInBytes);
    }

    private String licence(String encryptedData, PrivateKey privateKey) throws Exception {
        String decryptedData = decrypt(encryptedData, privateKey);
        String hash = hash(decryptedData);
        System.out.println("Hash: " + hash);
        System.out.println("Signiture: " + sign(hash, privateKey));
        return sign(hash, privateKey);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException {
        LicenceManager licenceManager = new LicenceManager();

//         Server
        port(5000);

        post("bbm465/assignment2", new Route() {
            @Override
            public String handle(Request request, Response response) throws Exception {
               String encrypted = request.queryParams(licenceManager.ENCRYPT);
               System.out.println("Request Body: " + encrypted);
               return licenceManager.licence(encrypted, licenceManager.privKey);
            }
        });
    }
}

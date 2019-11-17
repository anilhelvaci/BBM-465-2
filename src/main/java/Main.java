import okhttp3.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {
    private final String ENCRYPT = "encrypted";
    private final String URL = "http://127.0.0.1:5000/bbm465/assignment2";

    private final OkHttpClient httpClient = new OkHttpClient();
    private PublicKey pubKey;
    private Cipher cipher;

    private Main() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException {
        cipher = Cipher.getInstance("RSA");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Files.readAllBytes(Paths.get("./public.key")));
        pubKey = kf.generatePublic(keySpecX509);
    }

    private String encrypt(String plainText, PublicKey publicKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        System.out.println("Encrypted: " + plainText.getBytes(StandardCharsets.UTF_8).length);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
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

    private Response sendPost(String cipherText) throws Exception {
        // form parameters
        System.out.println("Cipher Text: " + cipherText);
        RequestBody formBody = new FormBody.Builder()
                .add(ENCRYPT, cipherText)
                .build();

        Request request = new Request.Builder()
                .url(URL)
                .post(formBody)
                .build();

        return  httpClient.newCall(request).execute();
    }

    public static void main(String[] args) throws Exception {
        String plainText = "ANIL-HELVACI$0H6U-23BJ-YR84$0C-54-15-5B-0A-FE$-633475686$Standard";
        Main main = new Main();

        String encryptedText = main.encrypt(plainText, main.pubKey);
        Response response = main.sendPost(encryptedText);

        if (response.isSuccessful() && response.body() != null) {
            String signiture = response.body().string();
            System.out.println("Response: " + signiture);
            String hash = main.hash(plainText);
            boolean verify = main.verify(hash, signiture, main.pubKey);
            System.out.println("Encrypted Text: " + encryptedText);
            System.out.println("Hash: " + hash);
            System.out.println("Verified: " + verify);
        } else {
            System.out.println("Server failed to send the signiture!!!");
            System.out.println("Response Success: " + response.isSuccessful());
            System.out.println("Response Body: " + response.body().string());
        }
    }
}

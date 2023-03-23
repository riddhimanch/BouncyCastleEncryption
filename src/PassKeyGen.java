import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class PassKeyGen {
    public static void main(String[] args) {
        // Generate a secret key using AES algorithm
        SecretKey secretKey = generateSecretKey();

        // Write the secret key to a file
        String fileName = "secretkey.txt";
        writeSecretKeyToFile(secretKey, fileName);

        System.out.println("Secret key written to " + fileName);
    }

    public static SecretKey generateSecretKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // key size
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void writeSecretKeyToFile(Key key, String fileName) {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(key.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

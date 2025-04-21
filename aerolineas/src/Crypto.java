import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class Crypto {

    // =================== DERIVACIÓN DE LLAVES ===================
    public static byte[][] derivarClaves(byte[] sharedSecret) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);
        byte[] aesKey = Arrays.copyOfRange(digest, 0, 32);
        byte[] hmacKey = Arrays.copyOfRange(digest, 32, 64);
        return new byte[][] { aesKey, hmacKey };
    }

    // =================== CIFRADO Y DESCIFRADO ===================
    public static byte[] cifrarAES(byte[] datos, byte[] key, byte[] iv) throws Exception {
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec skey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aes.init(Cipher.ENCRYPT_MODE, skey, ivSpec);
        return aes.doFinal(datos);
    }

    public static byte[] descifrarAES(byte[] datos, byte[] key, byte[] iv) throws Exception {
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec skey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aes.init(Cipher.DECRYPT_MODE, skey, ivSpec);
        return aes.doFinal(datos);
    }

    // =================== HMAC SHA256 ===================
    public static byte[] generarHMAC(byte[] datos, byte[] claveHmac) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec hmacKey = new SecretKeySpec(claveHmac, "HmacSHA256");
        hmac.init(hmacKey);
        return hmac.doFinal(datos);
    }

    public static boolean verificarHMAC(byte[] datos, byte[] claveHmac, byte[] hmacRecibido) throws Exception {
        byte[] esperado = generarHMAC(datos, claveHmac);
        return Arrays.equals(esperado, hmacRecibido);
    }

    // =================== FIRMAS ===================
    public static byte[] firmar(byte[] datos, PrivateKey llavePrivada) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(llavePrivada);
        signature.update(datos);
        return signature.sign();
    }

    public static boolean verificarFirma(byte[] datos, byte[] firma, PublicKey llavePublica) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(llavePublica);
        signature.update(datos);
        return signature.verify(firma);
    }

    // =================== LLAVES ===================
    public static PrivateKey cargarLlavePrivada(String ruta) throws Exception {
        String keyPEM = new String(Files.readAllBytes(Paths.get(ruta)))
                .replaceAll("-----\\w+ PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public static PublicKey cargarLlavePublica(String ruta) throws Exception {
        String keyPEM = new String(Files.readAllBytes(Paths.get(ruta)))
                .replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}

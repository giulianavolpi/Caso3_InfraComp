import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class Cliente {

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 12345)) {

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // 1. Recibir parámetros de Diffie-Hellman
            BigInteger p = (BigInteger) in.readObject();
            BigInteger g = (BigInteger) in.readObject();
            byte[] serverPubBytes = (byte[]) in.readObject();

            DHParameterSpec dhSpec = new DHParameterSpec(p, g);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);
            KeyPair keyPair = kpg.generateKeyPair();

            // Enviar clave pública al servidor
            out.writeObject(keyPair.getPublic().getEncoded());

            // Generar llave compartida
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(serverPubBytes);
            PublicKey serverPublicKey = kf.generatePublic(x509Spec);

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(serverPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // Derivar llaves
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret);
            byte[] aesKey = Arrays.copyOfRange(digest, 0, 32);
            byte[] hmacKey = Arrays.copyOfRange(digest, 32, 64);

            // 2. Recibir tabla cifrada, firma, IV, HMAC
            byte[] iv = (byte[]) in.readObject();
            byte[] firmaBytes = (byte[]) in.readObject();
            byte[] tablaCifrada = (byte[]) in.readObject();
            byte[] hmacTabla = (byte[]) in.readObject();

            // Verificar HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKey hmacKeyObj = new SecretKeySpec(hmacKey, "HmacSHA256");
            hmac.init(hmacKeyObj);
            byte[] hmacEsperado = hmac.doFinal(tablaCifrada);

            if (!Arrays.equals(hmacTabla, hmacEsperado)) {
                System.out.println("Error en la consulta (HMAC inválido)");
                return;
            }

            // Descifrar tabla
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKey aesKeyObj = new SecretKeySpec(aesKey, "AES");
            aes.init(Cipher.DECRYPT_MODE, aesKeyObj, new IvParameterSpec(iv));
            byte[] tablaBytes = aes.doFinal(tablaCifrada);

            // Verificar firma digital
            PublicKey publicKey = cargarLlavePublica("keys/public_key.pem");
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(tablaBytes);

            if (!signature.verify(firmaBytes)) {
                System.out.println("Error en la consulta (firma inválida)");
                return;
            }

            // Mostrar tabla de servicios
            ByteArrayInputStream bis = new ByteArrayInputStream(tablaBytes);
            ObjectInputStream ois = new ObjectInputStream(bis);
            @SuppressWarnings("unchecked")
            Map<Integer, Servicio> servicios = (Map<Integer, Servicio>) ois.readObject();
            System.out.println("Servicios disponibles:");
            for (Servicio s : servicios.values()) {
                System.out.println("[" + s.getId() + "] " + s.getNombre());
            }

            // Selección aleatoria del servicio
            List<Integer> ids = new ArrayList<>(servicios.keySet());
            int seleccionado = ids.get(new Random().nextInt(ids.size()));
            System.out.println("Solicitando servicio con ID: " + seleccionado);

            // Enviar ID + HMAC
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);
            dos.writeInt(seleccionado);
            byte[] datos = bos.toByteArray();
            byte[] hmacConsulta = hmac.doFinal(datos);

            out.writeInt(seleccionado);
            out.writeObject(hmacConsulta);

            // Leer respuesta
            Object respuestaObj = in.readObject();
            if (respuestaObj instanceof String) {
                System.out.println((String) respuestaObj); // Error
                return;
            }

            byte[] respuesta = (byte[]) respuestaObj;
            byte[] hmacRespuesta = (byte[]) in.readObject();

            byte[] hmacEsperada = hmac.doFinal(respuesta);
            if (!Arrays.equals(hmacRespuesta, hmacEsperada)) {
                System.out.println("Error en la consulta (respuesta inválida)");
                return;
            }

            // Mostrar IP y puerto
            ObjectInputStream ois2 = new ObjectInputStream(new ByteArrayInputStream(respuesta));
            String ip = (String) ois2.readObject();
            int puerto = ois2.readInt();

            System.out.println("Dirección del servicio: " + ip + ":" + puerto);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PublicKey cargarLlavePublica(String ruta) throws Exception {
        File file = new File(ruta);
        FileInputStream fis = new FileInputStream(file);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024];
        int nRead;
        while ((nRead = fis.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        buffer.flush();
        byte[] keyBytes = buffer.toByteArray();
        fis.close();

        String keyPEM = new String(keyBytes).replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}

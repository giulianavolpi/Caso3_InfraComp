import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import java.util.*;

public class ClienteIterativo {

    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 12345)) {

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // ==============================
            // NUEVA SECCIÓN: Challenge-Response (Reto-Respuesta)
            // ==============================
            System.out.println("Enviando saludo al servidor...");
    
            out.writeObject("ITERATIVO"); 
            out.writeObject("HELLO");

            System.out.println("Esperando reto cifrado del servidor...");
            byte[] retoCifrado = (byte[]) in.readObject();

            // Paso 5: Descifrar reto con la llave pública del servidor
            PublicKey publicKey = Crypto.cargarLlavePublica("keys/public_key.pem");
            Cipher cipherRSA = Cipher.getInstance("RSA");
            cipherRSA.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] retoBytes = cipherRSA.doFinal(retoCifrado);
            BigInteger retoBigInt = new BigInteger(retoBytes); //paso de long a bigint
            System.out.println("Reto recibido y descifrado: " + retoBigInt);

            // Paso 5b: Enviar el reto descifrado al servidor (como BigInteger)
            out.writeObject(retoBigInt); // se cambio a bigInt con long no servia
            System.out.println("Reto enviado al servidor para verificación.");

            // Paso 6: Esperar confirmación del servidor
            String confirmacion = (String) in.readObject();
            if (!"OK".equals(confirmacion)) {
                System.out.println("Error en el protocolo de inicio. Terminando...");
                return;
            }
            System.out.println("Protocolo de inicio completado con éxito. Continuando con Diffie-Hellman...");

            // ==============================
            // 1. Recibir parámetros Diffie-Hellman
            // ==============================
            BigInteger p = (BigInteger) in.readObject();
            BigInteger g = (BigInteger) in.readObject();
            byte[] serverPubBytes = (byte[]) in.readObject();

            DHParameterSpec dhSpec = new DHParameterSpec(p, g);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);
            KeyPair keyPair = kpg.generateKeyPair();

            out.writeObject(keyPair.getPublic().getEncoded());

            PublicKey serverPubKey = KeyFactory.getInstance("DH")
                    .generatePublic(new X509EncodedKeySpec(serverPubBytes));

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(serverPubKey, true);
            byte[] sharedSecret = ka.generateSecret();

            byte[][] claves = Crypto.derivarClaves(sharedSecret);
            byte[] aesKey = claves[0];
            byte[] hmacKey = claves[1];

            // ==============================
            // 2. Recibir y validar la tabla de servicios
            // ==============================
            byte[] iv = (byte[]) in.readObject();
            byte[] firmaBytes = (byte[]) in.readObject();
            byte[] tablaCifrada = (byte[]) in.readObject();
            byte[] hmacTabla = (byte[]) in.readObject();

            if (!Crypto.verificarHMAC(tablaCifrada, hmacKey, hmacTabla)) {
                System.out.println("HMAC inválido de la tabla");
                return;
            }

            // Medición de tiempo de descifrado de la tabla
            long inicioDescifrado = System.nanoTime();
            byte[] tablaBytes = Crypto.descifrarAES(tablaCifrada, aesKey, iv);
            long finDescifrado = System.nanoTime();
            long tiempoDescifradoMs = (finDescifrado - inicioDescifrado) / 1_000_000;
            System.out.println("[MEDICIÓN] Descifrado AES de la tabla: " + tiempoDescifradoMs + " ms");

            // Verificación de firma (medida de tiempo)
            long inicioVerifFirma = System.nanoTime();
            boolean firmaOk = Crypto.verificarFirma(tablaBytes, firmaBytes, publicKey);
            long finVerifFirma = System.nanoTime();
            long tiempoVerifFirmaMs = (finVerifFirma - inicioVerifFirma) / 1_000_000;
            System.out.println("[MEDICIÓN] Verificación de firma RSA: " + tiempoVerifFirmaMs + " ms");

            if (!firmaOk) {
                System.out.println("Firma digital inválida");
                return;
            }

            ObjectInputStream tablaIn = new ObjectInputStream(new ByteArrayInputStream(tablaBytes));
            @SuppressWarnings("unchecked")
            Map<Integer, Servicio> servicios = (Map<Integer, Servicio>) tablaIn.readObject();

            List<Integer> ids = new ArrayList<>(servicios.keySet());
            System.out.println("Ejecutando 32 consultas iterativas...");

            for (int i = 1; i <= 32; i++) {
                int id = ids.get(new Random().nextInt(ids.size()));

                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                new DataOutputStream(bos).writeInt(id);
                byte[] datos = bos.toByteArray();
                byte[] hmacConsulta = Crypto.generarHMAC(datos, hmacKey);

                out.writeInt(id);
                out.writeObject(hmacConsulta);

                Object respuestaObj = in.readObject();
                if (respuestaObj instanceof String) {
                    System.out.println("[" + i + "] Error recibido: " + respuestaObj);
                    continue;
                }

                byte[] respuesta = (byte[]) respuestaObj;
                byte[] hmacRespuesta = (byte[]) in.readObject();

                // Verificación HMAC de la respuesta (medida de tiempo)
                long inicioVerifHMACResp = System.nanoTime();
                boolean hmacRespOk = Crypto.verificarHMAC(respuesta, hmacKey, hmacRespuesta);
                long finVerifHMACResp = System.nanoTime();
                long tiempoVerifHMACRespMs = (finVerifHMACResp - inicioVerifHMACResp) / 1_000_000;
                System.out.println("[MEDICIÓN] Verificación HMAC de la respuesta: " + tiempoVerifHMACRespMs + " ms");

                if (!hmacRespOk) {
                    System.out.println("[" + i + "] HMAC inválido en respuesta");
                    continue;
                }

                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(respuesta));
                String ip = (String) ois.readObject();
                int puerto = ois.readInt();

                System.out.println("[" + i + "] Servicio ID: " + id + " -> " + ip + ":" + puerto);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

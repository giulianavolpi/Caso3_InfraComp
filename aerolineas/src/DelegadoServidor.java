import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.KeyAgreement;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class DelegadoServidor implements Runnable {
    private final Socket socket;
    private final Map<Integer, Servicio> servicios;

    public DelegadoServidor(Socket socket, Map<Integer, Servicio> servicios) {
        this.socket = socket;
        this.servicios = servicios;
    }

    @Override
    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // 1. Generar parámetros DH y claves
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            DHParameterSpec dhSpec = paramGen.generateParameters().getParameterSpec(DHParameterSpec.class);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);
            KeyPair keyPair = kpg.generateKeyPair();

            out.writeObject(dhSpec.getP());
            out.writeObject(dhSpec.getG());
            out.writeObject(keyPair.getPublic().getEncoded());

            byte[] clientPubBytes = (byte[]) in.readObject();
            PublicKey clientPublic = KeyFactory.getInstance("DH")
                    .generatePublic(new X509EncodedKeySpec(clientPubBytes));

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(clientPublic, true);
            byte[] sharedSecret = ka.generateSecret();

            byte[][] claves = Crypto.derivarClaves(sharedSecret);
            byte[] aesKey = claves[0];
            byte[] hmacKey = claves[1];

            // 2. Serializar la tabla de servicios
            ByteArrayOutputStream tablaOut = new ByteArrayOutputStream();
            new ObjectOutputStream(tablaOut).writeObject(servicios);
            byte[] tablaBytes = tablaOut.toByteArray();

            // 3. Firmar tabla
            long inicioFirma = System.nanoTime();
            byte[] firma = Crypto.firmar(tablaBytes, Crypto.cargarLlavePrivada("keys/private_key.pem"));
            long finFirma = System.nanoTime();
            long tiempoFirmaMs = (finFirma - inicioFirma) / 1_000_000;
            System.out.println("[MEDICIÓN] Firma digital: " + tiempoFirmaMs + " ms");

            // 4. Cifrado con AES-CBC
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            long inicioCifrado = System.nanoTime();
            byte[] tablaCifrada = Crypto.cifrarAES(tablaBytes, aesKey, iv);
            long finCifrado = System.nanoTime();
            long tiempoCifradoMs = (finCifrado - inicioCifrado) / 1_000_000;
            System.out.println("[MEDICIÓN] Cifrado AES: " + tiempoCifradoMs + " ms");

            // 5. HMAC de la tabla cifrada
            byte[] hmac = Crypto.generarHMAC(tablaCifrada, hmacKey);

            // 6. Enviar todo al cliente
            out.writeObject(iv);
            out.writeObject(firma);
            out.writeObject(tablaCifrada);
            out.writeObject(hmac);

            // 7. Recibir ID de servicio + HMAC del cliente
            int id = in.readInt();
            byte[] hmacRecibido = (byte[]) in.readObject();

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            new DataOutputStream(bos).writeInt(id);
            byte[] datos = bos.toByteArray();

            long inicioVerificacion = System.nanoTime();
            boolean hmacOk = Crypto.verificarHMAC(datos, hmacKey, hmacRecibido);
            long finVerificacion = System.nanoTime();
            long tiempoVerificacionMs = (finVerificacion - inicioVerificacion) / 1_000_000;
            System.out.println("[MEDICIÓN] Verificación HMAC de consulta: " + tiempoVerificacionMs + " ms");

            if (!hmacOk) {
                out.writeObject("Error en la consulta");
                return;
            }

            // 8. Buscar servicio solicitado
            Servicio s = servicios.get(id);
            String ip = (s != null) ? s.getIp() : "-1";
            int puerto = (s != null) ? s.getPuerto() : -1;

            // 9. Enviar respuesta con HMAC
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(response);
            oos.writeObject(ip);
            oos.writeInt(puerto);
            byte[] respuestaBytes = response.toByteArray();

            byte[] hmacRespuesta = Crypto.generarHMAC(respuestaBytes, hmacKey);
            out.writeObject(respuestaBytes);
            out.writeObject(hmacRespuesta);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

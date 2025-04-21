import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
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
        try {
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // 1. Generación de parámetros Diffie-Hellman
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);
            KeyPair keyPair = kpg.generateKeyPair();

            // Enviar parámetros y clave pública al cliente
            out.writeObject(dhSpec.getP());
            out.writeObject(dhSpec.getG());
            out.writeObject(keyPair.getPublic().getEncoded());

            // Recibir clave pública del cliente
            byte[] clientPubBytes = (byte[]) in.readObject();
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clientPubBytes);
            PublicKey clientPublicKey = kf.generatePublic(x509Spec);

            // Generar llave compartida
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(clientPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // Derivar claves (AES y HMAC)
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret);
            byte[] aesKey = Arrays.copyOfRange(digest, 0, 32);
            byte[] hmacKey = Arrays.copyOfRange(digest, 32, 64);

            // 2. Serializar y cifrar la tabla de servicios
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream tempOut = new ObjectOutputStream(bos);
            tempOut.writeObject(servicios);
            byte[] tablaBytes = bos.toByteArray();

            // Firmar con SHA256withRSA
            PrivateKey privateKey = cargarLlavePrivada("keys/private_key.pem");
            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initSign(privateKey);
            firma.update(tablaBytes);
            byte[] firmaBytes = firma.sign();

            // Cifrado AES-CBC
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKey aesSecretKey = new SecretKeySpec(aesKey, "AES");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aes.init(Cipher.ENCRYPT_MODE, aesSecretKey, ivSpec);
            byte[] tablaCifrada = aes.doFinal(tablaBytes);

            // HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKey hmacSecretKey = new SecretKeySpec(hmacKey, "HmacSHA256");
            hmac.init(hmacSecretKey);
            byte[] hmacTabla = hmac.doFinal(tablaCifrada);

            // Enviar: IV, firma, tabla cifrada, HMAC
            out.writeObject(iv);
            out.writeObject(firmaBytes);
            out.writeObject(tablaCifrada);
            out.writeObject(hmacTabla);

            // 3. Recibir solicitud del cliente (servicio id)
            int servicioSolicitado = in.readInt();
            byte[] hmacRecibido = (byte[]) in.readObject();

            // Verificar HMAC del número recibido
            ByteArrayOutputStream tmp = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(tmp);
            dos.writeInt(servicioSolicitado);
            byte[] data = tmp.toByteArray();
            byte[] hmacEsperado = hmac.doFinal(data);

            if (!Arrays.equals(hmacRecibido, hmacEsperado)) {
                out.writeObject("Error en la consulta");
                socket.close();
                return;
            }

            // Buscar servicio
            Servicio s = servicios.get(servicioSolicitado);
            int puerto = (s != null) ? s.getPuerto() : -1;
            String ip = (s != null) ? s.getIp() : "-1";

            // Enviar respuesta + HMAC
            ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
            ObjectOutputStream oos2 = new ObjectOutputStream(bos2);
            oos2.writeObject(ip);
            oos2.writeInt(puerto);
            byte[] respuestaBytes = bos2.toByteArray();
            byte[] hmacRespuesta = hmac.doFinal(respuestaBytes);

            out.writeObject(respuestaBytes);
            out.writeObject(hmacRespuesta);

            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private PrivateKey cargarLlavePrivada(String ruta) throws Exception {
        File file = new File(ruta);
        FileInputStream fis = new FileInputStream(file);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] temp = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(temp)) != -1) {
            buffer.write(temp, 0, bytesRead);
        }
        byte[] keyBytes = buffer.toByteArray();
        fis.close();

        String keyPEM = new String(keyBytes).replaceAll("-----\\w+ PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
}

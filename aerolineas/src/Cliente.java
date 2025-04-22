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

            // 1. DH: Recibir parámetros y clave pública del servidor
            BigInteger p = (BigInteger) in.readObject();
            BigInteger g = (BigInteger) in.readObject();
            byte[] serverPubBytes = (byte[]) in.readObject();

            DHParameterSpec dhSpec = new DHParameterSpec(p, g);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);
            KeyPair clientKeyPair = kpg.generateKeyPair();

            out.writeObject(clientKeyPair.getPublic().getEncoded());

            // DH: Llave compartida
            KeyFactory kf = KeyFactory.getInstance("DH");
            PublicKey serverPubKey = kf.generatePublic(new X509EncodedKeySpec(serverPubBytes));

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(clientKeyPair.getPrivate());
            ka.doPhase(serverPubKey, true);
            byte[] sharedSecret = ka.generateSecret();

            byte[][] claves = Crypto.derivarClaves(sharedSecret);
            byte[] aesKey = claves[0];
            byte[] hmacKey = claves[1];

            // 2. Recibir tabla cifrada + IV + firma + HMAC
            byte[] iv = (byte[]) in.readObject();
            byte[] firma = (byte[]) in.readObject();
            byte[] tablaCifrada = (byte[]) in.readObject();
            byte[] hmacRecibido = (byte[]) in.readObject();

            if (!Crypto.verificarHMAC(tablaCifrada, hmacKey, hmacRecibido)) {
                System.out.println("Error en la consulta (HMAC inválido)");
                return;
            }

            byte[] tablaBytes = Crypto.descifrarAES(tablaCifrada, aesKey, iv);

            PublicKey pubKey = Crypto.cargarLlavePublica("keys/public_key.pem");
            if (!Crypto.verificarFirma(tablaBytes, firma, pubKey)) {
                System.out.println("Error en la consulta (firma inválida)");
                return;
            }

            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(tablaBytes));
            @SuppressWarnings("unchecked")
            Map<Integer, Servicio> servicios = (Map<Integer, Servicio>) ois.readObject();
            System.out.println("Servicios disponibles:");
            for (Servicio s : servicios.values()) {
                System.out.println("[" + s.getId() + "] " + s.getNombre());
            }

            // Selección aleatoria
            List<Integer> ids = new ArrayList<>(servicios.keySet());
            int id = ids.get(new Random().nextInt(ids.size()));
            System.out.println("Solicitando servicio: " + id);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            new DataOutputStream(bos).writeInt(id);
            byte[] datos = bos.toByteArray();
            byte[] hmac = Crypto.generarHMAC(datos, hmacKey);

            out.writeInt(id);
            out.writeObject(hmac);

            // 3. Recibir respuesta
            Object obj = in.readObject();
            if (obj instanceof String) {
                System.out.println("Mensaje de error recibido del servidor: " + obj);
                return;
            }
            if (obj instanceof String) {
                System.out.println((String) obj); // Error
                return;
            }

            byte[] respuesta = (byte[]) obj;
            byte[] hmacResp = (byte[]) in.readObject();

            if (!Crypto.verificarHMAC(respuesta, hmacKey, hmacResp)) {
                System.out.println("Error en la consulta (respuesta inválida)");
                return;
            }

            ObjectInputStream ois2 = new ObjectInputStream(new ByteArrayInputStream(respuesta));
            String ip = (String) ois2.readObject();
            int puerto = ois2.readInt();
            System.out.println("Dirección del servicio: " + ip + ":" + puerto);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

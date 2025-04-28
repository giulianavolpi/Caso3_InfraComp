import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.Cipher;
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
    private final boolean usarRSA;//se usa o no RSA

    public DelegadoServidor(Socket socket, Map<Integer, Servicio> servicios, boolean usarRSA) { 
        this.socket = socket;
        this.servicios = servicios;
        this.usarRSA = usarRSA; 
    }

    @Override
    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            System.out.println("Cliente conectado. Iniciando protocolo...");

            // ==============================
            // NUEVA SECCIÓN: Challenge-Response (Reto-Respuesta) verifica si esta hablando con el servidor que es
            // ==============================
            System.out.println("Esperando tipo de cliente...");
            String tipoCliente = (String) in.readObject();
            String saludo = (String) in.readObject();
            System.out.println("Tipo de cliente: " + tipoCliente);
            System.out.println("Saludo recibido: " + saludo);

            if (!"HELLO".equals(saludo)) {
                System.out.println("Saludo inválido. Terminando conexión.");
                socket.close();
                return;
            }

            // Paso 2: Generar reto aleatorio (ahora BigInteger)
            SecureRandom random = new SecureRandom();
            BigInteger reto = new BigInteger(64, random);  // 64 bits
            System.out.println("Generando reto (BigInteger): " + reto);

            // Paso 3: Cifrar el reto con llave privada del servidor
            PrivateKey privateKey = Crypto.cargarLlavePrivada("keys/private_key.pem");
            Cipher cipherRSA = Cipher.getInstance("RSA");
            cipherRSA.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] retoCifrado = cipherRSA.doFinal(reto.toByteArray());

            // Paso 4: Enviar el reto cifrado al cliente
            out.writeObject(retoCifrado);
            System.out.println("Reto enviado al cliente.");

            // Paso 5: Esperar la respuesta del cliente (desencriptado del reto)
            BigInteger respuesta = (BigInteger) in.readObject();

            System.out.println("Reto original (servidor): " + reto);
            System.out.println("Respuesta recibida del cliente: " + respuesta);

            // Paso 6: Verificar
            if (!respuesta.equals(reto)) {
                System.out.println("Reto incorrecto. Terminando conexión.");
                out.writeObject("ERROR");
                socket.close();
                return;
            }
            System.out.println("Reto verificado correctamente. Continuando con Diffie-Hellman...");
            out.writeObject("OK");

            // ==============================
            // Continuar como estaba: Faltaba asegurarse de que realmente esta hablando con el servidor que es
            // ==============================

            // 1. Generar parámetros DH y claves
            System.out.println("Generando parámetros DH...");
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            DHParameterSpec dhSpec = paramGen.generateParameters().getParameterSpec(DHParameterSpec.class);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhSpec);
            KeyPair keyPair = kpg.generateKeyPair();

            System.out.println("Enviando parámetros DH y clave pública...");
            out.writeObject(dhSpec.getP());
            out.writeObject(dhSpec.getG());
            out.writeObject(keyPair.getPublic().getEncoded());

            System.out.println("Esperando clave pública del cliente...");
            byte[] clientPubBytes = (byte[]) in.readObject();

            System.out.println("Recibida clave pública del cliente. Generando llave compartida...");
            PublicKey clientPublic = KeyFactory.getInstance("DH")
                    .generatePublic(new X509EncodedKeySpec(clientPubBytes));

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(clientPublic, true);
            byte[] sharedSecret = ka.generateSecret();

            byte[][] claves = Crypto.derivarClaves(sharedSecret);
            byte[] aesKey = claves[0];
            byte[] hmacKey = claves[1];
            System.out.println("Claves derivadas correctamente.");

            // 2. Serializar la tabla de servicios
            System.out.println("Serializando tabla de servicios...");
            ByteArrayOutputStream tablaOut = new ByteArrayOutputStream();
            new ObjectOutputStream(tablaOut).writeObject(servicios);
            byte[] tablaBytes = tablaOut.toByteArray();

            // 3. Firmar tabla
            System.out.println("Firmando la tabla...");
            long inicioFirma = System.nanoTime();
            byte[] firma = Crypto.firmar(tablaBytes, Crypto.cargarLlavePrivada("keys/private_key.pem"));
            long finFirma = System.nanoTime();
            long tiempoFirmaMs = (finFirma - inicioFirma) / 1_000_000;
            System.out.println("[MEDICIÓN] Firma digital: " + tiempoFirmaMs + " ms");

            // 4. Cifrado con AES-CBC
            System.out.println("Cifrando la tabla con AES...");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            long inicioCifrado = System.nanoTime();
            byte[] tablaCifrada = Crypto.cifrarAES(tablaBytes, aesKey, iv);
            long finCifrado = System.nanoTime();
            long tiempoCifradoMs = (finCifrado - inicioCifrado) / 1_000_000;
            System.out.println("[MEDICIÓN] Cifrado AES: " + tiempoCifradoMs + " ms");

            // medir RSA
            if (usarRSA) {
                System.out.println("[INFO] Realizando medición de cifrado RSA (comparativo)...");
                Cipher cipherRSAComparativo = Cipher.getInstance("RSA");
                PublicKey publicKey = Crypto.cargarLlavePublica("keys/public_key.pem");
                cipherRSAComparativo.init(Cipher.ENCRYPT_MODE, publicKey);

                int blockSize = 117; // RSA 1024 bits con PKCS1
                ByteArrayOutputStream rsaOut = new ByteArrayOutputStream();

                long inicioCifradoRSA = System.nanoTime();
                for (int i = 0; i < tablaBytes.length; i += blockSize) {
                    int length = Math.min(blockSize, tablaBytes.length - i);
                    byte[] block = Arrays.copyOfRange(tablaBytes, i, i + length);
                    byte[] encryptedBlock = cipherRSAComparativo.doFinal(block);
                    rsaOut.write(encryptedBlock);
                }
                long finCifradoRSA = System.nanoTime();
                long tiempoCifradoRSAMs = (finCifradoRSA - inicioCifradoRSA) / 1_000_000;
                System.out.println("[MEDICIÓN] Cifrado RSA (comparativo): " + tiempoCifradoRSAMs + " ms");
            }

            // 5. HMAC de la tabla cifrada
            System.out.println("Generando HMAC de la tabla cifrada...");
            byte[] hmac = Crypto.generarHMAC(tablaCifrada, hmacKey);

            // 6. Enviar todo al cliente
            System.out.println("Enviando IV, firma, tabla cifrada y HMAC al cliente...");
            out.writeObject(iv);
            out.writeObject(firma);
            out.writeObject(tablaCifrada);
            out.writeObject(hmac);

            // ================================================
            // Definir si es normal(recibe solo 1) o iterativo(recibe n solicitudes)
            // ================================================
            boolean esIterativo = tipoCliente.equals("ITERATIVO");

            if (esIterativo) {
                for (int consulta = 1; consulta <= 32; consulta++) {
                    System.out.println("Esperando ID del servicio y su HMAC (consulta " + consulta + "/32)...");
                    if (!atenderConsulta(out, in, hmacKey)) {
                        break;
                    }
                }
                System.out.println("Cliente iterativo terminó las 32 consultas.");
            } else {
                System.out.println("Esperando ID del servicio y su HMAC (cliente normal)...");
                atenderConsulta(out, in, hmacKey);
            }

            System.out.println("Cerrando conexión con el cliente.");
        } catch (Exception e) {
            System.err.println("Error en DelegadoServidor:");
            e.printStackTrace();
        }
    }

    private boolean atenderConsulta(ObjectOutputStream out, ObjectInputStream in, byte[] hmacKey) {
        try {
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
                System.out.println("HMAC de consulta inválido. Terminando conexión.");
                out.writeObject("Error en la consulta");
                return false;
            }

            System.out.println("Buscando servicio con ID: " + id);
            Servicio s = servicios.get(id);
            String ip = (s != null) ? s.getIp() : "-1";
            int puerto = (s != null) ? s.getPuerto() : -1;

            System.out.println("Enviando respuesta: " + ip + ":" + puerto);
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(response);
            oos.writeObject(ip);
            oos.writeInt(puerto);
            oos.flush();
            oos.close();
            byte[] respuestaBytes = response.toByteArray();

            byte[] hmacRespuesta = Crypto.generarHMAC(respuestaBytes, hmacKey);
            out.writeObject(respuestaBytes);
            out.writeObject(hmacRespuesta);
            return true;
        } catch (Exception e) {
            System.err.println("Error durante la consulta:");
            e.printStackTrace();
            return false;
        }
    }
}

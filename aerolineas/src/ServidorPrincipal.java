import java.io.*;
import java.net.*;
import java.util.*;

public class ServidorPrincipal {

    private static final int PUERTO = 12345;
    private static final Map<Integer, Servicio> tablaServicios = new HashMap<>();

    public static void main(String[] args) throws IOException {
        inicializarServicios();

        // ================================
        //activar/desactivar RSA por consola
        // ================================
        boolean activarRSA = false; // Por defecto está apagado
        if (args.length > 0) {
            activarRSA = Boolean.parseBoolean(args[0]);  // Si paso 'true' lo activa
        }
        System.out.println("RSA ACTIVADO: " + activarRSA);

        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor Principal escuchando en el puerto " + PUERTO);

            while (true) {
                Socket cliente = serverSocket.accept();
                boolean rsaActivoFinal = activarRSA; // Variable final para usar dentro de la lambda
                new Thread(() -> {
                    try {
                        // DelegadoServidor ahora recibe la bandera de RSA
                        new DelegadoServidor(cliente, tablaServicios, rsaActivoFinal).run();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void inicializarServicios() {
        tablaServicios.put(1, new Servicio("Consulta vuelo", 1, "127.0.0.1", 9001));
        tablaServicios.put(2, new Servicio("Disponibilidad vuelo", 2, "127.0.0.1", 9002));
        tablaServicios.put(3, new Servicio("Costo vuelo", 3, "127.0.0.1", 9003));
    }
}

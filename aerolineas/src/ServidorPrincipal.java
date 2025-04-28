import java.io.*;
import java.net.*;
import java.util.*;

public class ServidorPrincipal {

    private static final int PUERTO = 12345;
    private static final Map<Integer, Servicio> tablaServicios = new HashMap<>();
    private static final MedidorTiempos medidor = new MedidorTiempos();
    private static final List<Thread> hilosMedidos = new ArrayList<>();
    private static int clientesConectados = 0;
    private static int totalClientesEsperados = 32; // Por defecto esperamos medir 32 clientes

    public static void main(String[] args) throws IOException {
        // ================================
        // activar/desactivar RSA por consola
        // y definir la cantidad de servicios
        // ================================
        boolean activarRSA = false; // Por defecto está apagado
        int numServicios = 3;       // Por defecto 3 servicios

        // Primer argumento: activar o desactivar RSA (true / false)
        if (args.length > 0) {
            activarRSA = Boolean.parseBoolean(args[0]);  // Si paso 'true' lo activa
        }

        // Segundo argumento: número de servicios
        if (args.length > 1) {
            try {
                numServicios = Integer.parseInt(args[1]);  // Si paso un número, define la cantidad de servicios
            } catch (NumberFormatException e) {
                System.out.println("Número de servicios inválido, usando 3 por defecto.");
            }
        }

        // Tercer argumento: número de clientes a medir (opcional)
        if (args.length > 2) {
            try {
                totalClientesEsperados = Integer.parseInt(args[2]);
            } catch (NumberFormatException e) {
                System.out.println("Número de clientes a medir inválido, usando 32 por defecto.");
            }
        }

        inicializarServicios(numServicios);  // Llamar con la cantidad de servicios
        System.out.println("RSA ACTIVADO: " + activarRSA);
        System.out.println("Número de servicios cargados: " + numServicios);

        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor Principal escuchando en el puerto " + PUERTO);

            while (true) { // Aceptar conexiones indefinidamente
                Socket cliente = serverSocket.accept();
                boolean rsaActivoFinal = activarRSA; // Variable final para usar dentro de la lambda
                Thread hiloCliente = new Thread(() -> {
                    try {
                        // DelegadoServidor ahora recibe la bandera de RSA y el medidor
                        new DelegadoServidor(cliente, tablaServicios, rsaActivoFinal, medidor).run();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
                synchronized (hilosMedidos) { // sincronizar para concurrencia segura
                    hilosMedidos.add(hiloCliente);
                    clientesConectados++;

                    // Cuando lleguen todos los clientes esperados, lanzar un hilo que espere y luego imprima
                    if (clientesConectados == totalClientesEsperados) {
                        new Thread(() -> {
                            try {
                                for (Thread t : hilosMedidos) {
                                    t.join();
                                }
                                medidor.imprimirResumen();
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }).start();
                    }
                }
                hiloCliente.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // ================================
    // Inicializa la tabla con N servicios
    // ================================
    private static void inicializarServicios(int cantidad) {
        tablaServicios.clear(); // Limpiar en caso de reinicialización
        for (int i = 1; i <= cantidad; i++) {
            tablaServicios.put(i, new Servicio("Servicio " + i, i, "127.0.0.1", 9000 + i));
        }
    }
    public static synchronized void imprimirResumenSiAplica() {
        // Llama al medidor de tiempos para imprimir todo
        medidor.imprimirResumen();
    }
    
}

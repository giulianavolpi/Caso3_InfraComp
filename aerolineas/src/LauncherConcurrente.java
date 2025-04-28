import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LauncherConcurrente {

    public static void main(String[] args) {
        // Permitir que el número de clientes se pase por argumentos (ej: java LauncherConcurrente 16)
        int numClientes = 32; // 4, 16, 64...

        if (args.length > 0) {
            try {
                numClientes = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.out.println("Argumento inválido, usando valor por defecto: 32 clientes.");
            }
        }

        System.out.println("Lanzando " + numClientes + " clientes concurrentes...");

        ExecutorService executor = Executors.newFixedThreadPool(numClientes);

        long inicio = System.nanoTime();

        for (int i = 0; i < numClientes; i++) {
            int clienteId = i + 1;  //id cliente
            executor.submit(() -> {
                try {
                    long inicioCliente = System.nanoTime(); // Medir tiempo individual de cada cliente
                    Cliente.main(null); // ejecuta el mismo cliente (una sola consulta)
                    long finCliente = System.nanoTime();
                    long duracionCliente = (finCliente - inicioCliente) / 1_000_000;
                    System.out.println("[Cliente " + clienteId + "] Tiempo de ejecución: " + duracionCliente + " ms");
                } catch (Exception e) {
                    System.err.println("[Cliente " + clienteId + "] Error durante la ejecución:");
                    e.printStackTrace();
                }
            });
        }

        executor.shutdown();
        while (!executor.isTerminated()) {
            // espera a que todos terminen
        }

        long fin = System.nanoTime();
        long duracionMs = (fin - inicio) / 1_000_000;
        System.out.println("Todos los clientes terminaron. Tiempo total: " + duracionMs + " ms");
    }
}

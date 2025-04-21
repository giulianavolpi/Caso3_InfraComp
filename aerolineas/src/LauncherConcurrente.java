import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LauncherConcurrente {

    public static void main(String[] args) {
        int numClientes = 32; // puedes cambiarlo a 4, 16, 64...

        ExecutorService executor = Executors.newFixedThreadPool(numClientes);

        long inicio = System.nanoTime();

        for (int i = 0; i < numClientes; i++) {
            executor.submit(() -> {
                try {
                    Cliente.main(null); // ejecuta el mismo cliente (una sola consulta)
                } catch (Exception e) {
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

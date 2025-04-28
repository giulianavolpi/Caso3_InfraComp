import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MedidorTiempos {

    private List<Double> tiemposFirma = new ArrayList<>();
    private List<Double> tiemposCifradoAES = new ArrayList<>();
    private List<Double> tiemposVerificacionHMAC = new ArrayList<>();
    private List<Double> tiemposCifradoRSA = new ArrayList<>(); // comparativo

    public void agregarFirma(double tiempoMs) {
        tiemposFirma.add(tiempoMs);
    }

    public void agregarCifradoAES(double tiempoMs) {
        tiemposCifradoAES.add(tiempoMs);
    }

    public void agregarVerificacionHMAC(double tiempoMs) {
        tiemposVerificacionHMAC.add(tiempoMs);
    }

    public void agregarCifradoRSA(double tiempoMs) {
        tiemposCifradoRSA.add(tiempoMs);
    }

    public void imprimirResumen() {
        System.out.println("\n===== RESUMEN FINAL DE MEDICIONES =====");
        procesarYMostrar("Firma Digital (SHA256withRSA)", tiemposFirma, true);
        procesarYMostrar("Cifrado AES (AES-CBC)", tiemposCifradoAES, true);
        procesarYMostrar("Verificación HMAC (HMAC-SHA256)", tiemposVerificacionHMAC, false);
        procesarYMostrar("Cifrado RSA (comparativo)", tiemposCifradoRSA, true);
        System.out.println("========================================");
    }

    private void procesarYMostrar(String titulo, List<Double> tiempos, boolean calcularOperaciones) {
        if (tiempos.isEmpty()) {
            System.out.println(titulo + ": No se registraron mediciones.");
            return;
        }

        double promedio = calcularPromedio(tiempos);
        double minimo = Collections.min(tiempos);
        double maximo = Collections.max(tiempos);

        System.out.println("\n[" + titulo + "]");
        System.out.println(String.join(", ",
            "Promedio: " + String.format("%.4f ms", promedio),
            "Mínimo: " + String.format("%.4f ms", minimo),
            "Máximo: " + String.format("%.4f ms", maximo)
        ));

        if (calcularOperaciones) {
            double operacionesPorSegundo = 1000.0 / promedio;
            System.out.println("→ Operaciones por segundo: " + String.format("%.2f", operacionesPorSegundo));
        }
    }

    private double calcularPromedio(List<Double> tiempos) {
        double suma = 0.0;
        for (double t : tiempos) {
            suma += t;
        }
        return suma / tiempos.size();
    }
}

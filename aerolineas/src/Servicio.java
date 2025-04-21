import java.io.Serializable;

public class Servicio implements Serializable {
    private String nombre;
    private int id;
    private String ip;
    private int puerto;

    public Servicio(String nombre, int id, String ip, int puerto) {
        this.nombre = nombre;
        this.id = id;
        this.ip = ip;
        this.puerto = puerto;
    }

    public String getNombre() {
        return nombre;
    }

    public int getId() {
        return id;
    }

    public String getIp() {
        return ip;
    }

    public int getPuerto() {
        return puerto;
    }
}

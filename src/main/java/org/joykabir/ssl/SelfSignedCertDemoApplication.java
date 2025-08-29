package org.joykabir.ssl;

import org.joykabir.ssl.cert.CertificateGenerator;
import org.joykabir.ssl.server.HttpsServer;
import org.joykabir.ssl.client.HttpsClient;
import org.joykabir.ssl.testing.InteractiveTestRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "self-signed-cert-demo", 
         description = "Self-signed SSL certificate demonstration with GSON",
         version = "1.0.0")
public class SelfSignedCertDemoApplication implements Callable<Integer> {
    
    private static final Logger logger = LoggerFactory.getLogger(SelfSignedCertDemoApplication.class);
    
    @Option(names = {"-s", "--server"}, description = "Start HTTPS server")
    private boolean startServer = false;
    
    @Option(names = {"-c", "--client"}, description = "Run HTTPS client tests")
    private boolean runClient = false;
    
    @Option(names = {"-i", "--interactive"}, description = "Run interactive testing")
    private boolean interactive = false;
    
    @Option(names = {"-g", "--generate-cert"}, description = "Generate new certificate")
    private boolean generateCert = false;
    
    @Option(names = {"-p", "--port"}, description = "Server port (default: 9001)")
    private int port = 9001;
    
    @Option(names = {"-k", "--keystore"}, description = "Keystore file path")
    private String keystorePath = "ssl-demo.p12";
    
    @Option(names = {"--password"}, description = "Keystore password")
    private String password = "changeit";
    
    @Option(names = {"--daemon"}, description = "Run server in daemon mode")
    private boolean daemon = false;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new SelfSignedCertDemoApplication()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        logger.info("Self-Signed Certificate Demo Application Starting...");
        logger.info("Using GSON for JSON processing");
        
        // Generate certificate if requested or if keystore doesn't exist
        if (generateCert || !Files.exists(Path.of(keystorePath))) {
            logger.info("Generating self-signed certificate...");
            CertificateGenerator.generateCertificate(keystorePath, password);
            logger.info("Certificate generated: {}", keystorePath);
        }
        
        if (startServer) {
            startHttpsServer();
        }
        
        if (runClient) {
            runClientTests();
        }
        
        if (interactive) {
            runInteractiveTests();
        }
        
        if (!startServer && !runClient && !interactive && !generateCert) {
            // Default behavior - start server and run interactive tests
            startHttpsServer();
            Thread.sleep(2000); // Give server time to start
            runInteractiveTests();
        }
        
        return 0;
    }
    
    private void startHttpsServer() throws Exception {
        HttpsServer server = new HttpsServer(port, keystorePath, password);
        server.start();
        logger.info("HTTPS Server started on port {}", port);
        
        // Keep server running
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutting down server...");
            server.stop();
        }));
        
        if (daemon || (!interactive && !runClient)) {
            Thread.currentThread().join(); // Keep main thread alive
        }
    }
    
    private void runClientTests() throws Exception {
        HttpsClient client = new HttpsClient();
        client.runAllTests("https://localhost:" + port);
    }
    
    private void runInteractiveTests() throws Exception {
        InteractiveTestRunner runner = new InteractiveTestRunner(port, keystorePath, password);
        runner.run();
    }
}

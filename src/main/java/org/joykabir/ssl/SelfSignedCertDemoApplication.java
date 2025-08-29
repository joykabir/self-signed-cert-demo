package org.joykabir.ssl;

import org.joykabir.ssl.cert.CertificateGenerationException;
import org.joykabir.ssl.cert.CertificateGenerator;
import org.joykabir.ssl.client.HttpsClient;
import org.joykabir.ssl.config.AppConfig;
import org.joykabir.ssl.server.HttpsServer;
import org.joykabir.ssl.testing.InteractiveTestRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

public class SelfSignedCertDemoApplication {

	private static final Logger logger = LoggerFactory.getLogger(SelfSignedCertDemoApplication.class);

	// Configuration fields
	private boolean startServer = false;
	private boolean runClient = false;
	private boolean interactive = false;
	private boolean generateCert = false;
	private boolean daemon = false;
	private boolean showConfig = false;
	private boolean showHelp = false;
	private Integer port = null;
	private String keystorePath = null;
	private String password = null;

	public static void main(String[] args) {
		// Print banner
		printBanner();

		SelfSignedCertDemoApplication app = new SelfSignedCertDemoApplication();
		try {
			app.parseArguments(args);
			int exitCode = app.run();
			System.exit(exitCode);
		} catch (Exception e) {
			logger.error("❌ Application failed: {}", e.getMessage(), e);
			System.exit(1);
		}
	}

	private static void printBanner() {
		try (InputStream is = SelfSignedCertDemoApplication.class.getClassLoader().getResourceAsStream("banner.txt")) {
			if (is != null) {
				String banner = new String(is.readAllBytes());
				System.out.println(banner);
			}
		} catch (IOException e) {
			logger.debug("Could not load banner: {}", e.getMessage());
		}
	}

	private void parseArguments(String[] args) {
		List<String> argList = Arrays.asList(args);

		for (int i = 0; i < args.length; i++) {
			String arg = args[i];

			switch (arg) {
				case "-s", "--server" -> startServer = true;
				case "-c", "--client" -> runClient = true;
				case "-i", "--interactive" -> interactive = true;
				case "-g", "--generate-cert" -> generateCert = true;
				case "--daemon" -> daemon = true;
				case "--show-config" -> showConfig = true;
				case "-h", "--help" -> showHelp = true;
				case "-p", "--port" -> {
					if (i + 1 < args.length) {
						try {
							port = Integer.parseInt(args[++i]);
						} catch (NumberFormatException e) {
							throw new IllegalArgumentException("Invalid port number: " + args[i]);
						}
					} else {
						throw new IllegalArgumentException("Port option requires a value");
					}
				}
				case "-k", "--keystore" -> {
					if (i + 1 < args.length) {
						keystorePath = args[++i];
					} else {
						throw new IllegalArgumentException("Keystore option requires a value");
					}
				}
				case "--password" -> {
					if (i + 1 < args.length) {
						password = args[++i];
					} else {
						throw new IllegalArgumentException("Password option requires a value");
					}
				}
				case "--version" -> {
					System.out.println("Self-Signed Certificate Demo v0.1-SNAPSHOT");
					System.exit(0);
				}
				default -> {
					if (arg.startsWith("-")) {
						throw new IllegalArgumentException("Unknown option: " + arg);
					}
				}
			}
		}

		if (showHelp) {
			printHelp();
			System.exit(0);
		}
	}

	private void printHelp() {
		System.out.println("""

            Usage: java -jar self-signed-cert-demo.jar [OPTIONS]

            Self-signed SSL certificate demonstration with GSON

            OPTIONS:
              -s, --server              Start HTTPS server
              -c, --client              Run HTTPS client tests
              -i, --interactive         Run interactive testing
              -g, --generate-cert       Generate new certificate
              -p, --port <port>         Server port (default: from config)
              -k, --keystore <path>     Keystore file path (default: from config)
                  --password <password> Keystore password (default: from config)
                  --daemon              Run server in daemon mode
                  --show-config         Show current configuration and exit
              -h, --help                Show this help message
                  --version             Show version information

            EXAMPLES:
              # Start server with default configuration
              java -jar self-signed-cert-demo.jar --server

              # Run interactive tests
              java -jar self-signed-cert-demo.jar --interactive

              # Start server on custom port
              java -jar self-signed-cert-demo.jar --server --port 8443

              # Generate certificate and start server
              java -jar self-signed-cert-demo.jar --generate-cert --server

              # Run client tests against custom port
              java -jar self-signed-cert-demo.jar --client --port 8443

              # Show current configuration
              java -jar self-signed-cert-demo.jar --show-config

            If no options are provided, the application will start the server
            and run interactive tests with default configuration.
            """);
	}

	public int run() throws Exception {
		AppConfig config = AppConfig.getInstance();

		logger.info("🚀 Self-Signed Certificate Demo Application Starting...");
		logger.info("📦 Using GSON for JSON processing");

		// Use configuration values with command line overrides
		int serverPort = port != null ? port : config.getServerPort();
		String keystoreFile = keystorePath != null ? keystorePath : config.getKeystorePath();
		String keystorePassword = password != null ? password : config.getKeystorePassword();

		if (showConfig) {
			config.printConfiguration();
			System.out.println("\nCommand Line Overrides:");
			if (port != null) System.out.println("  Port: " + port);
			if (keystorePath != null) System.out.println("  Keystore Path: " + keystorePath);
			if (password != null) System.out.println("  Password: [HIDDEN]");
			return 0;
		}

		// Generate certificate if requested or if keystore doesn't exist
		// Generate certificate if requested or if keystore doesn't exist
		if (generateCert || !Files.exists(Path.of(keystoreFile))) {
			logger.info("🔑 Generating self-signed certificate...");
			try {
				CertificateGenerator.generateCertificate(keystoreFile, keystorePassword);
				logger.info("✅ Certificate generated: {}", keystoreFile);
			} catch (CertificateGenerationException e) {
				logger.error("❌ Certificate generation failed: {}", e.getMessage());

				// Show available strategies
				List<String> strategies = CertificateGenerator.getAvailableStrategies();
				logger.info("💡 Available generation strategies: {}", strategies);

				throw e; // Re-throw to stop application
			}
		}

		if (startServer) {
			startHttpsServer(serverPort, keystoreFile, keystorePassword);
		}

		if (runClient) {
			runClientTests(serverPort);
		}

		if (interactive) {
			runInteractiveTests(serverPort, keystoreFile, keystorePassword);
		}

		if (!startServer && !runClient && !interactive && !generateCert && !showConfig) {
			// Default behavior - start server and run interactive tests
			logger.info("🎯 No specific options provided. Running default: server + interactive tests");
			startHttpsServer(serverPort, keystoreFile, keystorePassword);
			Thread.sleep(2000); // Give server time to start
			runInteractiveTests(serverPort, keystoreFile, keystorePassword);
		}

		return 0;
	}

	private void startHttpsServer(int serverPort, String keystoreFile, String keystorePassword) throws Exception {
		logger.info("🌐 Starting HTTPS server on port {}...", serverPort);

		HttpsServer server = new HttpsServer(serverPort, keystoreFile, keystorePassword);
		server.start();

		// Keep server running
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			logger.info("🛑 Shutting down server...");
			server.stop();
		}));

		if (daemon || (!interactive && !runClient)) {
			logger.info("🔄 Server running in daemon mode. Press Ctrl+C to stop.");
			Thread.currentThread().join(); // Keep main thread alive
		}
	}

	private void runClientTests(int serverPort) throws Exception {
		logger.info("🧪 Running HTTPS client tests...");
		HttpsClient client = new HttpsClient();
		client.runAllTests("https://localhost:" + serverPort);
	}

	private void runInteractiveTests(int serverPort, String keystoreFile, String keystorePassword) throws Exception {
		logger.info("🎮 Starting interactive test runner...");
		InteractiveTestRunner runner = new InteractiveTestRunner(serverPort, keystoreFile, keystorePassword);
		runner.run();
	}
}
package org.joykabir.ssl.testing;

import org.joykabir.ssl.client.HttpsClient;
import org.joykabir.ssl.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Scanner;

public class InteractiveTestRunner {

	private static final Logger logger = LoggerFactory.getLogger(InteractiveTestRunner.class);
	private final int port;
	private final String keystorePath;
	private final String password;
	private final Scanner scanner;
	private final AppConfig config;

	public InteractiveTestRunner(int port, String keystorePath, String password) {
		this.port = port;
		this.keystorePath = keystorePath;
		this.password = password;
		this.scanner = new Scanner(System.in);
		this.config = AppConfig.getInstance();
	}

	public void run() throws Exception {
		logger.info("\n=== SSL Demo Interactive Testing ===");

		boolean running = true;
		while (running) {
			printMenu();
			String choice = scanner.nextLine().trim();

			switch (choice) {
				case "1" -> runCurlTests();
				case "2" -> runHttpClientTests();
				case "3" -> showCertificateInfo();
				case "4" -> demonstrateValidationFailures();
				case "5" -> showSslSessionInfo();
				case "6" -> generateCurlCommands();
				case "7" -> showRealTimeCertInfo();
				case "8" -> showConfiguration();
				case "q", "quit", "exit" -> running = false;
				default -> logger.info("Invalid option. Please try again.");
			}

			if (running) {
				logger.info("\nPress Enter to continue...");
				scanner.nextLine();
			}
		}
	}

	private void printMenu() {
		System.out.println("""
            \n=== SSL Demo Menu ===
            1. Run cURL tests
            2. Run HttpClient tests
            3. Show certificate information
            4. Demonstrate validation failures
            5. Show SSL session information
            6. Generate cURL commands
            7. Show real-time certificate info
            8. Show configuration
            q. Quit

            Choose an option: """);
	}

	private void runCurlTests() throws Exception {
		logger.info("\n=== Running cURL Tests ===");

		String baseUrl = "https://localhost:" + port;
		CurlCommandGenerator curlGen = new CurlCommandGenerator(baseUrl);

		// Test 1: Strict validation (should fail)
		logger.info("1. Testing strict SSL validation (should fail):");
		String strictCommand = curlGen.generateStrictValidationCommand("/api/status");
		logger.info("Command: {}", strictCommand);
		executeCommand(strictCommand);

		Thread.sleep(2000);

		// Test 2: Insecure mode (should succeed)
		logger.info("\n2. Testing insecure mode (should succeed):");
		String insecureCommand = curlGen.generateInsecureCommand("/api/status");
		logger.info("Command: {}", insecureCommand);
		executeCommand(insecureCommand);

		Thread.sleep(2000);

		// Test 3: Verbose certificate info
		logger.info("\n3. Getting verbose certificate information:");
		String verboseCommand = curlGen.generateVerboseCommand("/api/certificate");
		logger.info("Command: {}", verboseCommand);
		executeCommand(verboseCommand);
	}

	private void runHttpClientTests() throws Exception {
		logger.info("\n=== Running HttpClient Tests ===");

		HttpsClient client = new HttpsClient();
		String baseUrl = "https://localhost:" + port;

		client.runAllTests(baseUrl);
	}

	private void showCertificateInfo() throws Exception {
		logger.info("\n=== Certificate Information ===");

		// Load and display certificate from keystore
		java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
		try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
			keyStore.load(fis, password.toCharArray());
		}

		java.security.cert.X509Certificate cert =
				(java.security.cert.X509Certificate) keyStore.getCertificate("ssl-demo");

		if (cert != null) {
			logger.info("Subject: {}", cert.getSubjectX500Principal().getName());
			logger.info("Issuer: {}", cert.getIssuerX500Principal().getName());
			logger.info("Serial Number: {}", cert.getSerialNumber().toString(16).toUpperCase());
			logger.info("Valid From: {}", cert.getNotBefore());
			logger.info("Valid To: {}", cert.getNotAfter());
			logger.info("Signature Algorithm: {}", cert.getSigAlgName());
			logger.info("Public Key Algorithm: {}", cert.getPublicKey().getAlgorithm());

			if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey rsaKey) {
				logger.info("Key Size: {} bits", rsaKey.getModulus().bitLength());
			}

			// Subject Alternative Names
			var sanCollection = cert.getSubjectAlternativeNames();
			if (sanCollection != null) {
				logger.info("Subject Alternative Names:");
				sanCollection.forEach(san ->
						logger.info("  - {}", san.get(1)));
			}
		}
	}

	private void demonstrateValidationFailures() throws Exception {
		logger.info("\n=== Demonstrating Validation Failures ===");

		String baseUrl = "https://localhost:" + port;

		logger.info("1. Certificate not in trust store");
		logger.info("2. Self-signed certificate");
		logger.info("3. Hostname verification (if using IP instead of localhost)");

		// Demonstrate with different client configurations
		HttpsClient client = new HttpsClient();
		client.runAllTests(baseUrl);
	}

	private void showSslSessionInfo() throws Exception {
		logger.info("\n=== SSL Session Information ===");

		String command = String.format(
				"curl -k -s https://localhost:%d/api/status | jq '.sslSession'", port);
		logger.info("Command: {}", command);
		executeCommand(command);
	}

	private void generateCurlCommands() {
		logger.info("\n=== cURL Commands ===");

		String baseUrl = "https://localhost:" + port;
		CurlCommandGenerator curlGen = new CurlCommandGenerator(baseUrl);

		logger.info("Strict validation (will fail):");
		logger.info("  {}", curlGen.generateStrictValidationCommand("/api/status"));

		logger.info("\nInsecure mode (will succeed):");
		logger.info("  {}", curlGen.generateInsecureCommand("/api/status"));

		logger.info("\nVerbose certificate info:");
		logger.info("  {}", curlGen.generateVerboseCommand("/api/certificate"));

		logger.info("\nShow only certificate details:");
		logger.info("  {}", curlGen.generateCertInfoCommand());

		logger.info("\nTest different endpoints:");
		logger.info("  {}", curlGen.generateInsecureCommand("/"));
		logger.info("  {}", curlGen.generateInsecureCommand("/api/certificate"));
	}

	private void showRealTimeCertInfo() throws Exception {
		logger.info("\n=== Real-time Certificate Information ===");

		// Show certificate expiration countdown
		java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
		try (java.io.FileInputStream fis = new java.io.FileInputStream(keystorePath)) {
			keyStore.load(fis, password.toCharArray());
		}

		java.security.cert.X509Certificate cert =
				(java.security.cert.X509Certificate) keyStore.getCertificate("ssl-demo");

		if (cert != null) {
			java.time.LocalDateTime now = java.time.LocalDateTime.now();
			java.time.LocalDateTime expiry = cert.getNotAfter().toInstant()
					.atZone(java.time.ZoneId.systemDefault()).toLocalDateTime();

			java.time.Duration timeToExpiry = java.time.Duration.between(now, expiry);

			logger.info("Certificate expires in: {} days, {} hours, {} minutes",
					timeToExpiry.toDays(),
					timeToExpiry.toHours() % 24,
					timeToExpiry.toMinutes() % 60);

			if (timeToExpiry.toDays() < 30) {
				logger.warn("Certificate expires within 30 days!");
			}

			// Live SSL connection test
			logger.info("\nTesting live SSL connection...");
			executeCommand(String.format("curl -k -w '%%{ssl_verify_result}' -s -o /dev/null https://localhost:%d/api/status", port));
		}
	}

	private void showConfiguration() {
		logger.info("\n=== Current Configuration ===");
		config.printConfiguration();
	}

	private void executeCommand(String command) {
		try {
			ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
			pb.redirectErrorStream(true);
			Process process = pb.start();

			try (BufferedReader reader = new BufferedReader(
					new InputStreamReader(process.getInputStream()))) {
				String line;
				while ((line = reader.readLine()) != null) {
					System.out.println(line);
				}
			}

			int exitCode = process.waitFor();
			if (exitCode != 0) {
				logger.info("Command exited with code: {}", exitCode);
			}

		} catch (Exception e) {
			logger.error("Failed to execute command: {}", command, e);
		}
	}
}
package org.joykabir.ssl.cert;

import org.joykabir.ssl.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class SimpleCertificateGenerator {

	private static final Logger logger = LoggerFactory.getLogger(SimpleCertificateGenerator.class);

	public static void generateCertificate(String keystorePath, String password) throws Exception {
		AppConfig config = AppConfig.getInstance();

		logger.info("🔑 Starting certificate generation using keytool...");
		logger.info("📊 Key Size: {} bits, Validity: {} years",
				config.getCertificateKeySize(),
				config.getCertificateValidityYears());

		// Delete existing keystore if it exists
		Path keystoreFile = Path.of(keystorePath);
		if (Files.exists(keystoreFile)) {
			Files.delete(keystoreFile);
			logger.info("🗑️ Deleted existing keystore: {}", keystorePath);
		}

		// Build keytool command
		List<String> command = new ArrayList<>();
		command.add("keytool");
		command.add("-genkeypair");
		command.add("-alias");
		command.add("ssl-demo");
		command.add("-keyalg");
		command.add(config.getCertificateAlgorithm());
		command.add("-keysize");
		command.add(String.valueOf(config.getCertificateKeySize()));
		command.add("-validity");
		command.add(String.valueOf(config.getCertificateValidityYears() * 365));
		command.add("-keystore");
		command.add(keystorePath);
		command.add("-storetype");
		command.add("PKCS12");
		command.add("-storepass");
		command.add(password);
		command.add("-keypass");
		command.add(password);
		command.add("-dname");
		command.add("CN=Self-Signed Cert Demo Server, OU=Development, O=JoyKabir SSL Demo, C=US");
		command.add("-ext");
		command.add("SAN=dns:localhost,ip:127.0.0.1,ip:::1");
		command.add("-ext");
		command.add("KeyUsage=digitalSignature,keyEncipherment");
		command.add("-ext");
		command.add("ExtendedKeyUsage=serverAuth,clientAuth");

		// Execute keytool command
		ProcessBuilder pb = new ProcessBuilder(command);
		pb.redirectErrorStream(true);

		logger.info("🔧 Executing: {}", String.join(" ", command));

		Process process = pb.start();

		// Read output
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
			String line;
			while ((line = reader.readLine()) != null) {
				logger.debug("keytool: {}", line);
			}
		}

		int exitCode = process.waitFor();

		if (exitCode == 0) {
			logger.info("✅ Certificate generated successfully using keytool");
			logger.info("✅ Keystore saved to: {}", keystorePath);
			logger.info("✅ Certificate includes SAN for localhost");
		} else {
			throw new RuntimeException("keytool failed with exit code: " + exitCode);
		}
	}
}
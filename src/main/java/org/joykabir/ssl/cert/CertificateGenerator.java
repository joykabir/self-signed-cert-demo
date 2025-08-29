package org.joykabir.ssl.cert;

import org.joykabir.ssl.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

/**
 * Robust certificate generator with multiple fallback strategies
 */
public class CertificateGenerator {

	private static final Logger logger = LoggerFactory.getLogger(CertificateGenerator.class);

	// Available generation strategies in order of preference
	private static final Map<String, CertificateGenerationStrategy> STRATEGIES = new LinkedHashMap<>();

	static {
		STRATEGIES.put("BouncyCastle", CertificateGenerator::generateWithBouncyCastle);
		STRATEGIES.put("Keytool", SimpleCertificateGenerator::generateCertificate);
		// Could add more strategies here, e.g., "OpenSSL", "JSecurity", etc.
	}

	/**
	 * Generate a certificate using the best available method
	 *
	 * @param keystorePath Path where the keystore should be saved
	 * @param password Password for the keystore
	 * @throws CertificateGenerationException if all generation methods fail
	 */
	public static void generateCertificate(String keystorePath, String password)
			throws CertificateGenerationException {

		logger.info("🔑 Starting certificate generation with {} available strategies...", STRATEGIES.size());

		List<CertificateGenerationException.GenerationAttempt> failedAttempts = new ArrayList<>();

		for (Map.Entry<String, CertificateGenerationStrategy> entry : STRATEGIES.entrySet()) {
			String strategyName = entry.getKey();
			CertificateGenerationStrategy strategy = entry.getValue();

			logger.info("🔧 Attempting certificate generation using: {}", strategyName);

			long startTime = System.currentTimeMillis();

			try {
				strategy.generateCertificate(keystorePath, password);

				long duration = System.currentTimeMillis() - startTime;
				logger.info("✅ Certificate generation successful using {} (took {}ms)", strategyName, duration);

				return; // Success! Exit the method

			} catch (Exception e) {
				long duration = System.currentTimeMillis() - startTime;
				String errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();

				logger.warn("⚠️ {} failed (took {}ms): {}", strategyName, duration, errorMessage);
				logger.debug("Full error details for {}", strategyName, e);

				failedAttempts.add(new CertificateGenerationException.GenerationAttempt(
						strategyName, errorMessage, e, duration));

				// Continue to next strategy
			}
		}

		// All strategies failed
		String errorMessage = String.format(
				"Certificate generation failed with all %d available methods", STRATEGIES.size());

		logger.error("❌ {}", errorMessage);
		logFailureSummary(failedAttempts);

		throw new CertificateGenerationException(errorMessage, failedAttempts);
	}

	/**
	 * Check if a specific generation strategy is available
	 */
	public static boolean isStrategyAvailable(String strategyName) {
		return STRATEGIES.containsKey(strategyName);
	}

	/**
	 * Get available strategy names
	 */
	public static List<String> getAvailableStrategies() {
		return new ArrayList<>(STRATEGIES.keySet());
	}

	/**
	 * Generate certificate using a specific strategy (for testing)
	 */
	public static void generateCertificateWithStrategy(String strategyName, String keystorePath, String password)
			throws CertificateGenerationException {

		CertificateGenerationStrategy strategy = STRATEGIES.get(strategyName);
		if (strategy == null) {
			throw new CertificateGenerationException(
					"Unknown strategy: " + strategyName + ". Available: " + STRATEGIES.keySet(),
					List.of()
			);
		}

		logger.info("🎯 Generating certificate using specific strategy: {}", strategyName);

		long startTime = System.currentTimeMillis();

		try {
			strategy.generateCertificate(keystorePath, password);

			long duration = System.currentTimeMillis() - startTime;
			logger.info("✅ Certificate generation successful using {} (took {}ms)", strategyName, duration);

		} catch (Exception e) {
			long duration = System.currentTimeMillis() - startTime;
			String errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();

			List<CertificateGenerationException.GenerationAttempt> attempts = List.of(
					new CertificateGenerationException.GenerationAttempt(strategyName, errorMessage, e, duration)
			);

			throw new CertificateGenerationException(
					"Certificate generation failed using " + strategyName, e, attempts);
		}
	}

	private static void logFailureSummary(List<CertificateGenerationException.GenerationAttempt> failedAttempts) {
		logger.error("📋 Certificate Generation Failure Summary:");
		for (int i = 0; i < failedAttempts.size(); i++) {
			CertificateGenerationException.GenerationAttempt attempt = failedAttempts.get(i);
			logger.error("  {}. {} ({}ms): {}",
					i + 1, attempt.getMethodName(), attempt.getDurationMs(), attempt.getErrorMessage());
		}

		// Suggest solutions
		logger.error("💡 Troubleshooting suggestions:");
		if (failedAttempts.stream().anyMatch(a -> a.getMethodName().equals("BouncyCastle"))) {
			logger.error("   - BouncyCastle: Ensure bcprov-jdk18on and bcpkix-jdk18on are in classpath");
		}
		if (failedAttempts.stream().anyMatch(a -> a.getMethodName().equals("Keytool"))) {
			logger.error("   - Keytool: Ensure Java keytool is available in PATH");
		}
		logger.error("   - Check file permissions for keystore directory");
		logger.error("   - Verify password is not empty or null");
	}

	// BouncyCastle implementation (same as before, but private)
	private static void generateWithBouncyCastle(String keystorePath, String password) throws Exception {
		// Check if BouncyCastle is available
		try {
			Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
		} catch (ClassNotFoundException e) {
			throw new RuntimeException("BouncyCastle not found in classpath", e);
		}

		AppConfig config = AppConfig.getInstance();

		logger.debug("📊 BouncyCastle config - Algorithm: {}, Key Size: {} bits, Validity: {} years",
				config.getCertificateAlgorithm(),
				config.getCertificateKeySize(),
				config.getCertificateValidityYears());

		// Add BouncyCastle provider
		org.bouncycastle.jce.provider.BouncyCastleProvider bcProvider =
				new org.bouncycastle.jce.provider.BouncyCastleProvider();
		java.security.Security.addProvider(bcProvider);

		// Generate RSA key pair
		java.security.KeyPairGenerator keyPairGenerator =
				java.security.KeyPairGenerator.getInstance(config.getCertificateAlgorithm());
		keyPairGenerator.initialize(config.getCertificateKeySize(), new java.security.SecureRandom());
		java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Certificate validity
		java.time.LocalDateTime notBefore = java.time.LocalDateTime.now();
		java.time.LocalDateTime notAfter = notBefore.plusYears(config.getCertificateValidityYears());

		logger.debug("📅 Certificate validity: {} to {}", notBefore, notAfter);

		// Create certificate using BouncyCastle
		java.security.cert.X509Certificate certificate = createSelfSignedCertificateBC(
				keyPair,
				java.util.Date.from(notBefore.atZone(java.time.ZoneId.systemDefault()).toInstant()),
				java.util.Date.from(notAfter.atZone(java.time.ZoneId.systemDefault()).toInstant()),
				config.getSignatureAlgorithm()
		);

		// Create and save keystore
		saveToKeystore(keystorePath, password, keyPair.getPrivate(), certificate);

		logger.debug("✅ BouncyCastle: Certificate saved to keystore: {}", keystorePath);
	}

	private static java.security.cert.X509Certificate createSelfSignedCertificateBC(
			java.security.KeyPair keyPair, java.util.Date notBefore, java.util.Date notAfter, String signatureAlgorithm)
			throws Exception {

		// Certificate subject and issuer (same for self-signed)
		org.bouncycastle.asn1.x500.X500Name subject =
				new org.bouncycastle.asn1.x500.X500Name("CN=Self-Signed Cert Demo Server, OU=Development, O=JoyKabir SSL Demo, C=US");
		org.bouncycastle.asn1.x500.X500Name issuer = subject; // Self-signed

		// Serial number
		java.math.BigInteger serialNumber = new java.math.BigInteger(64, new java.security.SecureRandom());

		// Create certificate builder
		org.bouncycastle.cert.X509v3CertificateBuilder certBuilder =
				new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
						issuer, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());

		// Add Subject Alternative Names (SAN)
		org.bouncycastle.asn1.x509.GeneralName[] sanArray = new org.bouncycastle.asn1.x509.GeneralName[] {
				new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName, "localhost"),
				new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.iPAddress, "127.0.0.1"),
				new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.iPAddress, "::1")
		};
		org.bouncycastle.asn1.x509.GeneralNames subjectAltNames =
				new org.bouncycastle.asn1.x509.GeneralNames(sanArray);
		certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, subjectAltNames);

		// Add extensions
		addStandardExtensions(certBuilder);

		// Create content signer
		org.bouncycastle.operator.ContentSigner contentSigner =
				new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(signatureAlgorithm)
						.setProvider("BC")
						.build(keyPair.getPrivate());

		// Build certificate
		org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(contentSigner);

		// Convert to X509Certificate
		return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
				.setProvider("BC")
				.getCertificate(certHolder);
	}

	private static void addStandardExtensions(org.bouncycastle.cert.X509v3CertificateBuilder certBuilder)
			throws java.io.IOException {

		// Key Usage
		org.bouncycastle.asn1.x509.KeyUsage keyUsage = new org.bouncycastle.asn1.x509.KeyUsage(
				org.bouncycastle.asn1.x509.KeyUsage.digitalSignature |
						org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment |
						org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation
		);
		certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, keyUsage);

		// Extended Key Usage
		org.bouncycastle.asn1.x509.ExtendedKeyUsage extKeyUsage =
				new org.bouncycastle.asn1.x509.ExtendedKeyUsage(new org.bouncycastle.asn1.x509.KeyPurposeId[] {
						org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth,
						org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth
				});
		certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, true, extKeyUsage);

		// Basic Constraints
		org.bouncycastle.asn1.x509.BasicConstraints basicConstraints =
				new org.bouncycastle.asn1.x509.BasicConstraints(false);
		certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, basicConstraints);
	}

	private static void saveToKeystore(String keystorePath, String password,
									   java.security.PrivateKey privateKey,
									   java.security.cert.X509Certificate certificate) throws Exception {

		// Create keystore
		java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
		keyStore.load(null, null);

		// Add private key and certificate
		keyStore.setKeyEntry("ssl-demo", privateKey,
				password.toCharArray(), new java.security.cert.Certificate[]{certificate});

		// Save keystore
		try (java.io.FileOutputStream fos = new java.io.FileOutputStream(keystorePath)) {
			keyStore.store(fos, password.toCharArray());
		}
	}
}
package org.joykabir.ssl;

import org.joykabir.ssl.cert.CertificateGenerator;
import org.joykabir.ssl.cert.CertificateInfo;
import org.junit.After;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.*;

public class CertificateGeneratorTest {

	private final String testKeystore = "test-cert.p12";
	private final String testPassword = "testpass123";

	@After
	public void cleanup() {
		new File(testKeystore).delete();
	}

	@Test
	public void testCertificateGeneration() throws Exception {
		// Generate certificate
		CertificateGenerator.generateCertificate(testKeystore, testPassword);

		// Verify file was created
		File keystoreFile = new File(testKeystore);
		assertThat(keystoreFile).exists();
		assertThat(keystoreFile.length()).isGreaterThan(0);

		// Load and verify keystore
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(testKeystore)) {
			keyStore.load(fis, testPassword.toCharArray());
		}

		// Verify certificate exists
		X509Certificate cert = (X509Certificate) keyStore.getCertificate("ssl-demo");
		assertThat(cert).isNotNull();

		// Verify certificate properties
		assertThat(cert.getPublicKey().getAlgorithm()).isEqualTo("RSA");

		// Check key size
		if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey rsaKey) {
			assertThat(rsaKey.getModulus().bitLength()).isEqualTo(4096);
		}

		// Check validity period (should be 3 years)
		long validityPeriod = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
		long threeyearsInMs = 3L * 365 * 24 * 60 * 60 * 1000; // 3 years in milliseconds
		assertThat(validityPeriod).isCloseTo(threeyearsInMs, within(24 * 60 * 60 * 1000L)); // Within 1 day

		// Check Subject Alternative Names
		assertThat(cert.getSubjectAlternativeNames()).isNotNull();
		assertThat(cert.getSubjectAlternativeNames()).isNotEmpty();
	}

	@Test
	public void testCertificateInfo() throws Exception {
		// Generate certificate
		CertificateGenerator.generateCertificate(testKeystore, testPassword);

		// Load certificate
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(testKeystore)) {
			keyStore.load(fis, testPassword.toCharArray());
		}

		X509Certificate cert = (X509Certificate) keyStore.getCertificate("ssl-demo");

		// Create certificate info
		CertificateInfo certInfo = CertificateInfo.from(cert);

		// Verify certificate info
		assertThat(certInfo.getKeySize()).isEqualTo(4096);
		assertThat(certInfo.getPublicKeyAlgorithm()).isEqualTo("RSA");
		assertThat(certInfo.getSignatureAlgorithm()).contains("SHA256");
		assertThat(certInfo.getSubject()).contains("Self-Signed Cert Demo Server");
		assertThat(certInfo.getSubjectAlternativeNames()).contains("localhost");
		assertThat(certInfo.getValidityPeriodDays()).isCloseTo(365 * 3, within(5L)); // ~3 years
		assertThat(certInfo.isExpired()).isFalse();
		assertThat(certInfo.getDaysUntilExpiry()).isGreaterThan(1000); // Should be more than 1000 days
	}
}
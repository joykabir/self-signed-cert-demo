package org.joykabir.ssl;

import org.joykabir.ssl.cert.CertificateGenerator;
import org.joykabir.ssl.cert.CertificateGenerationException;
import org.junit.After;
import org.junit.Test;

import java.io.File;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

public class CertificateGeneratorRobustTest {

	private final String testKeystore = "robust-test.p12";
	private final String testPassword = "testpass123";

	@After
	public void cleanup() {
		new File(testKeystore).delete();
	}

	@Test
	public void testSuccessfulGeneration() throws Exception {
		// Should succeed with available strategies
		CertificateGenerator.generateCertificate(testKeystore, testPassword);

		File keystoreFile = new File(testKeystore);
		assertThat(keystoreFile).exists();
		assertThat(keystoreFile.length()).isGreaterThan(0);
	}

	@Test
	public void testAvailableStrategies() {
		List<String> strategies = CertificateGenerator.getAvailableStrategies();

		assertThat(strategies).isNotEmpty();
		assertThat(strategies).contains("BouncyCastle", "Keytool");
	}

	@Test
	public void testStrategyAvailability() {
		assertThat(CertificateGenerator.isStrategyAvailable("BouncyCastle")).isTrue();
		assertThat(CertificateGenerator.isStrategyAvailable("Keytool")).isTrue();
		assertThat(CertificateGenerator.isStrategyAvailable("NonExistent")).isFalse();
	}

	@Test
	public void testInvalidPassword() {
		try {
			CertificateGenerator.generateCertificate("/invalid/path/test.p12", "");
			fail("Should have thrown CertificateGenerationException");
		} catch (CertificateGenerationException e) {
			assertThat(e.getFailedAttempts()).isNotEmpty();
			assertThat(e.getMessage()).contains("Certificate generation failed");
		}
	}

	@Test
	public void testSpecificStrategy() throws Exception {
		// Test using a specific strategy
		if (CertificateGenerator.isStrategyAvailable("Keytool")) {
			CertificateGenerator.generateCertificateWithStrategy("Keytool", testKeystore, testPassword);

			File keystoreFile = new File(testKeystore);
			assertThat(keystoreFile).exists();
		}
	}

	@Test
	public void testUnknownStrategy() {
		try {
			CertificateGenerator.generateCertificateWithStrategy("UnknownStrategy", testKeystore, testPassword);
			fail("Should have thrown CertificateGenerationException");
		} catch (CertificateGenerationException e) {
			assertThat(e.getMessage()).contains("Unknown strategy");
		}
	}
}
package org.joykabir.ssl.cert;

/**
 * Strategy interface for different certificate generation methods
 */
@FunctionalInterface
public interface CertificateGenerationStrategy {

	/**
	 * Generate a certificate using this strategy
	 *
	 * @param keystorePath Path where the keystore should be saved
	 * @param password Password for the keystore
	 * @throws Exception if generation fails
	 */
	void generateCertificate(String keystorePath, String password) throws Exception;
}

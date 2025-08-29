package org.joykabir.ssl.testing;

public class CurlCommandGenerator {

	private final String baseUrl;

	public CurlCommandGenerator(String baseUrl) {
		this.baseUrl = baseUrl;
	}

	public String generateStrictValidationCommand(String endpoint) {
		return String.format("curl -v --connect-timeout 10 %s%s", baseUrl, endpoint);
	}

	public String generateInsecureCommand(String endpoint) {
		return String.format("curl -k -v %s%s", baseUrl, endpoint);
	}

	public String generateVerboseCommand(String endpoint) {
		return String.format("curl -k -v -H 'Accept: application/json' %s%s | jq .", baseUrl, endpoint);
	}

	public String generateCertInfoCommand() {
		return String.format("openssl s_client -connect localhost:9001 -servername localhost < /dev/null 2>/dev/null | openssl x509 -text -noout");
	}

	public String generateSslTestCommand() {
		return String.format("echo | openssl s_client -connect localhost:9001 -servername localhost 2>/dev/null | openssl x509 -noout -dates");
	}

	public String generateCipherSuiteCommand() {
		return String.format("nmap --script ssl-enum-ciphers -p 9001 localhost");
	}

	public String generateSslVersionCommand() {
		return String.format("echo | openssl s_client -connect localhost:9001 -tls1_2 -servername localhost 2>/dev/null | grep Protocol");
	}
}
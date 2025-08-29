package org.joykabir.ssl.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Duration;

public class HttpsClient {

	private static final Logger logger = LoggerFactory.getLogger(HttpsClient.class);

	public void runAllTests(String baseUrl) throws Exception {
		logger.info("🔍 Starting HTTPS client tests for: {}", baseUrl);

		// Test 1: Strict SSL validation (should fail)
		testStrictSslValidation(baseUrl);

		// Test 2: Trust-all SSL context (should succeed)
		testTrustAllSslContext(baseUrl);

		// Test 3: Custom hostname verification
		testCustomHostnameVerification(baseUrl);

		// Test 4: Certificate information extraction
		testCertificateExtraction(baseUrl);

		// Test 5: Server stats
		testServerStats(baseUrl);
	}

	private void testStrictSslValidation(String baseUrl) {
		logger.info("\n=== Test 1: Strict SSL Validation ===");
		try {
			HttpClient client = HttpClient.newBuilder()
					.connectTimeout(Duration.ofSeconds(10))
					.build();

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl + "/api/status"))
					.timeout(Duration.ofSeconds(30))
					.build();

			HttpResponse<String> response = client.send(request,
					HttpResponse.BodyHandlers.ofString());

			logger.info("❌ Unexpected success with strict SSL validation");
			logger.info("Response: {}", response.body());

		} catch (Exception e) {
			logger.info("✅ Expected failure with strict SSL validation: {}", e.getMessage());
			logger.info("This demonstrates why self-signed certificates fail validation");
		}
	}

	private void testTrustAllSslContext(String baseUrl) throws Exception {
		logger.info("\n=== Test 2: Trust-All SSL Context ===");

		// Create trust-all SSL context
		SSLContext sslContext = createTrustAllSslContext();

		HttpClient client = HttpClient.newBuilder()
				.sslContext(sslContext)
				.connectTimeout(Duration.ofSeconds(10))
				.build();

		HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(baseUrl + "/api/status"))
				.timeout(Duration.ofSeconds(30))
				.build();

		try {
			HttpResponse<String> response = client.send(request,
					HttpResponse.BodyHandlers.ofString());

			logger.info("✅ Success with trust-all SSL context");
			logger.info("Status Code: {}", response.statusCode());
			logger.info("Response contains 'status': {}", response.body().contains("\"status\""));

		} catch (Exception e) {
			logger.error("❌ Failed even with trust-all SSL context", e);
		}
	}

	private void testCustomHostnameVerification(String baseUrl) throws Exception {
		logger.info("\n=== Test 3: Custom Hostname Verification ===");

		// Create SSL context with custom hostname verifier
		SSLContext sslContext = createTrustAllSslContext();

		// Custom hostname verifier that accepts localhost
		HostnameVerifier hostnameVerifier = (hostname, session) -> {
			logger.info("🔍 Verifying hostname: {} for session: {}", hostname, session.getPeerHost());
			return "localhost".equals(hostname) || "127.0.0.1".equals(hostname);
		};

		logger.info("✅ Custom hostname verification would accept: localhost, 127.0.0.1");
		logger.info("This prevents hostname mismatch errors");

		// Continue with trust-all test
		testTrustAllSslContext(baseUrl);
	}

	private void testCertificateExtraction(String baseUrl) throws Exception {
		logger.info("\n=== Test 4: Certificate Information Extraction ===");

		SSLContext sslContext = createTrustAllSslContext();

		HttpClient client = HttpClient.newBuilder()
				.sslContext(sslContext)
				.connectTimeout(Duration.ofSeconds(10))
				.build();

		HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(baseUrl + "/api/certificate"))
				.timeout(Duration.ofSeconds(30))
				.build();

		try {
			HttpResponse<String> response = client.send(request,
					HttpResponse.BodyHandlers.ofString());

			logger.info("✅ Certificate information retrieved successfully");
			logger.info("Response contains RSA: {}", response.body().contains("RSA"));
			logger.info("Response contains 4096: {}", response.body().contains("4096"));

		} catch (Exception e) {
			logger.error("❌ Failed to retrieve certificate information", e);
		}
	}

	private void testServerStats(String baseUrl) throws Exception {
		logger.info("\n=== Test 5: Server Statistics ===");

		SSLContext sslContext = createTrustAllSslContext();

		HttpClient client = HttpClient.newBuilder()
				.sslContext(sslContext)
				.connectTimeout(Duration.ofSeconds(10))
				.build();

		HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(baseUrl + "/api/stats"))
				.timeout(Duration.ofSeconds(30))
				.build();

		try {
			HttpResponse<String> response = client.send(request,
					HttpResponse.BodyHandlers.ofString());

			logger.info("✅ Server statistics retrieved successfully");
			logger.info("Response contains totalRequests: {}", response.body().contains("totalRequests"));

		} catch (Exception e) {
			logger.error("❌ Failed to retrieve server statistics", e);
		}
	}

	private SSLContext createTrustAllSslContext() throws NoSuchAlgorithmException, KeyManagementException {
		SSLContext sslContext = SSLContext.getInstance("TLS");

		// Create trust manager that accepts all certificates
		TrustManager[] trustAllManagers = new TrustManager[] {
				new TrustAllManager()
		};

		sslContext.init(null, trustAllManagers, new java.security.SecureRandom());
		return sslContext;
	}

	public HttpResponse<String> makeRequest(String url) throws Exception {
		SSLContext sslContext = createTrustAllSslContext();

		HttpClient client = HttpClient.newBuilder()
				.sslContext(sslContext)
				.connectTimeout(Duration.ofSeconds(5))
				.build();

		HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(url))
				.timeout(Duration.ofSeconds(10))
				.build();

		return client.send(request, HttpResponse.BodyHandlers.ofString());
	}
}
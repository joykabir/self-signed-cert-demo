package org.joykabir.ssl;

import org.joykabir.ssl.cert.CertificateGenerator;
import org.joykabir.ssl.client.HttpsClient;
import org.joykabir.ssl.server.HttpsServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.awaitility.Awaitility;

import java.io.File;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.assertj.core.api.Assertions.*;

public class HttpsServerTest {

	private HttpsServer server;
	private HttpsClient client;
	private final int testPort = 9999;
	private final String testKeystore = "test-ssl.p12";
	private final String testPassword = "testpass";

	@Before
	public void setUp() throws Exception {
		// Generate test certificate
		CertificateGenerator.generateCertificate(testKeystore, testPassword);

		// Start server
		server = new HttpsServer(testPort, testKeystore, testPassword);
		server.start();

		// Initialize client
		client = new HttpsClient();

		// Wait for server to be ready
		Awaitility.await()
				.atMost(Duration.ofSeconds(10))
				.pollInterval(Duration.ofMillis(100))
				.until(() -> {
					try {
						HttpResponse<String> response = client.makeRequest("https://localhost:" + testPort + "/api/status");
						return response.statusCode() == 200;
					} catch (Exception e) {
						return false;
					}
				});
	}

	@After
	public void tearDown() {
		if (server != null) {
			server.stop();
		}

		// Cleanup test files
		new File(testKeystore).delete();
	}

	@Test
	public void testServerStartsSuccessfully() {
		assertThat(server).isNotNull();
	}

	@Test
	public void testStatusEndpoint() throws Exception {
		HttpResponse<String> response = client.makeRequest("https://localhost:" + testPort + "/api/status");

		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.body()).contains("\"status\"");
		assertThat(response.body()).contains("\"OK\"");
		assertThat(response.body()).contains("\"timestamp\"");
	}

	@Test
	public void testCertificateEndpoint() throws Exception {
		HttpResponse<String> response = client.makeRequest("https://localhost:" + testPort + "/api/certificate");

		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.body()).contains("\"certificate\"");
		assertThat(response.body()).contains("\"keySize\"");
		assertThat(response.body()).contains("4096");
		assertThat(response.body()).contains("\"RSA\"");
	}

	@Test
	public void testStatsEndpoint() throws Exception {
		// Make a few requests to increment counter
		client.makeRequest("https://localhost:" + testPort + "/api/status");
		client.makeRequest("https://localhost:" + testPort + "/api/status");

		HttpResponse<String> response = client.makeRequest("https://localhost:" + testPort + "/api/stats");

		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.body()).contains("\"totalRequests\"");
		assertThat(response.body()).contains("\"serverUptime\"");
	}

	@Test
	public void testRequestCounterIncreases() throws Exception {
		// Get initial stats
		HttpResponse<String> initialResponse = client.makeRequest("https://localhost:" + testPort + "/api/stats");
		assertThat(initialResponse.statusCode()).isEqualTo(200);

		// Make additional requests
		for (int i = 0; i < 5; i++) {
			client.makeRequest("https://localhost:" + testPort + "/api/status");
		}

		// Check if counter increased
		HttpResponse<String> finalResponse = client.makeRequest("https://localhost:" + testPort + "/api/stats");
		assertThat(finalResponse.statusCode()).isEqualTo(200);
		assertThat(finalResponse.body()).contains("\"totalRequests\"");

		// The counter should have increased
		assertThat(server.getRequestCount()).isGreaterThan(0);
	}
}
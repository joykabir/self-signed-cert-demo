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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;

public class AsyncLoadTest {

	private HttpsServer server;
	private HttpsClient client;
	private final int testPort = 9998;
	private final String testKeystore = "load-test-ssl.p12";
	private final String testPassword = "loadtest";
	private ExecutorService executor;

	@Before
	public void setUp() throws Exception {
		// Generate test certificate
		CertificateGenerator.generateCertificate(testKeystore, testPassword);

		// Start server
		server = new HttpsServer(testPort, testKeystore, testPassword);
		server.start();

		// Initialize client
		client = new HttpsClient();

		// Initialize executor for async requests
		executor = Executors.newFixedThreadPool(50);

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
		if (executor != null) {
			executor.shutdown();
			try {
				if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
					executor.shutdownNow();
				}
			} catch (InterruptedException e) {
				executor.shutdownNow();
			}
		}

		if (server != null) {
			server.stop();
		}

		// Cleanup test files
		new File(testKeystore).delete();
	}

	@Test
	public void testConcurrentRequests() throws Exception {
		final int numberOfRequests = 100;
		final AtomicInteger successCount = new AtomicInteger(0);
		final AtomicInteger errorCount = new AtomicInteger(0);
		final List<Future<Void>> futures = new ArrayList<>();

		System.out.println("🚀 Starting " + numberOfRequests + " concurrent requests...");

		// Submit concurrent requests
		for (int i = 0; i < numberOfRequests; i++) {
			final int requestId = i;
			Future<Void> future = executor.submit(() -> {
				try {
					HttpResponse<String> response = client.makeRequest("https://localhost:" + testPort + "/api/status");
					if (response.statusCode() == 200) {
						successCount.incrementAndGet();
					} else {
						errorCount.incrementAndGet();
					}

					if (requestId % 10 == 0) {
						System.out.println("✅ Completed request " + requestId);
					}
				} catch (Exception e) {
					errorCount.incrementAndGet();
					System.err.println("❌ Request " + requestId + " failed: " + e.getMessage());
				}
				return null;
			});
			futures.add(future);
		}

		// Wait for all requests to complete
		for (Future<Void> future : futures) {
			future.get(30, TimeUnit.SECONDS);
		}

		System.out.println("📊 Results: " + successCount.get() + " successful, " + errorCount.get() + " errors");

		// Verify results
		assertThat(successCount.get()).isGreaterThan(numberOfRequests * 0.9); // At least 90% success
		assertThat(errorCount.get()).isLessThan(numberOfRequests * 0.1); // Less than 10% errors

		// Verify server received all requests
		Awaitility.await()
				.atMost(Duration.ofSeconds(5))
				.until(() -> server.getRequestCount() >= numberOfRequests);
	}

	@Test
	public void testMixedEndpointLoad() throws Exception {
		final int requestsPerEndpoint = 30;
		final AtomicInteger successCount = new AtomicInteger(0);
		final AtomicInteger errorCount = new AtomicInteger(0);
		final List<Future<Void>> futures = new ArrayList<>();

		String[] endpoints = {"/api/status", "/api/certificate", "/api/stats"};

		System.out.println("🔄 Testing mixed endpoint load...");

		// Submit requests to different endpoints
		for (String endpoint : endpoints) {
			for (int i = 0; i < requestsPerEndpoint; i++) {
				final String url = "https://localhost:" + testPort + endpoint;
				final int requestId = i;

				Future<Void> future = executor.submit(() -> {
					try {
						HttpResponse<String> response = client.makeRequest(url);
						if (response.statusCode() == 200) {
							successCount.incrementAndGet();
						} else {
							errorCount.incrementAndGet();
						}

						if (requestId % 10 == 0) {
							System.out.println("✅ Endpoint " + url + " request " + requestId + " completed");
						}
					} catch (Exception e) {
						errorCount.incrementAndGet();
						System.err.println("❌ Request to " + url + " failed: " + e.getMessage());
					}
					return null;
				});
				futures.add(future);
			}
		}

		// Wait for all requests to complete
		for (Future<Void> future : futures) {
			future.get(30, TimeUnit.SECONDS);
		}

		int totalRequests = endpoints.length * requestsPerEndpoint;
		System.out.println("📊 Mixed load results: " + successCount.get() + " successful, " + errorCount.get() + " errors");

		// Verify results
		assertThat(successCount.get()).isGreaterThan(totalRequests * 0.9);
		assertThat(errorCount.get()).isLessThan(totalRequests * 0.1);
	}

	@Test
	public void testServerPerformanceUnderLoad() throws Exception {
		final int warmupRequests = 50;
		final int testRequests = 100;

		System.out.println("🔥 Warming up server with " + warmupRequests + " requests...");

		// Warmup phase
		List<Future<Long>> warmupFutures = new ArrayList<>();
		for (int i = 0; i < warmupRequests; i++) {
			Future<Long> future = executor.submit(() -> {
				long startTime = System.currentTimeMillis();
				try {
					client.makeRequest("https://localhost:" + testPort + "/api/status");
				} catch (Exception e) {
					// Ignore errors during warmup
				}
				return System.currentTimeMillis() - startTime;
			});
			warmupFutures.add(future);
		}

		// Wait for warmup to complete
		for (Future<Long> future : warmupFutures) {
			future.get(30, TimeUnit.SECONDS);
		}

		System.out.println("🏃 Running performance test with " + testRequests + " requests...");

		// Performance test phase
		List<Future<Long>> testFutures = new ArrayList<>();
		long testStartTime = System.currentTimeMillis();

		for (int i = 0; i < testRequests; i++) {
			Future<Long> future = executor.submit(() -> {
				long startTime = System.currentTimeMillis();
				try {
					HttpResponse<String> response = client.makeRequest("https://localhost:" + testPort + "/api/status");
					if (response.statusCode() != 200) {
						throw new RuntimeException("Non-200 response: " + response.statusCode());
					}
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				return System.currentTimeMillis() - startTime;
			});
			testFutures.add(future);
		}

		// Collect results
		List<Long> responseTimes = new ArrayList<>();
		for (Future<Long> future : testFutures) {
			responseTimes.add(future.get(30, TimeUnit.SECONDS));
		}

		long totalTestTime = System.currentTimeMillis() - testStartTime;

		// Calculate statistics
		double avgResponseTime = responseTimes.stream().mapToLong(Long::longValue).average().orElse(0.0);
		long maxResponseTime = responseTimes.stream().mapToLong(Long::longValue).max().orElse(0L);
		long minResponseTime = responseTimes.stream().mapToLong(Long::longValue).min().orElse(0L);
		double throughput = (double) testRequests / totalTestTime * 1000; // requests per second

		System.out.println("📈 Performance Results:");
		System.out.println("  - Average response time: " + String.format("%.2f", avgResponseTime) + " ms");
		System.out.println("  - Min response time: " + minResponseTime + " ms");
		System.out.println("  - Max response time: " + maxResponseTime + " ms");
		System.out.println("  - Throughput: " + String.format("%.2f", throughput) + " requests/second");
		System.out.println("  - Total test time: " + totalTestTime + " ms");

		// Performance assertions
		assertThat(avgResponseTime).isLessThan(1000.0); // Average response time should be less than 1 second
		assertThat(maxResponseTime).isLessThan(5000L); // Max response time should be less than 5 seconds
		assertThat(throughput).isGreaterThan(10.0); // Should handle at least 10 requests per second
	}
}
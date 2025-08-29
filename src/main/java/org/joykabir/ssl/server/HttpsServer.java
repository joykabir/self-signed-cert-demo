package org.joykabir.ssl.server;

import org.joykabir.ssl.cert.CertificateInfo;
import org.joykabir.ssl.config.AppConfig;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

public class HttpsServer {

	private static final Logger logger = LoggerFactory.getLogger(HttpsServer.class);
	private final Gson gson;
	private HttpsServer httpsServer;
	private final int port;
	private final String keystorePath;
	private final String password;
	private SSLContext sslContext;
	private final AtomicLong requestCounter = new AtomicLong(0);
	private final AppConfig config;

	public HttpsServer(int port, String keystorePath, String password) {
		this.port = port;
		this.keystorePath = keystorePath;
		this.password = password;
		this.config = AppConfig.getInstance();
		this.gson = new GsonBuilder()
				.setPrettyPrinting()
				.excludeFieldsWithoutExposeAnnotation()
				.create();
	}

	public void start() throws Exception {
		// Load keystore and create SSL context
		this.sslContext = createSslContext();

		// Create HTTPS server
		httpsServer = HttpsServer.create(new InetSocketAddress(port), 0);
		httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
			@Override
			public void configure(HttpsParameters params) {
				try {
					SSLEngine engine = sslContext.createSSLEngine();
					params.setSSLParameters(engine.getSSLParameters());
					params.setProtocols(config.getSslProtocols());
					params.setCipherSuites(engine.getSSLParameters().getCipherSuites());
				} catch (Exception e) {
					logger.error("Failed to configure HTTPS parameters", e);
				}
			}
		});

		// Add endpoints
		httpsServer.createContext("/api/status", new StatusHandler());
		httpsServer.createContext("/api/certificate", new CertificateHandler());
		httpsServer.createContext("/api/stats", new StatsHandler());
		httpsServer.createContext("/", new RootHandler());

		// Set executor
		httpsServer.setExecutor(Executors.newFixedThreadPool(20));

		// Start server
		httpsServer.start();
		logger.info("🚀 HTTPS Server started on https://localhost:{}", port);
		logger.info("📊 Using GSON for JSON serialization");
		logger.info("🔒 SSL Protocols: {}", String.join(", ", config.getSslProtocols()));
	}

	public void stop() {
		if (httpsServer != null) {
			httpsServer.stop(0);
			logger.info("🛑 HTTPS Server stopped");
		}
	}

	private SSLContext createSslContext() throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(keystorePath)) {
			keyStore.load(fis, password.toCharArray());
		}

		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, password.toCharArray());

		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kmf.getKeyManagers(), null, null);

		return sslContext;
	}

	private class StatusHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			long requestId = requestCounter.incrementAndGet();

			if (config.isRequestLoggingEnabled()) {
				logger.debug("📥 Processing status request #{} from {}",
						requestId, exchange.getRemoteAddress());
			}

			try {
				Map<String, Object> status = new HashMap<>();
				status.put("status", "OK");
				status.put("timestamp", LocalDateTime.now().toString());
				status.put("server", "Self-Signed Certificate Demo HTTPS Server");
				status.put("port", port);
				status.put("protocol", exchange.getProtocol());
				status.put("method", exchange.getRequestMethod());
				status.put("uri", exchange.getRequestURI().toString());
				status.put("requestId", requestId);
				status.put("totalRequests", requestCounter.get());

				// SSL Session information
				if (exchange instanceof com.sun.net.httpserver.HttpsExchange httpsExchange) {
					SSLSession sslSession = httpsExchange.getSSLSession();
					if (config.isSslSessionLoggingEnabled()) {
						Map<String, Object> sslInfo = new HashMap<>();
						sslInfo.put("protocol", sslSession.getProtocol());
						sslInfo.put("cipherSuite", sslSession.getCipherSuite());
						sslInfo.put("peerHost", sslSession.getPeerHost());
						sslInfo.put("peerPort", sslSession.getPeerPort());
						sslInfo.put("creationTime", sslSession.getCreationTime());
						sslInfo.put("lastAccessedTime", sslSession.getLastAccessedTime());
						sslInfo.put("sessionId", bytesToHex(sslSession.getId()));
						status.put("sslSession", sslInfo);
					}
				}

				sendJsonResponse(exchange, 200, status);
			} catch (Exception e) {
				logger.error("Error in status handler", e);
				sendErrorResponse(exchange, 500, "Internal Server Error");
			}
		}
	}

	private class CertificateHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			long requestId = requestCounter.incrementAndGet();

			if (config.isRequestLoggingEnabled()) {
				logger.debug("📥 Processing certificate request #{} from {}",
						requestId, exchange.getRemoteAddress());
			}

			try {
				Map<String, Object> response = new HashMap<>();
				response.put("requestId", requestId);

				// Get certificate from keystore
				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				try (FileInputStream fis = new FileInputStream(keystorePath)) {
					keyStore.load(fis, password.toCharArray());
				}

				X509Certificate cert = (X509Certificate) keyStore.getCertificate("ssl-demo");
				CertificateInfo certInfo = CertificateInfo.from(cert);
				response.put("certificate", certInfo);

				// SSL Session information
				if (exchange instanceof com.sun.net.httpserver.HttpsExchange httpsExchange && config.isSslSessionLoggingEnabled()) {
					SSLSession sslSession = httpsExchange.getSSLSession();
					Map<String, Object> sessionInfo = new HashMap<>();
					sessionInfo.put("protocol", sslSession.getProtocol());
					sessionInfo.put("cipherSuite", sslSession.getCipherSuite());
					sessionInfo.put("keySize", sslSession.getPacketBufferSize());
					sessionInfo.put("sessionId", bytesToHex(sslSession.getId()));
					sessionInfo.put("creationTime", sslSession.getCreationTime());
					sessionInfo.put("lastAccessedTime", sslSession.getLastAccessedTime());

					// Peer certificate chain
					try {
						java.security.cert.Certificate[] peerCerts = sslSession.getPeerCertificates();
						sessionInfo.put("peerCertificateCount", peerCerts.length);
					} catch (SSLPeerUnverifiedException e) {
						sessionInfo.put("peerCertificateCount", 0);
					}

					response.put("sslSession", sessionInfo);
				}

				sendJsonResponse(exchange, 200, response);
			} catch (Exception e) {
				logger.error("Error in certificate handler", e);
				sendErrorResponse(exchange, 500, "Internal Server Error");
			}
		}
	}

	private class StatsHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			try {
				Map<String, Object> stats = new HashMap<>();
				stats.put("totalRequests", requestCounter.get());
				stats.put("serverUptime", System.currentTimeMillis());
				stats.put("port", port);
				stats.put("keystorePath", keystorePath);
				stats.put("timestamp", LocalDateTime.now().toString());

				sendJsonResponse(exchange, 200, stats);
			} catch (Exception e) {
				logger.error("Error in stats handler", e);
				sendErrorResponse(exchange, 500, "Internal Server Error");
			}
		}
	}

	private class RootHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			String html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Self-Signed Certificate Demo</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .endpoint { margin: 20px 0; padding: 15px; background: #e8f4f8; border-radius: 5px; }
                        .code { background: #2d2d2d; color: #f8f8f2; padding: 10px; font-family: monospace; border-radius: 3px; overflow-x: auto; }
                        .success { color: #27ae60; }
                        .warning { color: #f39c12; }
                        h1 { color: #2c3e50; }
                        h2 { color: #34495e; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔒 Self-Signed Certificate Demo Server</h1>
                        <p class="success">Welcome to the HTTPS server running on port %d with GSON JSON processing!</p>

                        <h2>📡 Available Endpoints:</h2>

                        <div class="endpoint">
                            <h3>GET /api/status</h3>
                            <p>Returns server status and SSL session information</p>
                            <div class="code">curl -k https://localhost:%d/api/status</div>
                        </div>

                        <div class="endpoint">
                            <h3>GET /api/certificate</h3>
                            <p>Returns detailed certificate and SSL session information</p>
                            <div class="code">curl -k https://localhost:%d/api/certificate</div>
                        </div>

                        <div class="endpoint">
                            <h3>GET /api/stats</h3>
                            <p>Returns server statistics and request counters</p>
                            <div class="code">curl -k https://localhost:%d/api/stats</div>
                        </div>

                        <h2>🔑 Certificate Information:</h2>
                        <p>This server uses a self-signed RSA 4096-bit certificate with 3-year validity.</p>
                        <p>The certificate includes Subject Alternative Names (SAN) for localhost.</p>

                        <h2>🧪 Testing:</h2>
                        <p class="warning">Use the <code>-k</code> flag with curl to bypass certificate verification for testing.</p>
                        <p>For load testing, run the included <code>run-demo.sh</code> script.</p>

                        <h2>💾 JSON Processing:</h2>
                        <p>This application uses Google GSON for JSON serialization with pretty printing enabled.</p>
                    </div>
                </body>
                </html>
                """.formatted(port, port, port, port);

			exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
			exchange.sendResponseHeaders(200, html.getBytes().length);
			try (OutputStream os = exchange.getResponseBody()) {
				os.write(html.getBytes());
			}
		}
	}

	private void sendJsonResponse(HttpExchange exchange, int statusCode, Object data) throws IOException {
		String json = gson.toJson(data);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
		exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
		exchange.sendResponseHeaders(statusCode, json.getBytes().length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(json.getBytes());
		}
	}

	private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
		Map<String, Object> error = new HashMap<>();
		error.put("error", message);
		error.put("statusCode", statusCode);
		error.put("timestamp", LocalDateTime.now().toString());
		sendJsonResponse(exchange, statusCode, error);
	}

	private String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}

	public long getRequestCount() {
		return requestCounter.get();
	}
}
package org.joykabir.ssl.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class AppConfig {

	private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);
	private static final String DEFAULT_CONFIG_FILE = "application.properties";
	private final Properties properties;

	private static AppConfig instance;

	private AppConfig() {
		this.properties = new Properties();
		loadConfiguration();
	}

	public static AppConfig getInstance() {
		if (instance == null) {
			synchronized (AppConfig.class) {
				if (instance == null) {
					instance = new AppConfig();
				}
			}
		}
		return instance;
	}

	private void loadConfiguration() {
		// Load default configuration from classpath
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(DEFAULT_CONFIG_FILE)) {
			if (is != null) {
				properties.load(is);
				logger.info("✅ Loaded default configuration from classpath");
			} else {
				logger.warn("⚠️ Default configuration file not found in classpath: {}", DEFAULT_CONFIG_FILE);
			}
		} catch (IOException e) {
			logger.warn("⚠️ Failed to load default configuration: {}", e.getMessage());
		}

		// Override with external configuration if exists
		Path externalConfig = Path.of("application.properties");
		if (Files.exists(externalConfig)) {
			try (InputStream is = Files.newInputStream(externalConfig)) {
				Properties externalProps = new Properties();
				externalProps.load(is);
				properties.putAll(externalProps);
				logger.info("✅ Loaded external configuration from: {}", externalConfig.toAbsolutePath());
			} catch (IOException e) {
				logger.warn("⚠️ Failed to load external configuration: {}", e.getMessage());
			}
		}

		// Override with system properties
		for (String key : properties.stringPropertyNames()) {
			String systemValue = System.getProperty(key);
			if (systemValue != null) {
				properties.setProperty(key, systemValue);
				logger.debug("🔧 Overriding configuration from system property: {} = {}", key, systemValue);
			}
		}

		logger.info("📋 Configuration loaded with {} properties", properties.size());
	}

	public String getString(String key, String defaultValue) {
		return properties.getProperty(key, defaultValue);
	}

	public int getInt(String key, int defaultValue) {
		String value = properties.getProperty(key);
		if (value != null) {
			try {
				return Integer.parseInt(value.trim());
			} catch (NumberFormatException e) {
				logger.warn("⚠️ Invalid integer value for key '{}': {}. Using default: {}", key, value, defaultValue);
			}
		}
		return defaultValue;
	}

	public boolean getBoolean(String key, boolean defaultValue) {
		String value = properties.getProperty(key);
		if (value != null) {
			return Boolean.parseBoolean(value.trim());
		}
		return defaultValue;
	}

	public String[] getStringArray(String key, String[] defaultValue) {
		String value = properties.getProperty(key);
		if (value != null && !value.trim().isEmpty()) {
			return value.split(",");
		}
		return defaultValue;
	}

	// Convenience methods for application-specific configuration
	public int getServerPort() {
		return getInt("app.server.port", 9001);
	}

	public String getKeystorePath() {
		return getString("app.server.keystore.path", "ssl-demo.p12");
	}

	public String getKeystorePassword() {
		return getString("app.server.keystore.password", "changeit");
	}

	public int getCertificateKeySize() {
		return getInt("app.cert.keysize", 4096);
	}

	public int getCertificateValidityYears() {
		return getInt("app.cert.validity.years", 3);
	}

	public String getCertificateAlgorithm() {
		return getString("app.cert.algorithm", "RSA");
	}

	public String getSignatureAlgorithm() {
		return getString("app.cert.signature.algorithm", "SHA256withRSA");
	}

	public String[] getSslProtocols() {
		return getStringArray("app.ssl.protocols", new String[]{"TLSv1.3", "TLSv1.2"});
	}

	public boolean isRequestLoggingEnabled() {
		return getBoolean("app.logging.request.details", true);
	}

	public boolean isSslSessionLoggingEnabled() {
		return getBoolean("app.logging.ssl.session.details", true);
	}

	public int getDefaultLoadTestRequests() {
		return getInt("app.test.load.default.requests", 100);
	}

	public int getDefaultLoadTestConcurrency() {
		return getInt("app.test.load.default.concurrency", 10);
	}

	public int getTestTimeoutSeconds() {
		return getInt("app.test.timeout.seconds", 30);
	}

	public void printConfiguration() {
		logger.info("📋 Current Configuration:");
		logger.info("  🌐 Server Port: {}", getServerPort());
		logger.info("  🔑 Keystore Path: {}", getKeystorePath());
		logger.info("  🔐 Certificate Key Size: {} bits", getCertificateKeySize());
		logger.info("  📅 Certificate Validity: {} years", getCertificateValidityYears());
		logger.info("  🔒 SSL Protocols: {}", String.join(", ", getSslProtocols()));
		logger.info("  📝 Request Logging: {}", isRequestLoggingEnabled() ? "enabled" : "disabled");
		logger.info("  🔍 SSL Session Logging: {}", isSslSessionLoggingEnabled() ? "enabled" : "disabled");
	}
}
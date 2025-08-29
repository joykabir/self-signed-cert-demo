package org.joykabir.ssl.cert;

import org.joykabir.ssl.config.AppConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.DNSName;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.IPAddressName;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import javax.security.auth.x500.X500Principal;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class CertificateGenerator {

	private static final Logger logger = LoggerFactory.getLogger(CertificateGenerator.class);

	public static void generateCertificate(String keystorePath, String password)
			throws Exception {

		AppConfig config = AppConfig.getInstance();

		logger.info("🔑 Starting certificate generation...");
		logger.info("📊 Algorithm: {}, Key Size: {} bits, Validity: {} years",
				config.getCertificateAlgorithm(),
				config.getCertificateKeySize(),
				config.getCertificateValidityYears());

		// Generate RSA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(config.getCertificateAlgorithm());
		keyPairGenerator.initialize(config.getCertificateKeySize(), new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Certificate validity
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusYears(config.getCertificateValidityYears());

		logger.info("📅 Certificate validity period: {} to {}", notBefore, notAfter);

		// Create certificate
		X509Certificate certificate = createSelfSignedCertificate(
				keyPair,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()),
				config.getSignatureAlgorithm()
		);

		// Create keystore
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, null);

		// Add private key and certificate
		keyStore.setKeyEntry("ssl-demo", keyPair.getPrivate(),
				password.toCharArray(), new Certificate[]{certificate});

		// Save keystore
		try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
			keyStore.store(fos, password.toCharArray());
		}

		logger.info("✅ Generated {} {}-bit self-signed certificate",
				config.getCertificateAlgorithm(), config.getCertificateKeySize());
		logger.info("✅ Subject: {}", certificate.getSubjectX500Principal().getName());
		logger.info("✅ Keystore saved to: {}", keystorePath);
		logger.info("✅ Certificate includes SAN for localhost");
	}

	private static X509Certificate createSelfSignedCertificate(
			KeyPair keyPair, Date notBefore, Date notAfter, String signatureAlgorithm)
			throws CertificateException, NoSuchAlgorithmException,
			InvalidKeyException, SignatureException, NoSuchProviderException, IOException {

		// Certificate info
		X500Principal subject = new X500Principal(
				"CN=Self-Signed Cert Demo Server, OU=Development, O=JoyKabir SSL Demo, C=US");

		BigInteger serialNumber = new BigInteger(64, new SecureRandom());

		// Create certificate info
		X509CertInfo certInfo = new X509CertInfo();
		certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
		certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(
				AlgorithmId.get(signatureAlgorithm)));
		certInfo.set(X509CertInfo.SUBJECT, subject);
		certInfo.set(X509CertInfo.ISSUER, subject); // Self-signed
		certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
		certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(notBefore, notAfter));

		// Add extensions
		CertificateExtensions extensions = new CertificateExtensions();

		// Subject Alternative Names (SAN) for localhost
		GeneralNames sanNames = new GeneralNames();
		sanNames.add(new GeneralName(new DNSName("localhost")));
		sanNames.add(new GeneralName(new IPAddressName("127.0.0.1")));
		sanNames.add(new GeneralName(new IPAddressName("::1"))); // IPv6 localhost

		SubjectAlternativeNameExtension sanExtension =
				new SubjectAlternativeNameExtension(sanNames);
		extensions.set(SubjectAlternativeNameExtension.NAME, sanExtension);

		// Key Usage
		KeyUsageExtension keyUsage = new KeyUsageExtension();
		keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
		keyUsage.set(KeyUsageExtension.KEY_ENCIPHERMENT, true);
		extensions.set(KeyUsageExtension.NAME, keyUsage);

		// Extended Key Usage
		ExtendedKeyUsageExtension extKeyUsage = new ExtendedKeyUsageExtension();
		extKeyUsage.set(ExtendedKeyUsageExtension.SERVER_AUTH, true);
		extKeyUsage.set(ExtendedKeyUsageExtension.CLIENT_AUTH, true);
		extensions.set(ExtendedKeyUsageExtension.NAME, extKeyUsage);

		// Basic Constraints
		BasicConstraintsExtension basicConstraints =
				new BasicConstraintsExtension(true, false, -1);
		extensions.set(BasicConstraintsExtension.NAME, basicConstraints);

		certInfo.set(X509CertInfo.EXTENSIONS, extensions);

		// Create and sign certificate
		X509CertImpl certificate = new X509CertImpl(certInfo);
		certificate.sign(keyPair.getPrivate(), signatureAlgorithm);

		// Update certificate with signature
		certInfo = (X509CertInfo) certificate.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
		certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM,
				new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid));
		certificate = new X509CertImpl(certInfo);
		certificate.sign(keyPair.getPrivate(), signatureAlgorithm);

		return certificate;
	}
}
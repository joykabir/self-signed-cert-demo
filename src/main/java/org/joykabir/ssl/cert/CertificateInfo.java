package org.joykabir.ssl.cert;

import com.google.gson.annotations.SerializedName;
import com.google.gson.annotations.Expose;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Collection;
import java.util.stream.Collectors;

public class CertificateInfo {

	@Expose
	@SerializedName("subject")
	private String subject;

	@Expose
	@SerializedName("issuer")
	private String issuer;

	@Expose
	@SerializedName("serialNumber")
	private String serialNumber;

	@Expose
	@SerializedName("notBefore")
	private String notBefore;

	@Expose
	@SerializedName("notAfter")
	private String notAfter;

	@Expose
	@SerializedName("signatureAlgorithm")
	private String signatureAlgorithm;

	@Expose
	@SerializedName("publicKeyAlgorithm")
	private String publicKeyAlgorithm;

	@Expose
	@SerializedName("keySize")
	private int keySize;

	@Expose
	@SerializedName("subjectAlternativeNames")
	private List<String> subjectAlternativeNames;

	@Expose
	@SerializedName("fingerprint")
	private String fingerprint;

	@Expose
	@SerializedName("version")
	private int version;

	@Expose
	@SerializedName("validityPeriodDays")
	private long validityPeriodDays;

	@Expose
	@SerializedName("daysUntilExpiry")
	private long daysUntilExpiry;

	@Expose
	@SerializedName("isExpired")
	private boolean isExpired;

	public static CertificateInfo from(X509Certificate cert) throws Exception {
		CertificateInfo info = new CertificateInfo();

		info.subject = cert.getSubjectX500Principal().getName();
		info.issuer = cert.getIssuerX500Principal().getName();
		info.serialNumber = cert.getSerialNumber().toString(16).toUpperCase();

		LocalDateTime notBeforeTime = LocalDateTime.ofInstant(cert.getNotBefore().toInstant(), ZoneId.systemDefault());
		LocalDateTime notAfterTime = LocalDateTime.ofInstant(cert.getNotAfter().toInstant(), ZoneId.systemDefault());
		LocalDateTime now = LocalDateTime.now();

		info.notBefore = notBeforeTime.toString();
		info.notAfter = notAfterTime.toString();
		info.signatureAlgorithm = cert.getSigAlgName();
		info.publicKeyAlgorithm = cert.getPublicKey().getAlgorithm();
		info.version = cert.getVersion();

		// Calculate validity period and expiry
		info.validityPeriodDays = java.time.Duration.between(notBeforeTime, notAfterTime).toDays();
		info.daysUntilExpiry = java.time.Duration.between(now, notAfterTime).toDays();
		info.isExpired = now.isAfter(notAfterTime);

		// Calculate key size for RSA
		if ("RSA".equals(cert.getPublicKey().getAlgorithm())) {
			info.keySize = ((java.security.interfaces.RSAPublicKey) cert.getPublicKey())
					.getModulus().bitLength();
		}

		// Get Subject Alternative Names
		Collection<List<?>> sanCollection = cert.getSubjectAlternativeNames();
		if (sanCollection != null) {
			info.subjectAlternativeNames = sanCollection.stream()
					.map(san -> (String) san.get(1))
					.collect(Collectors.toList());
		}

		// Calculate fingerprint (SHA-256)
		java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(cert.getEncoded());
		StringBuilder sb = new StringBuilder();
		for (byte b : digest) {
			sb.append(String.format("%02X:", b));
		}
		info.fingerprint = sb.toString().replaceAll(":$", "");

		return info;
	}

	// Getters and setters
	public String getSubject() { return subject; }
	public void setSubject(String subject) { this.subject = subject; }

	public String getIssuer() { return issuer; }
	public void setIssuer(String issuer) { this.issuer = issuer; }

	public String getSerialNumber() { return serialNumber; }
	public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

	public String getNotBefore() { return notBefore; }
	public void setNotBefore(String notBefore) { this.notBefore = notBefore; }

	public String getNotAfter() { return notAfter; }
	public void setNotAfter(String notAfter) { this.notAfter = notAfter; }

	public String getSignatureAlgorithm() { return signatureAlgorithm; }
	public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }

	public String getPublicKeyAlgorithm() { return publicKeyAlgorithm; }
	public void setPublicKeyAlgorithm(String publicKeyAlgorithm) { this.publicKeyAlgorithm = publicKeyAlgorithm; }

	public int getKeySize() { return keySize; }
	public void setKeySize(int keySize) { this.keySize = keySize; }

	public List<String> getSubjectAlternativeNames() { return subjectAlternativeNames; }
	public void setSubjectAlternativeNames(List<String> subjectAlternativeNames) {
		this.subjectAlternativeNames = subjectAlternativeNames;
	}

	public String getFingerprint() { return fingerprint; }
	public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

	public int getVersion() { return version; }
	public void setVersion(int version) { this.version = version; }

	public long getValidityPeriodDays() { return validityPeriodDays; }
	public void setValidityPeriodDays(long validityPeriodDays) { this.validityPeriodDays = validityPeriodDays; }

	public long getDaysUntilExpiry() { return daysUntilExpiry; }
	public void setDaysUntilExpiry(long daysUntilExpiry) { this.daysUntilExpiry = daysUntilExpiry; }

	public boolean isExpired() { return isExpired; }
	public void setExpired(boolean expired) { isExpired = expired; }
}
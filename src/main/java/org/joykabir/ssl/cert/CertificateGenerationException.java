package org.joykabir.ssl.cert;

import java.util.ArrayList;
import java.util.List;

/**
 * Custom exception for certificate generation failures.
 * Provides detailed information about all attempted methods and their failures.
 */
public class CertificateGenerationException extends Exception {

	private final List<GenerationAttempt> failedAttempts;

	public CertificateGenerationException(String message, List<GenerationAttempt> failedAttempts) {
		super(message);
		this.failedAttempts = new ArrayList<GenerationAttempt>(failedAttempts);
	}

	public CertificateGenerationException(String message, Throwable cause, List<GenerationAttempt> failedAttempts) {
		super(message, cause);
		this.failedAttempts = new ArrayList<GenerationAttempt>(failedAttempts);
	}

	public List<GenerationAttempt> getFailedAttempts() {
		return new ArrayList<>(failedAttempts);
	}

	@Override
	public String getMessage() {
		StringBuilder sb = new StringBuilder(super.getMessage());
		sb.append("\n\nFailed attempts:");

		for (int i = 0; i < failedAttempts.size(); i++) {
			GenerationAttempt attempt = failedAttempts.get(i);
			sb.append(String.format("\n  %d. %s: %s",
					i + 1, attempt.getMethodName(), attempt.getErrorMessage()));

			if (attempt.getCause() != null) {
				sb.append(String.format(" (Cause: %s)", attempt.getCause().getClass().getSimpleName()));
			}
		}

		return sb.toString();
	}

	/**
	 * Represents a single certificate generation attempt
	 */
	public static class GenerationAttempt {
		private final String methodName;
		private final String errorMessage;
		private final Throwable cause;
		private final long durationMs;

		public GenerationAttempt(String methodName, String errorMessage, Throwable cause, long durationMs) {
			this.methodName = methodName;
			this.errorMessage = errorMessage;
			this.cause = cause;
			this.durationMs = durationMs;
		}

		public String getMethodName() {
			return methodName;
		}

		public String getErrorMessage() {
			return errorMessage;
		}

		public Throwable getCause() {
			return cause;
		}

		public long getDurationMs() {
			return durationMs;
		}

		@Override
		public String toString() {
			return String.format("%s (took %dms): %s", methodName, durationMs, errorMessage);
		}
	}
}
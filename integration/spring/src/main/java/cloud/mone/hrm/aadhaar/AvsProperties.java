package cloud.mone.hrm.aadhaar;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * AVS connection settings — Step 10.
 *
 * <pre>{@code
 * avs:
 *   base-url: https://avs.internal.m-one.cloud
 *   tenant-id: m-one-prod
 *   secret: ${AVS_TENANT_SECRET}          # NEVER inline
 *   callback-secret: ${AVS_CALLBACK_SECRET}
 *   connect-timeout: 5s
 *   read-timeout: 30s
 * }</pre>
 *
 * <p><b>⛔ Secrets come from the environment, never from application.yml.</b> A
 * committed secret is a permanent one — it lives in every clone, every CI cache
 * and every fork of the repository, and rotating it does not remove it from
 * history.
 */
@ConfigurationProperties(prefix = "avs")
public record AvsProperties(
        String baseUrl,
        String tenantId,
        String secret,
        String callbackSecret,
        Duration connectTimeout,
        Duration readTimeout) {

    /** A 256-bit key as hex is 64 characters. Shorter means human-chosen. */
    private static final int MIN_SECRET_LENGTH = 32;

    public AvsProperties {
        connectTimeout = connectTimeout == null ? Duration.ofSeconds(5) : connectTimeout;
        readTimeout = readTimeout == null ? Duration.ofSeconds(30) : readTimeout;
    }

    /**
     * ⛔ Refuse to start rather than run with a weak or missing key.
     *
     * <p>A service that boots with {@code changeme} as its signing secret looks
     * perfectly healthy right up until somebody tries it. Failing at startup is
     * loud, immediate, and happens in front of whoever is deploying.
     */
    @PostConstruct
    void validate() {
        require(baseUrl, "avs.base-url");
        require(tenantId, "avs.tenant-id");
        requireStrong(secret, "avs.secret");
        requireStrong(callbackSecret, "avs.callback-secret");

        if (baseUrl.startsWith("http://") && !baseUrl.contains("localhost")) {
            throw new IllegalStateException(
                    "avs.base-url uses plain HTTP. Aadhaar images would cross the "
                            + "network unencrypted. Use https, or localhost for development.");
        }
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is not configured");
        }
    }

    private static void requireStrong(String value, String name) {
        require(value, name);
        if (value.length() < MIN_SECRET_LENGTH) {
            throw new IllegalStateException(
                    name + " is only " + value.length() + " characters; minimum is "
                            + MIN_SECRET_LENGTH + ". Generate one with: openssl rand -hex 32");
        }
        String lower = value.toLowerCase();
        if (lower.contains("changeme") || lower.equals("secret") || lower.contains("placeholder")) {
            throw new IllegalStateException(name + " is still a placeholder value");
        }
    }
}

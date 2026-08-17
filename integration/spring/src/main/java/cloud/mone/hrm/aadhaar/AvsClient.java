package cloud.mone.hrm.aadhaar;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Submits Aadhaar images to AVS for verification — Step 10.
 *
 * <p>Spring Boot 3 / Java 17. Uses {@link HttpClient} from the JDK rather than
 * RestTemplate or RestClient, because the request body must be assembled and
 * <b>signed as exact bytes</b>; a higher-level client that re-encodes the
 * multipart body would invalidate the signature.
 *
 * <h2>⛔ THIS METHOD RETURNS A JOB ID, NOT A VERDICT</h2>
 *
 * <p>Verification takes 3–12 seconds. Blocking an HTTP worker thread for that
 * long means a few concurrent uploads exhaust the pool and the whole HRM stops
 * responding. AVS answers {@code 202} immediately and calls
 * {@link AvsCallbackController} when it is done.
 *
 * <p>If you find yourself wanting to wait here for the verdict, that is the
 * shape of the problem telling you the UI should poll instead.
 */
@Component
public class AvsClient {

    private static final Logger log = LoggerFactory.getLogger(AvsClient.class);

    private final AvsProperties properties;
    private final HttpClient http;

    public AvsClient(AvsProperties properties) {
        this.properties = properties;
        this.http = HttpClient.newBuilder()
                .connectTimeout(properties.connectTimeout())
                // ⚠ Redirects OFF. A 302 would resend the signed body to a host
                //    we never authenticated, carrying an employee's Aadhaar.
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** Outcome of submitting a document. */
    public sealed interface Submission {
        /** Accepted. Await the callback for the verdict. */
        record Accepted(String jobId, boolean alreadyQueued) implements Submission {}

        /** AVS is up but cannot verify — usually an empty trust store. Retry. */
        record Unavailable(String reason) implements Submission {}

        /** Our request was wrong: bad signature, clock skew, malformed. Do NOT retry blindly. */
        record Rejected(int status, String reason) implements Submission {}
    }

    /**
     * Submit both faces of a card.
     *
     * <p><b>Both faces are required</b> — CONTRACTS.md §11. The UIDAI signature
     * covers the QR payload only, never the printed card, so a single image
     * cannot be a complete document. The QR may be on either face; do not assume
     * it is on the back.
     *
     * @param requestId trace id to correlate HRM and AVS logs. Pass the one from
     *     the inbound HRM request so a single id spans both systems.
     */
    public Submission submit(
            String jobId, byte[] frontImage, byte[] backImage, String requestId) {

        String boundary = "avs-" + UUID.randomUUID().toString().replace("-", "");
        byte[] body = multipartBody(boundary, jobId, frontImage, backImage);

        // ★ Sign exactly the bytes that go on the wire. Building the body first
        //   and signing it second is the only order that can be correct.
        AvsSignature.Headers signed =
                AvsSignature.sign(properties.secret(), properties.tenantId(), body);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(properties.baseUrl() + "/v1/verify/upload"))
                .timeout(properties.readTimeout())
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .header(AvsSignature.HEADER_TENANT, signed.tenant())
                .header(AvsSignature.HEADER_SIGNATURE, signed.signature())
                .header(AvsSignature.HEADER_TIMESTAMP, signed.timestamp())
                .header(AvsSignature.HEADER_NONCE, signed.nonce())
                .header("X-Request-ID", requestId == null ? jobId : requestId)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();

        try {
            HttpResponse<String> response =
                    http.send(request, HttpResponse.BodyHandlers.ofString());

            return switch (response.statusCode()) {
                case 202 -> accepted(response.body(), jobId);
                case 401 -> {
                    // Our signature was refused. Almost always a wrong secret or
                    // a clock more than five minutes out. Retrying will not help.
                    log.error("avs.submit.unauthorised jobId={} — check avs.secret and NTP", jobId);
                    yield new Submission.Rejected(401, "authentication failed");
                }
                case 503 -> {
                    // AVS is running but not ready — typically no usable UIDAI
                    // certificate. Transient from our side.
                    log.warn("avs.submit.unavailable jobId={}", jobId);
                    yield new Submission.Unavailable("service not ready");
                }
                default -> {
                    log.error(
                            "avs.submit.failed jobId={} status={} body={}",
                            jobId, response.statusCode(), truncate(response.body()));
                    yield new Submission.Rejected(response.statusCode(), truncate(response.body()));
                }
            };
        } catch (IOException e) {
            log.warn("avs.submit.io jobId={}", jobId, e);
            return new Submission.Unavailable(e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Submission.Unavailable("interrupted");
        }
    }

    private Submission accepted(String body, String jobId) {
        // Parsed by hand to avoid a Jackson dependency in the client itself.
        boolean alreadyQueued = body.contains("\"already_queued\":true");
        log.info("avs.submit.accepted jobId={} alreadyQueued={}", jobId, alreadyQueued);
        return new Submission.Accepted(jobId, alreadyQueued);
    }

    /**
     * Assemble a multipart body by hand.
     *
     * <p>Necessary because the signature is over these exact bytes. Any library
     * that regenerates the body — different boundary, different header order,
     * different line endings — produces a body that no longer matches the
     * signature, and the failure appears as an unexplained 401.
     */
    private static byte[] multipartBody(
            String boundary, String jobId, byte[] front, byte[] back) {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            writePart(out, boundary, "front", "front.jpg", front);
            writePart(out, boundary, "back", "back.jpg", back);
            writeField(out, boundary, "job_id", jobId);
            out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("could not build multipart body", e);
        }
        return out.toByteArray();
    }

    private static void writePart(
            ByteArrayOutputStream out, String boundary, String name, String filename, byte[] data)
            throws IOException {
        out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(("Content-Disposition: form-data; name=\"" + name + "\"; filename=\""
                        + filename + "\"\r\n").getBytes(StandardCharsets.UTF_8));
        out.write("Content-Type: image/jpeg\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        out.write(data);
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private static void writeField(
            ByteArrayOutputStream out, String boundary, String name, String value)
            throws IOException {
        out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n")
                .getBytes(StandardCharsets.UTF_8));
        out.write(value.getBytes(StandardCharsets.UTF_8));
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private static String truncate(String body) {
        return body == null ? "" : body.substring(0, Math.min(body.length(), 300));
    }
}

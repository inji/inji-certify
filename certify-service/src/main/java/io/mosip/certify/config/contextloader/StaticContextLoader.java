package io.mosip.certify.config.contextloader;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonStructure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public final class StaticContextLoader implements DocumentLoader {

    private static final Logger log = LoggerFactory.getLogger(StaticContextLoader.class);

    private static final int MAX_REDIRECTS = 5;

    private static final class CacheEntry {
        final JsonObject json;
        final long expiresAtMillis; // 0 = never expires
        CacheEntry(JsonObject json, long expiresAtMillis) {
            this.json = json;
            this.expiresAtMillis = expiresAtMillis;
        }
        boolean isExpired(long now) {
            return expiresAtMillis > 0 && now >= expiresAtMillis;
        }
    }

    private final JsonLdContextLoaderProperties jsonLdProps;
    private final ResourceLoader resourceLoader;
    private final HttpClient httpClient;

    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public StaticContextLoader(JsonLdContextLoaderProperties jsonLdProps, ResourceLoader resourceLoader) {
        this.jsonLdProps = jsonLdProps;
        this.resourceLoader = resourceLoader;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        preloadConfiguredContexts();
    }

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
        if (url == null) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, "Document URL is null.");
        }

        URI normalized = url.normalize();
        String iri = normalized.toString();

        // 1) Cache hit
        JsonObject cached = fetchCachedContext(iri);
        if (cached != null) {
            return JsonDocument.of(cached);
        }

        // 2) Configured mapping
        JsonLdContextLoaderProperties.Context configured = jsonLdProps.getContexts().get(iri);
        if (configured != null) {
            Document doc = loadFromResource(normalized, configured.getResource(), options);
            cacheDocument(iri, doc, configured.isCache());
            return doc;
        }

        // 3) Unknown context remote fetch
        if (!jsonLdProps.getRemote().isEnabled() || !jsonLdProps.getRemote().isAllowUnknown()) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "No configured mapping for context: " + iri + " and remote unknown contexts are disabled.");
        }

        Document doc = fetchRemoteDocument(normalized);
        cacheDocument(iri, doc, true);
        return doc;
    }

    private void preloadConfiguredContexts() {
        jsonLdProps.getContexts().forEach((iri, cfg) -> {
            if (!cfg.isPreload()) return;
            try {
                Document doc = loadFromResource(URI.create(iri), cfg.getResource(), null);
                cacheDocument(iri, doc, cfg.isCache());
            } catch (Exception e) {
                log.warn("Failed to preload JSON-LD context {} from {}", iri, cfg.getResource(), e);
            }
        });
    }

    private Document loadFromResource(URI contextIri, String resourceLocation, DocumentLoaderOptions options) throws JsonLdError {
        if (resourceLocation == null || resourceLocation.isBlank()) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Blank resource location for context: " + contextIri);
        }

        // If resourceLocation is remote URL, load using remote policy
        if (isRemoteUrl(resourceLocation)) {
            if (!jsonLdProps.getRemote().isEnabled()) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Remote loading disabled, but configured context resource is remote: " + resourceLocation);
            }
            URI remoteUri = URI.create(resourceLocation).normalize();
            return fetchRemoteDocument(remoteUri);
        }

        // Local/classpath/file
        try {
            Resource resource = resourceLoader.getResource(resourceLocation);
            if (!resource.exists()) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Context resource does not exist: " + resourceLocation + " (for " + contextIri + ")");
            }

            try (InputStream is = resource.getInputStream();
                 JsonReader reader = Json.createReader(is)) {

                JsonStructure js = reader.read();
                if (!(js instanceof JsonObject obj)) {
                    throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                            "Context must be a JSON object at: " + resourceLocation + " (for " + contextIri + ")");
                }
                return JsonDocument.of(obj);
            }

        } catch (JsonLdError e) {
            throw e;
        } catch (Exception e) {
            JsonLdError wrapped = new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Failed to load context from " + resourceLocation + " (for " + contextIri + "): " + e.getMessage());
            wrapped.initCause(e);
            throw wrapped;
        }
    }

    /**
     * Fetches a remote JSON-LD document with manual redirect handling.
     * Each redirect hop is validated against the allowlist before following.
     */
    private Document fetchRemoteDocument(URI uri) throws JsonLdError {
        URI current = uri;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            validateRemoteBasics(current);
            validateRemoteHostAllowed(current);

            HttpResponse<String> response;
            try {
                response = httpClient.send(
                        HttpRequest.newBuilder(current).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                JsonLdError err = new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Failed to fetch remote context: " + current + " - " + e.getMessage());
                err.initCause(e);
                throw err;
            }

            int status = response.statusCode();

            // Handle redirects (3xx)
            if (status >= 300 && status < 400) {
                URI redirectSource = current;
                String location = response.headers().firstValue("Location")
                        .orElseThrow(() -> new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                                "Redirect response with no Location header from: " + redirectSource));
                current = current.resolve(location);
                continue;
            }

            if (status != 200) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Remote context returned HTTP " + status + " for: " + current);
            }

            return parseJsonLdResponse(response.body(), uri);
        }

        throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                "Too many redirects (max " + MAX_REDIRECTS + ") for remote context: " + uri);
    }

    private Document parseJsonLdResponse(String body, URI originalUri) throws JsonLdError {
        try (JsonReader reader = Json.createReader(new StringReader(body))) {
            JsonStructure js = reader.read();
            if (!(js instanceof JsonObject obj)) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                        "Remote context must be a JSON object: " + originalUri);
            }
            return JsonDocument.of(obj);
        } catch (JsonLdError e) {
            throw e;
        } catch (Exception e) {
            JsonLdError err = new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Failed to parse remote context from " + originalUri + ": " + e.getMessage());
            err.initCause(e);
            throw err;
        }
    }

    private boolean isRemoteUrl(String resourceLocation) {
        String resourceUrl = resourceLocation.toLowerCase(Locale.ROOT);
        return resourceUrl.startsWith("http://") || resourceUrl.startsWith("https://");
    }

    private void validateRemoteBasics(URI uri) throws JsonLdError {
        String scheme = uri.getScheme();
        if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Unsupported scheme for remote context: " + uri);
        }
    }

    /**
     * Enforces allowlist ONLY when user explicitly wants it:
     * - remote.enforceAllowedHosts=true AND allowedHosts not empty
     */
    private void validateRemoteHostAllowed(URI uri) throws JsonLdError {
        if (!jsonLdProps.getRemote().isEnforceAllowedHosts()) {
            return; // host filtering disabled by config
        }

        Set<String> allowedHosts = jsonLdProps.getRemote().getAllowedHosts();
        if (allowedHosts == null || allowedHosts.isEmpty()) {
            return; // nothing to enforce
        }

        String host = uri.getHost();
        if (host == null) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Remote context has no host: " + uri);
        }

        String normalizedHost = host.toLowerCase(Locale.ROOT);
        if (!allowedHosts.contains(normalizedHost)) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED,
                    "Remote context host not allowed: " + host + " (uri=" + uri + ")");
        }
    }

    private JsonObject fetchCachedContext(String iri) {
        if (!jsonLdProps.getCache().isEnabled()) return null;

        CacheEntry entry = cache.get(iri);
        if (entry == null) return null;

        long now = System.currentTimeMillis();
        if (entry.isExpired(now)) {
            cache.remove(iri, entry);
            return null;
        }
        return entry.json;
    }

    private void cacheDocument(String iri, Document doc, boolean perEntryCache) {
        if (!jsonLdProps.getCache().isEnabled() || !perEntryCache) return;

        JsonObject json = extractJsonObject(doc);
        if (json == null) return;

        int maxEntries = jsonLdProps.getCache().getMaxEntries();
        if (maxEntries > 0 && cache.size() >= maxEntries && !cache.containsKey(iri)) {
            log.warn("Context cache full (maxEntries={}), not caching {}", maxEntries, iri);
            return;
        }

        Duration ttl = jsonLdProps.getCache().getTtl();
        long expiresAt = 0L;
        if (ttl != null && !ttl.isZero() && !ttl.isNegative()) {
            expiresAt = System.currentTimeMillis() + ttl.toMillis();
        }

        cache.putIfAbsent(iri, new CacheEntry(json, expiresAt));
    }

    private JsonObject extractJsonObject(Document document) {
        if (!(document instanceof JsonDocument jd)) return null;
        Optional<JsonStructure> content = jd.getJsonContent();
        if (content.isEmpty()) return null;
        return (content.get() instanceof JsonObject jo) ? jo : null;
    }
}

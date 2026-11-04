package io.mosip.certify.core.constants;

// error_description texts for access-token failures, shared by the filter that records them
// and the tests that assert them.
public class AuthErrorMessages {
    public static final String ERROR_TOKEN_REQUIRES_DPOP = "This access token is DPoP-bound and cannot be presented as a Bearer token.";
    public static final String ERROR_DPOP_NOT_SUPPORTED = "DPoP is not supported by this deployment. Use a Bearer token.";
}

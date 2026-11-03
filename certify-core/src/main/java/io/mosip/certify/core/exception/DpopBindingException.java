package io.mosip.certify.core.exception;

import io.mosip.certify.core.constants.ErrorConstants;

/**
 * Raised when a valid DPoP proof arrives with an access token that is not bound to
 * its key (RFC 9449 §7.1, Figure 16).
 *
 * <p>The fault is the token's, not the proof's, so it answers {@code invalid_token}
 * rather than {@code invalid_dpop_proof}. A type of its own lets the filter tell this
 * {@code invalid_token} apart from the others and keep {@code algs} on its challenge.
 */
public class DpopBindingException extends CertifyException {

    public DpopBindingException(String message) {
        super(ErrorConstants.INVALID_AUTH_TOKEN, message);
    }
}

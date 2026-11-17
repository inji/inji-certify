package io.mosip.certify.api.exception;

import io.mosip.certify.api.util.ErrorConstants;

public class VCIExchangeException extends Exception {
    private String errorCode;
    private String errorMessage;

    public VCIExchangeException() {
        super(ErrorConstants.VCI_EXCHANGE_FAILED);
        this.errorCode = ErrorConstants.VCI_EXCHANGE_FAILED;
    }

    public VCIExchangeException(String errorCode) {
        super(errorCode);
        this.errorCode = errorCode;
    }

    public VCIExchangeException(String errorCode, String errorMessage) {
        super(errorCode +  " -> " +  errorMessage);
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public String getErrorCode() {
        return errorCode;
    }

    /**
     * The message the plugin passed to {@link #VCIExchangeException(String, String)}, without the error code.
     * Certify returns it to the wallet as error_description, so it must not carry internal details.
     * Null when the plugin gave only an error code.
     */
    public String getErrorMessage() {
        return errorMessage;
    }
}

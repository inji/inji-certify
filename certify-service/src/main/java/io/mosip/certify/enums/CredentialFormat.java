package io.mosip.certify.enums;

/**
 * Enum for credential format as per the OpenID4VCI
 */
public enum CredentialFormat {
    VC_SD_JWT("vc+sd-jwt"), //defined by W3C
    VC_DC_SD_JWT("dc+sd-jwt"), //direct sd_jwt as defined by sd jwt spec
    VC_LDP("ldp_vc"),
    VC_JWT("jwt_vc_json"),
    VC_LD_JWT("jwt_vc_json-ld"),
    VC_MDOC("mso_mdoc");

    private final String format;

    CredentialFormat(String inputFormat) {
        this.format = inputFormat;
    }

    public boolean equalsName(String otherFormat) {
        // (otherFormat == null) check is not needed because format.equals(null) returns false 
        return format.equalsIgnoreCase(otherFormat);
    }

    @Override
    public String toString() {
       return this.format;
    }
}

package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The rule in isolation. {@code CredentialConfigSdClaimValidationTest} covers the same cases through
 * the Add and Update APIs; this covers the validator itself.
 */
class SdClaimValidatorTest {

    @ParameterizedTest(name = "rejects not-a-path: {0}")
    @ValueSource(strings = {
            "abcdef",               // the ticket's own reproduction: random values
            "fullName",             // field name with no $ root
            ".fullName",            // leading dot, still no root
            "$..fullName",          // recursive descent is outside the supported subset
            "$.phoneNumbers[01]",   // non canonical, zero padded index
            "$.phoneNumbers[x]",    // bracket segment that is neither an index nor the wildcard
            "$.address.",           // trailing dot leaves an empty segment
            "$.address[",           // unbalanced bracket
            "$[0]x",                // trailing junk after a segment
            "credentialSubject.name"
    })
    void rejectsAnEntryThatIsNotASelectiveDisclosurePath(String sdClaim) {
        CertifyException exception = assertThrows(CertifyException.class,
                () -> SdClaimValidator.validateSdClaim(sdClaim));

        assertEquals(ErrorConstants.INVALID_SD_CLAIM, exception.getErrorCode());
        assertTrue(exception.getMessage().contains(sdClaim),
                "message should name the offending entry but was: " + exception.getMessage());
    }

    @ParameterizedTest(name = "rejects blank entry in: \"{0}\"")
    @ValueSource(strings = {
            "",                        // wholly empty: already unusable at VC fetch
            "   ",                     // whitespace only
            ",",                       // separators only
            ",,",
            "$.fullName,,$.gender",    // blank between two valid paths
            "$.fullName, ,$.gender",   // whitespace only entry between two valid paths
            "$.fullName,",             // trailing separator, which split(",") would hide
            "$.fullName,,",
            ",$.fullName"              // leading separator
    })
    void rejectsABlankEntry(String sdClaim) {
        CertifyException exception = assertThrows(CertifyException.class,
                () -> SdClaimValidator.validateSdClaim(sdClaim));

        assertEquals(ErrorConstants.INVALID_SD_CLAIM, exception.getErrorCode());
    }

    @ParameterizedTest(name = "accepts: \"{0}\"")
    @ValueSource(strings = {
            "$",                                   // the root alone is syntactically valid
            "$.fullName",
            "$.address.region",                    // nested
            "$.phoneNumbers[0]",                   // array index
            "$.phoneNumbers[*]",                   // array wildcard
            "$.address.*",                         // object wildcard
            "$.fullName,$.gender",                 // several entries
            "$.fullName, $.gender",                // whitespace after the separator is tolerated
            "$.fullName,$.fullName",               // a repeated path is not an error
            "$.a.b.c.d[0].e[*]",                   // deep mixture
            "$.favouriteColour",                   // well formed but absent: a VC fetch concern
            "$.fullName[*]"                        // well formed but wrong shape: also VC fetch
    })
    void acceptsWellFormedPaths(String sdClaim) {
        assertDoesNotThrow(() -> SdClaimValidator.validateSdClaim(sdClaim));
    }

    @Test
    @DisplayName("a configuration with no selective disclosure is left alone")
    void acceptsNull() {
        assertDoesNotThrow(() -> SdClaimValidator.validateSdClaim(null));
    }

    @Test
    @DisplayName("one valid entry does not excuse a broken one")
    void rejectsWhenOnlyOneEntryIsInvalid() {
        CertifyException exception = assertThrows(CertifyException.class,
                () -> SdClaimValidator.validateSdClaim("$.fullName, $.gender, abcdef, $.address.region"));

        assertEquals(ErrorConstants.INVALID_SD_CLAIM, exception.getErrorCode());
        assertTrue(exception.getMessage().contains("abcdef"));
    }

    @Test
    @DisplayName("fails fast, naming the first offending entry")
    void reportsTheFirstOffendingEntry() {
        CertifyException exception = assertThrows(CertifyException.class,
                () -> SdClaimValidator.validateSdClaim("$.ok, firstBad, secondBad"));

        assertTrue(exception.getMessage().contains("firstBad"),
                "should name the first offender but was: " + exception.getMessage());
        assertTrue(!exception.getMessage().contains("secondBad"),
                "should not mention later entries but was: " + exception.getMessage());
    }

   
    @Test
    @DisplayName("says nothing about whether a path exists in the credential")
    void doesNotAttemptToResolvePathsAgainstACredential() {
        assertDoesNotThrow(() -> SdClaimValidator.validateSdClaim("$.noSuchFieldAnywhere"));
        assertDoesNotThrow(() -> SdClaimValidator.validateSdClaim("$.aStringField[*]"));
    }
}

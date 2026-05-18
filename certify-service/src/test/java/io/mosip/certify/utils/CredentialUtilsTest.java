package io.mosip.certify.utils;

import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.core.constants.VCFormats;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class CredentialUtilsTest  {

    //todo check and fix this -> there seems to be a logic change, ignoring for now
    @Test
    public void testGetTemplateNameFor_LDP_VC() {
        VCRequestDto request = new VCRequestDto();
        request.setFormat(VCFormats.LDP_VC);
        request.setContext(List.of("https://www.w3.org/ns/credentials/v2", "https://example.org/Person.json"));
        request.setType(List.of("VerifiableCredential", "UniversityCredential"));
        String expected = "UniversityCredential,VerifiableCredential::https://example.org/Person.json,https://www.w3.org/ns/credentials/v2::ldp_vc";
        assertEquals(expected, CredentialUtils.getTemplateName(request));
    }


    @Test
    public void testIsVC2_0Request() {
        VCRequestDto request = new VCRequestDto();
        request.setContext(List.of("https://www.w3.org/ns/credentials/v2", "https://example.org/Person.json"));
        request.setType(List.of("VerifiableCredential", "UniversityCredential"));
        assertTrue(CredentialUtils.isVC2_0Request(request));
    }

    @Test
    public void testGetTemplateNameFor_MsoMdoc_VC() {
        VCRequestDto request = new VCRequestDto();
        request.setFormat(VCFormats.MSO_MDOC);
        request.setDoctype("org.iso.18013.5.1.mDL");
        String expected = "mso_mdoc::org.iso.18013.5.1.mDL";
        assertEquals(expected, CredentialUtils.getTemplateName(request));
    }

    @Test
    public void testGetTemplateNameFor_DCSDJWT_VC() {
        VCRequestDto request = new VCRequestDto();
        request.setFormat(VCFormats.DC_SD_JWT);
        request.setVct("test-vct");
        String expected = "dc+sd-jwt::test-vct";
        assertEquals(expected, CredentialUtils.getTemplateName(request));
    }
}
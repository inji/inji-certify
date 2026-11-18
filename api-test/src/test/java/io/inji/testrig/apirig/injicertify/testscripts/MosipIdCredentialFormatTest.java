package io.inji.testrig.apirig.injicertify.testscripts;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.restassured.builder.ResponseBuilder;
import io.restassured.response.Response;
import org.json.JSONArray;
import org.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Map;

public class MosipIdCredentialFormatTest {
    private TestCaseDTO scenario(String format) throws Exception {
        String path = "/injicertify/VCIMosipID/GetCredentialMosipID/GetCredentialMosipID.yml";
        try (InputStream input = getClass().getResourceAsStream(path)) {
            Assert.assertNotNull(input);
            Map<?, ?> document = new Yaml().load(input);
            Map<?, ?> cases = (Map<?, ?>) document.get("GetCredentialMosipID");
            String name = "InjiCertify_GetCredentialMosipID_IdpAccessToken_" + format + "_all_Valid_Smoke";
            Map<?, ?> config = (Map<?, ?>) cases.get(name);
            Assert.assertNotNull(config, name);
            TestCaseDTO dto = new TestCaseDTO();
            dto.setTestCaseName(name);
            dto.setOutput((String) config.get("output"));
            return dto;
        }
    }

    private Response response(Object credential) {
        JSONObject body = new JSONObject().put("credentials",
                new JSONArray().put(new JSONObject().put("credential", credential)));
        return new ResponseBuilder().setStatusCode(200).setBody(body.toString()).build();
    }

    private String jwt(String type, String vct) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(type)).build(), new JWTClaimsSet.Builder().claim("vct", vct).build());
        jwt.sign(new ECDSASigner(new ECKeyGenerator(Curve.P_256).generate()));
        return jwt.serialize();
    }

    @Test
    public void acceptsSdJwt() throws Exception {
        SimplePost.validateCredentialResponse(response(jwt("dc+sd-jwt", "MosipID") + "~"), scenario("SdJwt"));
    }

    @Test
    public void acceptsMdoc() throws Exception {
        SimplePost.validateCredentialResponse(response("oWdkb2NUeXBlZ01vc2lwSUQ"), scenario("Mdoc"));
    }

    @DataProvider
    public Object[][] formats() {
        return new Object[][] {{"SdJwt"}, {"Mdoc"}};
    }

    @Test(dataProvider = "formats")
    public void rejectsLdpCredential(String format) throws Exception {
        TestCaseDTO dto = scenario(format);
        Response ldp = response(new JSONObject().put("type", new JSONArray().put("VerifiableCredential")));
        Assert.expectThrows(RuntimeException.class, () -> SimplePost.validateCredentialResponse(ldp, dto));
    }

    @DataProvider
    public Object[][] invalidSdJwt() throws Exception {
        return new Object[][] {
                {""}, {"not-a-jwt~"}, {"oWdkb2NUeXBlZ01vc2lwSUQ"},
                {jwt("dc+sd-jwt", "MosipID")},
                {jwt("JWT", "MosipID") + "~"},
                {jwt("dc+sd-jwt", null) + "~"},
                {jwt("dc+sd-jwt", " ") + "~"}
        };
    }

    @Test(dataProvider = "invalidSdJwt")
    public void rejectsInvalidSdJwt(String credential) throws Exception {
        TestCaseDTO dto = scenario("SdJwt");
        Assert.expectThrows(RuntimeException.class,
                () -> SimplePost.validateCredentialResponse(response(credential), dto));
    }

    @Test
    public void rejectsSdJwtAsMdoc() throws Exception {
        TestCaseDTO dto = scenario("Mdoc");
        Response sdJwt = response(jwt("dc+sd-jwt", "MosipID") + "~");
        Assert.expectThrows(RuntimeException.class, () -> SimplePost.validateCredentialResponse(sdJwt, dto));
    }

    @Test(dataProvider = "formats")
    public void rejectsMissingOrEmptyCredentials(String format) throws Exception {
        TestCaseDTO dto = scenario(format);
        for (String body : new String[] {"{}", "{\"credentials\":[]}"}) {
            Response invalid = new ResponseBuilder().setStatusCode(200).setBody(body).build();
            Assert.expectThrows(RuntimeException.class, () -> SimplePost.validateCredentialResponse(invalid, dto));
        }
    }

    @Test(dataProvider = "formats")
    public void preservesExpectedErrorResponses(String format) throws Exception {
        TestCaseDTO dto = scenario(format);
        dto.setOutput("{\"error\":\"invalid_proof\"}");
        Response error = new ResponseBuilder().setStatusCode(400).setBody(dto.getOutput()).build();
        SimplePost.validateCredentialResponse(error, dto);
    }
}

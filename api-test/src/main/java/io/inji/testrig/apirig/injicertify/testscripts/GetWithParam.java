package io.inji.testrig.apirig.injicertify.testscripts;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.testng.ITest;
import org.testng.ITestContext;
import org.testng.ITestResult;
import org.testng.Reporter;
import org.testng.SkipException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.testng.internal.BaseTestMethod;
import org.testng.internal.TestResult;

import io.inji.testrig.apirig.injicertify.utils.InjiCertifyConfigManager;
import io.inji.testrig.apirig.injicertify.utils.InjiCertifyUtil;
import io.mosip.testrig.apirig.dto.OutputValidationDto;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.utils.AdminTestException;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.AuthenticationTestException;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.GlobalMethods;
import io.mosip.testrig.apirig.utils.OutputValidationUtil;
import io.mosip.testrig.apirig.utils.ReportUtil;
import io.mosip.testrig.apirig.utils.SecurityXSSException;
import io.restassured.response.Response;

import static io.restassured.RestAssured.given;

public class GetWithParam extends InjiCertifyUtil implements ITest {
	private static final Logger logger = Logger.getLogger(GetWithParam.class);
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	protected String testCaseName = "";
	public Response response = null;
	public boolean sendEsignetToken = false;
	public boolean auditLogCheck = false;

	@BeforeClass
	public static void setLogLevel() {
		if (InjiCertifyConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
	}

	/**
	 * get current testcaseName
	 */
	@Override
	public String getTestName() {
		return testCaseName;
	}

	/**
	 * Data provider class provides test case list
	 * 
	 * @return object of data provider
	 */
	@DataProvider(name = "testcaselist")
	public Object[] getTestCaseList(ITestContext context) {
		String ymlFile = context.getCurrentXmlTest().getLocalParameters().get("ymlFile");
		sendEsignetToken = context.getCurrentXmlTest().getLocalParameters().containsKey("sendEsignetToken");
		logger.info("Started executing yml: " + ymlFile);
		return getYmlTestData(ymlFile);
	}

	/**
	 * Test method for OTP Generation execution
	 * 
	 * @param objTestParameters
	 * @param testScenario
	 * @param testcaseName
	 * @throws AuthenticationTestException
	 * @throws AdminTestException
	 */
	@Test(dataProvider = "testcaselist")
	public void test(TestCaseDTO testCaseDTO) throws AuthenticationTestException, AdminTestException, SecurityXSSException {
		testCaseName = testCaseDTO.getTestCaseName();
		testCaseDTO = InjiCertifyUtil.isTestCaseValidForExecution(testCaseDTO);
		if (HealthChecker.signalTerminateExecution) {
			throw new SkipException(
					GlobalConstants.TARGET_ENV_HEALTH_CHECK_FAILED + HealthChecker.healthCheckFailureMapS);
		}

		if (testCaseDTO.getTestCaseName().contains("VID") || testCaseDTO.getTestCaseName().contains("Vid")) {
			if (!BaseTestCase.getSupportedIdTypesValueFromActuator().contains("VID")
					&& !BaseTestCase.getSupportedIdTypesValueFromActuator().contains("vid")) {
				throw new SkipException(GlobalConstants.VID_FEATURE_NOT_SUPPORTED);
			}
		}
		auditLogCheck = testCaseDTO.isAuditLogCheck();
		String[] templateFields = testCaseDTO.getTemplateFields();

		if (testCaseDTO.getInputTemplate().contains(GlobalConstants.$PRIMARYLANG$))
			testCaseDTO.setInputTemplate(testCaseDTO.getInputTemplate().replace(GlobalConstants.$PRIMARYLANG$,
					BaseTestCase.languageList.get(0)));
		if (testCaseDTO.getOutputTemplate().contains(GlobalConstants.$PRIMARYLANG$))
			testCaseDTO.setOutputTemplate(testCaseDTO.getOutputTemplate().replace(GlobalConstants.$PRIMARYLANG$,
					BaseTestCase.languageList.get(0)));
		if (testCaseDTO.getInput().contains(GlobalConstants.$PRIMARYLANG$))
			testCaseDTO.setInput(
					testCaseDTO.getInput().replace(GlobalConstants.$PRIMARYLANG$, BaseTestCase.languageList.get(0)));
		if (testCaseDTO.getOutput().contains(GlobalConstants.$PRIMARYLANG$))
			testCaseDTO.setOutput(
					testCaseDTO.getOutput().replace(GlobalConstants.$PRIMARYLANG$, BaseTestCase.languageList.get(0)));

		if (testCaseDTO.getTemplateFields() != null && templateFields.length > 0) {
			ArrayList<JSONObject> inputtestCases = AdminTestUtil.getInputTestCase(testCaseDTO);
			ArrayList<JSONObject> outputtestcase = AdminTestUtil.getOutputTestCase(testCaseDTO);
			for (int i = 0; i < languageList.size(); i++) {
				response = getWithPathParamAndCookie(ApplnURI + testCaseDTO.getEndPoint(),
						getJsonFromTemplate(inputtestCases.get(i).toString(), testCaseDTO.getInputTemplate()),
						COOKIENAME, testCaseDTO.getRole(), testCaseDTO.getTestCaseName());

				Map<String, List<OutputValidationDto>> ouputValid = OutputValidationUtil.doJsonOutputValidation(
						response.asString(),
						getJsonFromTemplate(outputtestcase.get(i).toString(), testCaseDTO.getOutputTemplate()),
						testCaseDTO, response.getStatusCode());
				Reporter.log(ReportUtil.getOutputValidationReport(ouputValid));

				if (!OutputValidationUtil.publishOutputResult(ouputValid))
					throw new AdminTestException("Failed at output validation");
			}
		}

		else {
			String inputJson = getJsonFromTemplate(testCaseDTO.getInput(), testCaseDTO.getInputTemplate());
			inputJson = inputStringKeyWordHandeler(inputJson, testCaseName);
			if (testCaseName.contains("ESignet_")) {
				if (InjiCertifyConfigManager.isInServiceNotDeployedList(GlobalConstants.ESIGNET)) {
					throw new SkipException("esignet is not deployed hence skipping the testcase");
				}

				String tempUrl = ApplnURI;

				if (testCaseDTO.getEndPoint().startsWith("$SUNBIRDBASEURL$") && testCaseName.contains("SunBirdR")) {

					if (InjiCertifyConfigManager.isInServiceNotDeployedList("sunbirdrc"))
						throw new SkipException(GlobalConstants.SERVICE_NOT_DEPLOYED_MESSAGE);

					if (InjiCertifyConfigManager.getSunBirdBaseURL() != null
							&& !InjiCertifyConfigManager.getSunBirdBaseURL().isBlank())
						tempUrl = InjiCertifyConfigManager.getSunBirdBaseURL();
					testCaseDTO.setEndPoint(testCaseDTO.getEndPoint().replace("$SUNBIRDBASEURL$", ""));
				}

				response = getWithPathParamAndCookie(tempUrl + testCaseDTO.getEndPoint(), inputJson, auditLogCheck,
						COOKIENAME, testCaseDTO.getRole(), testCaseDTO.getTestCaseName(), sendEsignetToken);

			} else {
				String tempUrl = ApplnURI;
				String endPointKeyWord = "";

				if (testCaseDTO.getEndPoint().contains("BASEURL$")) {
					tempUrl = InjiCertifyUtil.getTempURL(testCaseDTO);
					endPointKeyWord = InjiCertifyUtil.getKeyWordFromEndPoint(testCaseDTO.getEndPoint());

					if (!(endPointKeyWord.isBlank()) && testCaseDTO.getEndPoint().startsWith(endPointKeyWord)) {
						testCaseDTO.setEndPoint(testCaseDTO.getEndPoint().replace(endPointKeyWord, ""));
					}
				}

				// The two-request cases keep their expected comparison fields in YAML; the shared result HBS is empty.
				if (testCaseName.startsWith("InjiCertify_WellKnownEndpoint_") && testCaseName.contains("_Accept_")) {
					verifyWellKnownResponse(tempUrl + testCaseDTO.getEndPoint(), testCaseDTO.getOutput());
					return;
				}
				response = getWithPathParamAndCookie(tempUrl + testCaseDTO.getEndPoint(), inputJson, auditLogCheck,
						COOKIENAME, testCaseDTO.getRole(), testCaseDTO.getTestCaseName(), sendEsignetToken);
			}

			Map<String, List<OutputValidationDto>> ouputValid = null;
			if (testCaseName.contains("_StatusCode")) {

				OutputValidationDto customResponse = customStatusCodeResponse(String.valueOf(response.getStatusCode()),
						testCaseDTO.getOutput());

				ouputValid = new HashMap<>();
				ouputValid.put(GlobalConstants.EXPECTED_VS_ACTUAL, List.of(customResponse));
			} else {
				ouputValid = OutputValidationUtil.doJsonOutputValidation(response.asString(),
						getJsonFromTemplate(testCaseDTO.getOutput(), testCaseDTO.getOutputTemplate()), testCaseDTO,
						response.getStatusCode());
			}

			Reporter.log(ReportUtil.getOutputValidationReport(ouputValid));
			if (!OutputValidationUtil.publishOutputResult(ouputValid))
				throw new AdminTestException("Failed at output validation");
		}
	}

	private static void verifyWellKnownResponse(String url, String expectedOutput) throws AdminTestException {
		Response json = getWellKnownResponse(url, "application/json");
		Response jwt = getWellKnownResponse(url, "application/jwt");
		String jsonBodyText = json.asString();
		String jwtBodyText = jwt.asString();
		JsonNode jsonBody = parseJsonObject(jsonBodyText);
		JsonNode jwtBody = parseJsonObject(jwtBodyText);

		Map<String, String> actual = new LinkedHashMap<>();
		actual.put("Status (Accept: application/json)", String.valueOf(json.getStatusCode()));
		actual.put("Status (Accept: application/jwt)", String.valueOf(jwt.getStatusCode()));
		actual.put("Status equal", String.valueOf(json.getStatusCode() == jwt.getStatusCode()));
		actual.put("Content-Type (Accept: application/json)", mediaType(json));
		actual.put("Content-Type (Accept: application/jwt)", mediaType(jwt));
		actual.put("Non-empty body (Accept: application/json)", String.valueOf(jsonBodyText != null && !jsonBodyText.isBlank()));
		actual.put("Non-empty body (Accept: application/jwt)", String.valueOf(jwtBodyText != null && !jwtBodyText.isBlank()));
		boolean sameContent = jsonBody != null && jsonBody.equals(jwtBody);
		actual.put("JSON response content matches", String.valueOf(sameContent));
		actual.put("No error document", String.valueOf(jsonBody != null && jwtBody != null
				&& !jsonBody.has("errors") && !jsonBody.has("error")
				&& !jwtBody.has("errors") && !jwtBody.has("error")));

		JSONObject expectedJson = new JSONObject(expectedOutput);
		if (expectedJson.length() != actual.size()) {
			throw new AdminTestException("Well-known expected output must define every validation field: " + url);
		}
		Map<String, String> expected = new LinkedHashMap<>();
		for (String field : actual.keySet()) {
			expected.put(field, expectedJson.getString(field));
		}

		Map<String, List<OutputValidationDto>> validation = OutputValidationUtil.compareActuExpValue(
				actual, expected, GlobalConstants.EXPECTED_VS_ACTUAL);
		Reporter.log(ReportUtil.getOutputValidationReport(validation));
		if (!OutputValidationUtil.publishOutputResult(validation)) {
			throw new AdminTestException("Well-known response validation failed: " + url);
		}
	}

	private static Response getWellKnownResponse(String url, String accept) {
		GlobalMethods.reportRequest("Accept: " + accept, "", url);
		Response response = given().accept(accept).get(url);
		GlobalMethods.reportResponse(response.getHeaders().asList().toString(), url, response);
		return response;
	}

	private static String mediaType(Response response) {
		String contentType = response.getHeader("Content-Type");
		return contentType == null ? "<missing>" : contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
	}

	private static JsonNode parseJsonObject(String body) {
		if (body == null || body.isBlank()) {
			return null;
		}
		try {
			JsonNode parsedBody = OBJECT_MAPPER.readTree(body);
			return parsedBody != null && parsedBody.isObject() && !parsedBody.isEmpty() ? parsedBody : null;
		} catch (JsonProcessingException e) {
			return null;
		}
	}

	/**
	 * The method ser current test name to result
	 * 
	 * @param result
	 */
	@AfterMethod(alwaysRun = true)
	public void setResultTestName(ITestResult result) {
		result.setAttribute("TestCaseName", testCaseName);
	}
}

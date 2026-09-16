package io.inji.testrig.apirig.injicertify.testscripts;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.testng.ITest;
import org.testng.ITestContext;
import org.testng.ITestResult;
import org.testng.Reporter;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.testng.internal.BaseTestMethod;
import org.testng.internal.TestResult;

import com.amazonaws.services.budgets.model.Notification;
import com.github.openjson.JSONObject;

import io.inji.testrig.apirig.injicertify.utils.InjiCertifyConfigManager;
import io.inji.testrig.apirig.injicertify.utils.InjiCertifyUtil;
import io.mosip.testrig.apirig.dto.OutputValidationDto;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.utils.AdminTestException;
import io.mosip.testrig.apirig.utils.AuthenticationTestException;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.NotificationListener;
import io.mosip.testrig.apirig.utils.OutputValidationUtil;
import io.mosip.testrig.apirig.utils.ReportUtil;
import io.mosip.testrig.apirig.utils.SecurityXSSException;
import io.restassured.response.Response;

public class PostWithAutogenIdWithOtpGenerate extends InjiCertifyUtil implements ITest {
	private static final Logger logger = Logger.getLogger(PostWithAutogenIdWithOtpGenerate.class);
	protected String testCaseName = "";
	public String idKeyName = null;
	public Response response = null;
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
		idKeyName = context.getCurrentXmlTest().getLocalParameters().get("idKeyName");
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
	 * @throws InterruptedException
	 * @throws NumberFormatException
	 */
	@Test(dataProvider = "testcaselist")
	public void test(TestCaseDTO testCaseDTO)
			throws AuthenticationTestException, AdminTestException, NumberFormatException, InterruptedException, SecurityXSSException {
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

		JSONObject req = new JSONObject(testCaseDTO.getInput());

		auditLogCheck = testCaseDTO.isAuditLogCheck();
		String otpRequest = null;
		String sendOtpReqTemplate = null;
		String sendOtpEndPoint = null;
		if (req.has(GlobalConstants.SENDOTP)) {
			otpRequest = req.get(GlobalConstants.SENDOTP).toString();
			req.remove(GlobalConstants.SENDOTP);
		}
		JSONObject otpReqJson = new JSONObject(otpRequest);
		sendOtpReqTemplate = otpReqJson.getString("sendOtpReqTemplate");
		otpReqJson.remove("sendOtpReqTemplate");
		sendOtpEndPoint = otpReqJson.getString("sendOtpEndPoint");
		otpReqJson.remove("sendOtpEndPoint");

		String otpReqTemplateJson = otpReqJson.toString();

		String otpBaseUrl = InjiCertifyConfigManager.getEsignetBaseUrl();
		String otpPath = sendOtpEndPoint;
		if (otpPath != null && otpPath.contains("BASEURL$")) {
			otpBaseUrl = InjiCertifyUtil.getTempURL(testCaseDTO, otpPath);
			String endPointKeyWord = InjiCertifyUtil.getKeyWordFromEndPoint(otpPath);
			if (!endPointKeyWord.isBlank() && otpPath.startsWith(endPointKeyWord)) {
				otpPath = otpPath.replace(endPointKeyWord, "");
			}
		}
		
		Response otpResponse = null;
		int maxLoopCount = InjiCertifyUtil.parsePositiveInt(properties.getProperty("uinGenMaxLoopCount"), 20);
		long uinGenDelayMs = InjiCertifyUtil.parsePositiveLong(properties.getProperty("uinGenDelayTime"), 10000L);
		int currLoopCount = 0;
		while (currLoopCount < maxLoopCount) {
			// Rebuild from the template each attempt. eSignet rejects a stale requestTime
			// (~2 minutes) with invalid_request; mutating the already-substituted body
			// left $TIMESTAMP$ gone so retries reused the first attempt's clock.
			String input = getJsonFromTemplate(otpReqTemplateJson, sendOtpReqTemplate);
			input = inputStringKeyWordHandeler(input, testCaseName);
			input = InjiCertifyUtil.refreshEsignetRequestTime(input);
			NotificationListener.markRequestStart();
			if (testCaseName.contains(GlobalConstants.ESIGNET_)) {
				if (InjiCertifyConfigManager.isInServiceNotDeployedList(GlobalConstants.ESIGNET)) {
					throw new SkipException("esignet is not deployed hence skipping the testcase");
				}
				InjiCertifyUtil.fetchMosipIdCsrfTokenIfNeeded(testCaseName);

				otpResponse = postRequestWithCookieAuthHeaderAndXsrfToken(otpBaseUrl + otpPath, input, COOKIENAME,
						testCaseDTO.getTestCaseName());
				InjiCertifyUtil.captureEsignetCsrf(otpResponse);
			} else {
				otpResponse = postWithBodyAndCookie(ApplnURI + otpPath, input, COOKIENAME,
						GlobalConstants.RESIDENT, testCaseDTO.getTestCaseName());
			}

			if (shouldRetrySendOtp(otpResponse)) {
				logger.info("waiting for: " + uinGenDelayMs
						+ " as UIN not available in IDA yet ("
						+ InjiCertifyUtil.describeMosipIdSendOtpFailure(otpResponse) + ")");
				try {
					Thread.sleep(uinGenDelayMs);
				} catch (InterruptedException e) {
					logger.error(e.getMessage());
					Thread.currentThread().interrupt();
					break;
				}
			} else {
				break;
			}

			currLoopCount++;
		}

		JSONObject res = new JSONObject(testCaseDTO.getOutput());
		String sendOtpResp = null;
		String sendOtpResTemplate = null;
		if (res.has(GlobalConstants.SENDOTPRESP)) {
			sendOtpResp = res.get(GlobalConstants.SENDOTPRESP).toString();
			res.remove(GlobalConstants.SENDOTPRESP);
		}
		JSONObject sendOtpRespJson = new JSONObject(sendOtpResp);
		sendOtpResTemplate = sendOtpRespJson.getString("sendOtpResTemplate");
		sendOtpRespJson.remove("sendOtpResTemplate");
		if (otpResponse != null) {
			Map<String, List<OutputValidationDto>> ouputValidOtp = OutputValidationUtil.doJsonOutputValidation(
					otpResponse.asString(), getJsonFromTemplate(sendOtpRespJson.toString(), sendOtpResTemplate),
					testCaseDTO, otpResponse.getStatusCode());
			Reporter.log(ReportUtil.getOutputValidationReport(ouputValidOtp));

			if (!OutputValidationUtil.publishOutputResult(ouputValidOtp)) {
				if (otpResponse.asString().contains("IDA-OTA-001")) {
					throw new AdminTestException(
							"Exceeded number of OTP requests in a given time, Increase otp.request.flooding.max-count");
				} else if (shouldRetrySendOtp(otpResponse)) {
					throw new AdminTestException(
							"IDA rejected send-otp after retries ("
									+ InjiCertifyUtil.describeMosipIdSendOtpFailure(otpResponse)
									+ "). IDA-MLC-018 means the UIN is not in IDA yet. IDA-MLC-007 is a generic "
									+ "IDA failure. eSignet 1.8.0 calls IDA as /otp/{misp-lk}/{relyingPartyId}/"
									+ "{clientId}; clientId must be a PMS-issued API key from "
									+ "/v1/partnermanager/oidc/client, not an eSignet-only oauth-client. Also "
									+ "check ID-repo to IDA credential sync and CBEFF face.");
				} else
					throw new AdminTestException("Failed at otp output validation");
			}
		} else {
			throw new AdminTestException("Invalid otp response");
		}
		
		String reqJson = getJsonFromTemplate(testCaseDTO.getInput(), testCaseDTO.getInputTemplate());
		reqJson = inputStringKeyWordHandeler(reqJson, testCaseName);
		reqJson = inputJsonKeyWordHandeler(reqJson, testCaseName);
		reqJson = InjiCertifyUtil.smtpOtpHandler(reqJson, testCaseDTO);

		if (testCaseName.contains(GlobalConstants.ESIGNET_)) {
			if (InjiCertifyConfigManager.isInServiceNotDeployedList(GlobalConstants.ESIGNET)) {
				throw new SkipException("esignet is not deployed hence skipping the testcase");
			}
			String tempUrl = InjiCertifyConfigManager.getEsignetBaseUrl();
			String endPointKeyWord = "";
			if (testCaseDTO.getEndPoint().contains("BASEURL$")) {
				tempUrl = InjiCertifyUtil.getTempURL(testCaseDTO);
				endPointKeyWord = InjiCertifyUtil.getKeyWordFromEndPoint(testCaseDTO.getEndPoint());

				if (!(endPointKeyWord.isBlank()) && testCaseDTO.getEndPoint().startsWith(endPointKeyWord)) {
					testCaseDTO.setEndPoint(testCaseDTO.getEndPoint().replace(endPointKeyWord, ""));
				}
			}
			InjiCertifyUtil.fetchMosipIdCsrfTokenIfNeeded(testCaseName);
			response = postRequestWithCookieAuthHeaderAndXsrfTokenForAutoGenId(tempUrl + testCaseDTO.getEndPoint(),
					reqJson, COOKIENAME, testCaseDTO.getTestCaseName(), idKeyName);
			InjiCertifyUtil.captureEsignetCsrf(response);
		} else {
			response = postWithBodyAndCookieForAutoGeneratedId(ApplnURI + testCaseDTO.getEndPoint(), reqJson,
					auditLogCheck, COOKIENAME, testCaseDTO.getRole(), testCaseDTO.getTestCaseName(), idKeyName);
		}

		Map<String, List<OutputValidationDto>> ouputValid = OutputValidationUtil.doJsonOutputValidation(
				response.asString(), getJsonFromTemplate(res.toString(), testCaseDTO.getOutputTemplate()), testCaseDTO,
				response.getStatusCode());
		Reporter.log(ReportUtil.getOutputValidationReport(ouputValid));

		if (!OutputValidationUtil.publishOutputResult(ouputValid))
			throw new AdminTestException("Failed at output validation");
	}

	/**
	 * Released IDA returns IDA-MLC-018 while a newly created UIN is still being
	 * indexed. Some deployments return IDA-MLC-007 for the same window. The MOSIP ID
	 * stack can also wrap that window as eSignet {@code send_otp_failed}.
	 */
	private boolean shouldRetrySendOtp(Response otpResponse) {
		if (otpResponse == null) {
			return false;
		}
		if (testCaseName != null && testCaseName.toUpperCase().contains("MOSIPID")) {
			return InjiCertifyUtil.isRetryableMosipIdSendOtpFailure(otpResponse);
		}
		String body = otpResponse.asString();
		return body.contains("IDA-MLC-018") || body.contains("IDA-MLC-007");
	}

	/**
	 * The method ser current test name to result
	 * 
	 * @param result
	 */
	@AfterMethod(alwaysRun = true)
	public void setResultTestName(ITestResult result) {
		result.setAttribute("TestCaseName", testCaseName);
		NotificationListener.markRequestRemove();
	}

	@AfterClass(alwaysRun = true)
	public void waittime() {}
}

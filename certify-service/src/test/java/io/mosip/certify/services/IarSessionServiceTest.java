/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.dto.AuthorizationDetail;
import io.mosip.certify.core.dto.InteractiveAuthorizationRequest;
import io.mosip.certify.core.dto.VerifyVpResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IarSessionRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class IarSessionServiceTest {

    @Mock
    private IarSessionRepository iarSessionRepository;

    @Mock
    private CredentialConfigRepository credentialConfigRepository;

    @InjectMocks
    private IarSessionService iarSessionService;

    private InteractiveAuthorizationRequest iarRequest;
    private VerifyVpResponse verifyResponse;

    @Before
    public void setup() {
        AuthorizationDetail detail = new AuthorizationDetail();
        detail.setCredentialConfigurationId("cred-config-1");

        iarRequest = new InteractiveAuthorizationRequest();
        iarRequest.setClientId("client-1");
        iarRequest.setCodeChallenge("challenge");
        iarRequest.setCodeChallengeMethod("S256");
        iarRequest.setAuthorizationDetails(List.of(detail));

        VerifyVpResponse.AuthorizationDetails authDetails = new VerifyVpResponse.AuthorizationDetails();
        authDetails.setNonce("nonce-1");
        authDetails.setResponseUri("https://wallet/response");

        verifyResponse = new VerifyVpResponse();
        verifyResponse.setRequestId("request-1");
        verifyResponse.setExpiresAt(System.currentTimeMillis() + 60000);
        verifyResponse.setAuthorizationDetails(authDetails);
    }

    private CredentialConfig activeConfig(String scope) {
        CredentialConfig config = new CredentialConfig();
        config.setStatus("active");
        config.setScope(scope);
        return config;
    }

    @Test
    public void should_returnPrefixedSession_when_authSessionGenerated() {
        String authSession = iarSessionService.generateAuthSession();
        assertNotNull(authSession);
        assertTrue(authSession.startsWith("iar_session_"));
    }

    @Test
    public void should_createSession_when_requestIsValid() {
        when(credentialConfigRepository.findByCredentialConfigKeyId("cred-config-1"))
                .thenReturn(Optional.of(activeConfig("test_scope")));

        IarSession session = iarSessionService.createIarSession(
                iarRequest, verifyResponse, "auth-1", "txn-1");

        assertEquals("auth-1", session.getAuthSession());
        assertEquals("txn-1", session.getTransactionId());
        assertEquals("request-1", session.getRequestId());
        assertEquals("nonce-1", session.getVerifyNonce());
        assertEquals("https://wallet/response", session.getResponseUri());
        assertEquals("client-1", session.getClientId());
        assertEquals("challenge", session.getCodeChallenge());
        assertEquals("S256", session.getCodeChallengeMethod());
        assertEquals("test_scope", session.getScope());
        assertNotNull(session.getExpiresAt());
    }

    @Test
    public void should_createSession_when_expiresAtIsNull() {
        verifyResponse.setExpiresAt(null);
        when(credentialConfigRepository.findByCredentialConfigKeyId(anyString()))
                .thenReturn(Optional.of(activeConfig("test_scope")));

        IarSession session = iarSessionService.createIarSession(
                iarRequest, verifyResponse, "auth-1", "txn-1");

        assertNull(session.getExpiresAt());
    }

    @Test
    public void should_throwException_when_authorizationDetailsMissing() {
        verifyResponse.setAuthorizationDetails(null);
        assertThrows(CertifyException.class, () ->
                iarSessionService.createIarSession(iarRequest, verifyResponse, "auth-1", "txn-1"));
    }

    @Test
    public void should_throwException_when_responseUriMissing() {
        verifyResponse.getAuthorizationDetails().setResponseUri("");
        assertThrows(CertifyException.class, () ->
                iarSessionService.createIarSession(iarRequest, verifyResponse, "auth-1", "txn-1"));
    }

    @Test
    public void should_throwException_when_authDetailsMissingInRequest() {
        iarRequest.setAuthorizationDetails(List.of());
        assertThrows(CertifyException.class, () ->
                iarSessionService.createIarSession(iarRequest, verifyResponse, "auth-1", "txn-1"));
    }

    @Test
    public void should_throwException_when_credentialConfigIdMissing() {
        AuthorizationDetail detail = new AuthorizationDetail();
        detail.setCredentialConfigurationId("");
        iarRequest.setAuthorizationDetails(List.of(detail));
        assertThrows(CertifyException.class, () ->
                iarSessionService.createIarSession(iarRequest, verifyResponse, "auth-1", "txn-1"));
    }

    @Test
    public void should_throwException_when_configNotFound() {
        when(credentialConfigRepository.findByCredentialConfigKeyId("cred-config-1"))
                .thenReturn(Optional.empty());
        assertThrows(CertifyException.class, () ->
                iarSessionService.createIarSession(iarRequest, verifyResponse, "auth-1", "txn-1"));
    }

    @Test
    public void should_throwException_when_configInactive() {
        CredentialConfig config = activeConfig("test_scope");
        config.setStatus("inactive");
        when(credentialConfigRepository.findByCredentialConfigKeyId("cred-config-1"))
                .thenReturn(Optional.of(config));
        assertThrows(CertifyException.class, () ->
                iarSessionService.createIarSession(iarRequest, verifyResponse, "auth-1", "txn-1"));
    }

    @Test
    public void should_throwException_when_scopeMissing() {
        when(credentialConfigRepository.findByCredentialConfigKeyId("cred-config-1"))
                .thenReturn(Optional.of(activeConfig(null)));
        assertThrows(CertifyException.class, () ->
                iarSessionService.createIarSession(iarRequest, verifyResponse, "auth-1", "txn-1"));
    }

    @Test
    public void should_validateAuthSession_when_variousInputsProvided() {
        when(iarSessionRepository.findByAuthSession("present")).thenReturn(Optional.of(new IarSession()));
        when(iarSessionRepository.findByAuthSession("absent")).thenReturn(Optional.empty());
        assertTrue(iarSessionService.isValidAuthSession("present"));
        assertFalse(iarSessionService.isValidAuthSession("absent"));
    }

    @Test
    public void should_returnSession_when_authSessionFound() {
        IarSession existing = new IarSession();
        existing.setAuthSession("present");
        when(iarSessionRepository.findByAuthSession("present")).thenReturn(Optional.of(existing));
        assertEquals("present", iarSessionService.getSessionByAuthSession("present").getAuthSession());
    }

    @Test
    public void should_throwException_when_authSessionNotFound() {
        when(iarSessionRepository.findByAuthSession("absent")).thenReturn(Optional.empty());
        assertThrows(CertifyException.class, () -> iarSessionService.getSessionByAuthSession("absent"));
    }
}

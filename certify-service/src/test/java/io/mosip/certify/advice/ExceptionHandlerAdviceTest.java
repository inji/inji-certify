package io.mosip.certify.advice;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import io.mosip.certify.core.dto.VCError;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;

public class ExceptionHandlerAdviceTest {

    private final ExceptionHandlerAdvice advice = new ExceptionHandlerAdvice();
    private final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

    @Test
    public void should_returnInvalidRequest_when_unrecognizedPropertyIsProvided() {
        JsonParser parser = Mockito.mock(JsonParser.class);
        Mockito.when(parser.getCurrentLocation()).thenReturn(com.fasterxml.jackson.core.JsonLocation.NA);
        UnrecognizedPropertyException cause = UnrecognizedPropertyException.from(
                parser, Object.class, "unrecognized_field", null
        );
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", cause, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Unrecognized field 'unrecognized_field' in request", response.getBody().getError_description());
    }

    @Test
    public void should_returnInvalidRequest_when_fieldFormatIsInvalid() {
        InvalidFormatException cause = InvalidFormatException.from(
                null, "msg", "value", String.class
        );
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", cause, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Invalid format for field 'unknown' in request", response.getBody().getError_description());
    }

    @Test
    public void should_returnInvalidRequest_when_jsonSyntaxIsMalformed() {
        JsonParseException cause = new JsonParseException(null, "msg");
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", cause, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Malformed JSON syntax error", response.getBody().getError_description());
    }

    @Test
    public void should_returnInvalidRequest_when_requestStructureIsInvalid() {
        JsonMappingException cause = JsonMappingException.from(
                (JsonParser) null, "msg"
        );
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", cause, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Invalid request structure for field 'unknown'", response.getBody().getError_description());
    }

    @Test
    public void should_returnInvalidRequest_when_requestBodyIsUnreadable() {
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("msg", (Throwable) null, null);

        ResponseEntity<VCError> response = advice.handleVCIControllerExceptions(ex, request);

        Assert.assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assert.assertEquals("invalid_request", response.getBody().getError());
        Assert.assertEquals("Invalid JSON request body", response.getBody().getError_description());
    }
}

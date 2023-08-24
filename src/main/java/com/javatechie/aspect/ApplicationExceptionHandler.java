package com.javatechie.aspect;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApplicationExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleJwtException(Exception ex) {
        ProblemDetail pd = null;
        if (ex instanceof BadCredentialsException) {
            pd = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401), ex.getMessage());
            pd.setProperty("access_denied_reason", "authentication_failure");
        }
        if (ex instanceof AccessDeniedException) {
            pd = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), ex.getMessage());
            pd.setProperty("access_denied_reason", "not_authorized");
        }
        if (ex instanceof ExpiredJwtException) {
            pd = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), ex.getMessage());
            pd.setProperty("access_denied_reason", "JWT Token already expired !");
        }
        if (ex instanceof SignatureException) {
            pd = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), ex.getMessage());
            pd.setProperty("access_denied_reason", "JWT Signature not valid");
        }
        return pd;
    }
}

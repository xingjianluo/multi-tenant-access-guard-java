package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/** 统一异常处理：内部错误只记录日志，向调用方返回通用错误，不暴露内部细节。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(CredentialException.class)
    public ResponseEntity<Map<String, Object>> credential(CredentialException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "UNAUTHORIZED");
        body.put("reason", e.reason().name());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> internal(Exception e) {
        log.error("internal error", e);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "INTERNAL_ERROR");
        body.put("reason", "INTERNAL_ERROR");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}

package com.github.highcumontoa.tokenrotationaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class AbstractApiTest {

    protected static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    protected TestRestTemplate rest;

    protected record LoginBundle(String accessToken, String refreshToken, String sessionId,
                                 String accessTokenId, String refreshTokenId) {
    }

    protected LoginBundle login(String username, String password) {
        String body = """
                {"username":"%s","password":"%s"}""".formatted(username, password);
        ResponseEntity<String> resp = post("/api/auth/login", body, null);
        if (resp.getStatusCode() != HttpStatus.OK) {
            throw new IllegalStateException("login failed: " + resp.getStatusCode() + " " + resp.getBody());
        }
        return parseBundle(resp.getBody());
    }

    protected LoginBundle refresh(String refreshToken) {
        String body = """
                {"refreshToken":"%s"}""".formatted(refreshToken);
        ResponseEntity<String> resp = post("/api/auth/refresh", body, null);
        if (resp.getStatusCode() != HttpStatus.OK) {
            throw new IllegalStateException("refresh failed: " + resp.getStatusCode() + " " + resp.getBody());
        }
        return parseBundle(resp.getBody());
    }

    protected static LoginBundle parseBundle(String body) {
        try {
            JsonNode json = MAPPER.readTree(body);
            return new LoginBundle(json.get("accessToken").asText(),
                    json.get("refreshToken").asText(),
                    json.get("sessionId").asText(),
                    json.get("accessTokenId").asText(),
                    json.get("refreshTokenId").asText());
        } catch (Exception e) {
            throw new IllegalStateException("bad token response: " + body, e);
        }
    }

    protected ResponseEntity<String> post(String path, String jsonBody, String bearer) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/json");
        if (bearer != null) {
            headers.setBearerAuth(bearer);
        }
        return rest.exchange(path, HttpMethod.POST,
                new HttpEntity<>(jsonBody, headers), String.class);
    }

    protected ResponseEntity<String> get(String path, String bearer) {
        HttpHeaders headers = new HttpHeaders();
        if (bearer != null) {
            headers.setBearerAuth(bearer);
        }
        return rest.exchange(path, HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
    }

    protected static JsonNode json(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}

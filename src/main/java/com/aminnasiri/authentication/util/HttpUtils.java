package com.aminnasiri.authentication.util;

import jakarta.servlet.http.HttpServletRequest;

public final class HttpUtils {

    private static final String[] IP_HEADERS = {
            "X-Real-IP"
    };

    public static String getRequestIP(HttpServletRequest request) {
        for (String header: IP_HEADERS) {
            String value = request.getHeader(header);
            if (value == null || value.isEmpty()) {
                continue;
            }
            String[] parts = value.split("\\s*,\\s*");
            return parts[0];
        }
        return request.getRemoteAddr();
    }
}

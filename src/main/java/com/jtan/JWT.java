package com.jtan;

import org.apache.commons.codec.binary.Base64;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.jtan.Utility.ensure;
import static javax.xml.crypto.dsig.SignatureMethod.HMAC_SHA256;


class HMAC {
    public static String hexFromBytes(byte[] array) {
        String hex = new BigInteger(1, array).toString(16);
        // 1 byte => 2 hex
        int zeroLength = array.length * 2 - hex.length();
        for (int i = 0; i < zeroLength; i++) {
            hex = "0" + hex;
        }
        return hex;
    }

    public static byte[] sign(String key, String message) {
        try {
            byte[] byteKey = key.getBytes(StandardCharsets.UTF_8);
            // 摘要算法用 HmacSHA256
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(byteKey, HMAC_SHA256);
            sha256Hmac.init(keySpec);
            byte[] result = sha256Hmac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return result;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static Boolean verify(String key, String message, String signature) {
        byte[] sBytes = HMAC.sign(key, message);
        String s = HMAC.hexFromBytes(sBytes);
        return s.equals(signature);
    }

    public static void testSign() {
        String message = "this is message";
        String key = "my_key";
        String e = "d60e67d31a36836fc66b45cc146f562dfa4a60b1a65b526c1e64c8314607c0f5";
        ensure(verify(key, message, e), "testSign");
    }

    public static void main(String[] args) {
        testSign();
    }
}


public class JWT {
    public static String JSONEncodeBase64(JSONObject object) {
        // 将一个 JSONObject 对象转成 base64 编码的字符串
        String json = JSON.toJSONString(object);
        String r = Base64.encodeBase64URLSafeString(json.getBytes());
        return r;
    }

    public static String jwt(String key, JSONObject header, JSONObject payload) {
        String hBase64 = JSONEncodeBase64(header);
        String payloadBase64 = JSONEncodeBase64(payload);
        String sBase64 = String.format("%s.%s", hBase64, payloadBase64);

        byte[] sBytes = HMAC.sign(key, sBase64);
        String signatureBase64 = Base64.encodeBase64URLSafeString(sBytes);

        String jwtToken = String.format("%s.%s.%s", hBase64, payloadBase64, signatureBase64);
        return jwtToken;
    }

    public static void testJSONEncodeBase64() {
        JSONObject header = new JSONObject(true);
        header.put("typ", "JWT");
        header.put("alg", "HS256");

        JSONObject payload = new JSONObject(true);
        payload.put("sub", "1234567890");
        payload.put("name", "John Doe");
        payload.put("iat", 1516239022);

        String headerString = JSONEncodeBase64(header);
        String payloadString = JSONEncodeBase64(payload);
        String r = String.format("%s.%s", headerString, payloadString);
        String e = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        ensure(r.equals(e), "testJSONEncodeBase64");
    }

    public static void testJWT() {
        JSONObject header = new JSONObject(true);
        header.put("typ", "JWT");
        header.put("alg", "HS256");

        JSONObject payload = new JSONObject(true);
        payload.put("sub", "1234567890");
        payload.put("name", "John Doe");
        payload.put("iat", 1516239022);

        String key = "my-secret";
        String r = jwt(key, header, payload);
        String e = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.j7vwW1sfcOmnR4tTCVMZfJCFVjwnQh0ajARTY2Q9nMw";
        ensure(r.equals(e), "testJWT");
    }

    public static void main(String[] args) {
        // testJSONEncodeBase64();
        testJWT();
    }
}

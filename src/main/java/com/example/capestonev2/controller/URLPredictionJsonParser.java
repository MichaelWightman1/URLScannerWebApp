package com.example.capestonev2.controller;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

@Component
public class URLPredictionJsonParser {

    public static boolean checkPredictionValue(String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            throw new IllegalArgumentException("Input JSON string cannot be null or empty");
        }

        JSONObject jsonObject = new JSONObject(jsonString);
        String message = jsonObject.getString("message");

        if (message.equalsIgnoreCase("URL is Malicious")) {
            return false;
        } else if (message.equalsIgnoreCase("URL is safe")) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean checkHttpsValue(String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            throw new IllegalArgumentException("Input JSON string cannot be null or empty");
        }

        JSONObject outerJsonObject = new JSONObject(jsonString);
        String featuresString = outerJsonObject.getString("features");

        featuresString = featuresString.substring(1, featuresString.length()-1);
        featuresString = featuresString.replace("\\", "");

        JSONObject jsonObject;
        try {
            jsonObject = new JSONObject(featuresString);
        } catch (JSONException e) {
            throw new JSONException("Error processing input JSON");
        } catch (Exception e) {
            throw new JSONException("Unexpected error occurred while processing JSON");
        }

        if(jsonObject.has("https")) {
            double httpsValue = jsonObject.getDouble("https");

            if (httpsValue == 0.0) {
                return false;
            } else if (httpsValue == 1.0) {
                return true;
            } else {
                return false;
            }
        } else {
            throw new JSONException("Invalid JSON structure");
        }
    }

    public static boolean checkTldValue(String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            throw new IllegalArgumentException("Input JSON string cannot be null or empty");
        }

        JSONObject outerJsonObject = new JSONObject(jsonString);
        String featuresString = outerJsonObject.getString("features");

        JSONObject jsonObject;
        try {
            JSONArray jsonArray = new JSONArray(featuresString);
            jsonObject = jsonArray.getJSONObject(0);
        } catch (JSONException e) {
            throw new JSONException("Error processing input JSON");
        } catch (Exception e) {
            throw new JSONException("Unexpected error occurred while processing JSON");
        }

        if(jsonObject.has("valid_tld")) {
            double tldValue = jsonObject.getDouble("valid_tld");

            if (tldValue == 0.0) {
                return false;
            } else if (tldValue == 1.0) {
                return true;
            } else {
                return false;
            }
        } else {
            throw new JSONException("Invalid JSON structure");
        }
    }
}

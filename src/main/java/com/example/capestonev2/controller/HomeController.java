package com.example.capestonev2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.example.capestonev2.controller.LevenshteinDistanceCalculator.levDistance;
import static com.example.capestonev2.controller.URLPredictionJsonParser.*;

@Controller
public class HomeController {

    private final URLPredictionService predictionService;


    @Autowired
    public HomeController(@Lazy URLPredictionService predictionService) {
        this.predictionService = predictionService;
    }


    @PostMapping("/process")
    @ResponseBody
    public Map<String, String> process(@RequestParam(name = "url") String parseurl, Model model) {

        Map<String, String> response = new HashMap<>();

        try {
            URL url = new URL(parseurl);
            String prediction = predictionService.predict(parseurl);
            String urlInput = url.getHost();
            String[] parts = urlInput.split("\\.");
            String primaryDomain = parts[parts.length - 2] + "." + parts[parts.length - 1];

            int levDistanceValue = levDistance(primaryDomain);
            boolean isPredictionValueValid = checkPredictionValue(prediction);

            String bottomCardHeading1 = "N/A";
            String color1 = "#b4b5b6";
            String bottomCardText1 = "";

            String bottomCardHeading2 = "N/A";
            String color2 = "#b4b5b6";
            String bottomCardText2 = "";

            String urlInsights = "";

            if (!isPredictionValueValid) {
                bottomCardHeading1 = "Malicious";
                color1 = "#AC270A";
                bottomCardText1 = "This URL is possibly malicious and contains cyber threats.";
            } else {
                bottomCardHeading1 = "Safe";
                color1 = "#0B8750";
                bottomCardText1 = "This URL is likely safe and clear from cyber threats.";
            }
            switch (levDistanceValue) {
                case 0:
                    bottomCardHeading2 = isPredictionValueValid ? "Verified" : "N/A";
                    color2 = isPredictionValueValid ? "#0B8750" : "#b4b5b6";
                    bottomCardText2 = isPredictionValueValid ? "We can confirm that this URL belongs to a popular website." : "";
                    break;
                case 1:
                    bottomCardHeading2 = "Deceptive";
                    color2 = "#AC270A";
                    bottomCardText2 = "This URL is likely attempting to deceive you and pose as a popular website. Use a high degree of caution.";
                    if (isPredictionValueValid) {
                        bottomCardText1 = "";
                        bottomCardHeading1 = "N/A";
                        color1 = "#b4b5b6";
                    }
                    break;
                case 2:
                    bottomCardHeading2 = "Caution";
                    color2 = "#C36D0C";
                    bottomCardText2 = "This URL may be attempting to deceive you and pose as a popular website";
                    break;
                case 3:
                    bottomCardHeading2 = "Unknown";
                    color2 = "#b4b5b6";
                    bottomCardText2 = "This URL likely belongs to a site that does not receive much traffic";
                    break;
            }
            if (isPredictionValueValid && levDistanceValue == 0) {
                urlInsights += "The URL provided is likely safe and free of cyber threats ";
            }

            if (!checkHttpsValue(prediction)) {
                urlInsights += "The URL provided contains a scheme that raises concern. ";
            }

            if (!checkTldValue(prediction)) {
                urlInsights += "The URL provided contains a top-level domain that is not commonly used and raises concern. ";
            }
            urlInsights += "Please note that this tool does not determine if the URL is clear of adult or inappropriate content. ";
            response.put("bottom-card-heading-1", bottomCardHeading1);
            response.put("color-1", color1);
            response.put("bottom-card-text-1", bottomCardText1);
            response.put("bottom-card-heading-2", bottomCardHeading2);
            response.put("color-2", color2);
            response.put("bottom-card-text-2", bottomCardText2);
            response.put("bottom-card-text-3", urlInsights);

        } catch (MalformedURLException e) {
            response.put("bottom-card-text-1", "There was an error when parsing the URL provided. Please ensure all four components of the URL above are included.");
            response.put("bottom-card-text-2", " ");
            response.put("bottom-card-text-3", " ");
            response.put("bottom-card-heading-1", "N/A");
            response.put("bottom-card-heading-2", "N/A");
            response.put("color-1", "#b4b5b6");
            response.put("color-2", "#b4b5b6");
        } catch (Exception e) {
            response.put("bottom-card-text-1", "There was an error when parsing the URL provided. Please ensure all four components of the URL above are included.");
            response.put("bottom-card-text-2", " ");
            response.put("bottom-card-text-3", " ");
            response.put("bottom-card-heading-1", "N/A");
            response.put("bottom-card-heading-2", "N/A");
            response.put("color-1", "#b4b5b6");
            response.put("color-2", "#b4b5b6");
        }
        return response;
    }

@Configuration
class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@Service
class URLPredictionService {
    private final RestTemplate restTemplate;

    public URLPredictionService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String predict(String url) {
        Map<String, String> body = new HashMap<>();
        body.put("url", url);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<Map<String, String>> httpEntity = new HttpEntity<>(body, headers);
        String response = restTemplate.postForObject("http://localhost:5000/predict", httpEntity, String.class);

        return response;
    }
}


@RestController
class URLPredictionController {
    private final URLPredictionService predictionService;

    public URLPredictionController(@Lazy URLPredictionService predictionService) {
        this.predictionService = predictionService;
    }

    @PostMapping("/predict-url")
    public ResponseEntity<String> predict(@RequestBody String url) {
        String prediction = predictionService.predict(url);
        return ResponseEntity.ok(prediction);
    }
}

}




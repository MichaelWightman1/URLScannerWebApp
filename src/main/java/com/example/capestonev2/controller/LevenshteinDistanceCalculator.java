package com.example.capestonev2.controller;

import org.springframework.stereotype.Component;

@Component
public class LevenshteinDistanceCalculator {

    static int levDistance(String host) {
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("Host cannot be null or empty");
        }

        int output = 3;
        for (String string : WebList.getWebsites()) {
            if (string == null || string.isEmpty()) {
                continue;
            }

            int distance = levDistanceCalc(host, string);

            switch (distance) {
                case 0:
                case 1:
                    return distance;
                case 2:
                case 3:
                    return 2;
                default:
                    continue;
            }
        }
        return output;
    }

    private static int levDistanceCalc(CharSequence lhs, CharSequence rhs) {
        if (lhs == null || rhs == null) {
            throw new IllegalArgumentException("lhs and rhs cannot be null");
        }

        int len0 = lhs.length() + 1;
        int len1 = rhs.length() + 1;

        int[] cost = new int[len0];
        int[] newCost = new int[len0];

        for (int i = 0; i < len0; i++) {
            cost[i] = i;
        }

        for (int j = 1; j < len1; j++) {
            newCost[0] = j;

            for (int i = 1; i < len0; i++) {
                int match = (lhs.charAt(i - 1) == rhs.charAt(j - 1)) ? 0 : 1;

                int costReplace = cost[i - 1] + match;
                int costInsert  = cost[i] + 1;
                int costDelete  = newCost[i - 1] + 1;

                newCost[i] = Math.min(Math.min(costInsert, costDelete), costReplace);
            }

            int[] swap = cost;
            cost = newCost;
            newCost = swap;
        }

        return cost[len0 - 1];
    }
}

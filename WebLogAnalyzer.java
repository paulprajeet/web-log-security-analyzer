import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class WebLogAnalyzer {

    static class LogEntry {
        String ip, timestamp, method, url, status, userAgent;
        int riskScore = 0;
        List<String> detectedThreats = new ArrayList<>();
    }

    static Map<String, Integer> ipRequests        = new HashMap<>();
    static Map<String, Integer> ip404Count         = new HashMap<>();
    static Map<String, Integer> ipFailedLogins     = new HashMap<>();
    static Map<String, Boolean> ipSuccessAfterFail = new HashMap<>();
    static Map<String, Integer> ipAuthErrors       = new HashMap<>();
    static Map<String, Set<String>> ipUniqueURLs   = new HashMap<>();
    static Map<String, Integer> ipRiskScores       = new HashMap<>();
    static Map<String, Set<String>> ipThreats      = new HashMap<>();
    static Map<String, Integer> attackPatterns     = new HashMap<>();
    static List<LogEntry> suspiciousLogs           = new ArrayList<>();
    static Map<String, Integer> ipWildcardCount = new HashMap<>();

    // ip -> url -> list of epoch-second timestamps  (for rapid-hit detection)
    static Map<String, Map<String, List<Long>>> ipUrlTimestamps = new HashMap<>();

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println("Usage: java WebLogAnalyzer <logfile>");
            return;
        }
        analyzeLog(args[0]);
        generateMLReport();
        exportDashboardData();
        System.out.println("\nDashboard data exported to dashboard-data.json");
    }

    private static LogEntry parseLogLine(String line) {
        line = line.trim();
        if (line.matches("\\d+\\.\\d+\\.\\d+\\.\\d+:")) return null;
        if (line.startsWith("TIME")) return null;

        Pattern p = Pattern.compile(
            "(\\S+)\\s+(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\s+\"([^\"]+)\"(?:\\s+\\{[^}]*\\})?\\s+(\\d{3})"
        );
        Matcher m = p.matcher(line);
        if (!m.find()) return null;

        LogEntry entry  = new LogEntry();
        entry.timestamp = m.group(1);
        entry.method    = m.group(2);
        entry.url       = m.group(3);
        entry.status    = m.group(4);
        return entry;
    }

    static long parseTimestamp(String ts) {
        try {
            ts = ts.replace("T", " ").replace(".000Z", "").replace("Z", "");
            java.time.LocalDateTime ldt = java.time.LocalDateTime.parse(
                ts, java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            );
            return ldt.toEpochSecond(java.time.ZoneOffset.UTC);
        } catch (Exception e) {
            return 0;
        }
    }

    private static void analyzeLog(String filename) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get("samples/" + filename));
        String currentIP = "unknown";
        Pattern ipHeader = Pattern.compile("^(\\d+\\.\\d+\\.\\d+\\.\\d+):$");

        for (String line : lines) {
            line = line.trim();

            Matcher ipMatcher = ipHeader.matcher(line);
            if (ipMatcher.matches()) {
                currentIP = ipMatcher.group(1);
                continue;
            }

            LogEntry entry = parseLogLine(line);
            if (entry == null) continue;
            entry.ip = currentIP;

            ipRequests.put(entry.ip, ipRequests.getOrDefault(entry.ip, 0) + 1);

            if ("401".equals(entry.status) || "403".equals(entry.status))
                ipAuthErrors.put(entry.ip, ipAuthErrors.getOrDefault(entry.ip, 0) + 1);

            if ("404".equals(entry.status))
                ip404Count.put(entry.ip, ip404Count.getOrDefault(entry.ip, 0) + 1);

            String urlLower    = entry.url.toLowerCase();
            boolean isLoginPage = urlLower.contains("/login")  ||
                                  urlLower.contains("/signin") ||
                                  urlLower.contains("/wp-login");
            if (isLoginPage) {
                if ("401".equals(entry.status) || "403".equals(entry.status))
                    ipFailedLogins.put(entry.ip, ipFailedLogins.getOrDefault(entry.ip, 0) + 1);
                if ("200".equals(entry.status) && ipFailedLogins.getOrDefault(entry.ip, 0) >= 3)
                    ipSuccessAfterFail.put(entry.ip, true);
            }

            ipUniqueURLs.putIfAbsent(entry.ip, new HashSet<>());
            ipUniqueURLs.get(entry.ip).add(entry.url);
            if (entry.url.contains("=*")) {
                ipWildcardCount.put(entry.ip, ipWildcardCount.getOrDefault(entry.ip, 0) + 1);
            }

            // Record timestamp per IP per URL for rapid-hit detection
            long ts = parseTimestamp(entry.timestamp);
            if (ts > 0) {
                ipUrlTimestamps
                    .computeIfAbsent(entry.ip, k -> new HashMap<>())
                    .computeIfAbsent(entry.url, k -> new ArrayList<>())
                    .add(ts);
            }

            int score = calculateRiskScore(entry);
            if (score > 0) {
                ipRiskScores.put(entry.ip, ipRiskScores.getOrDefault(entry.ip, 0) + score);
                suspiciousLogs.add(entry);
                for (String threat : entry.detectedThreats) {
                    attackPatterns.put(threat, attackPatterns.getOrDefault(threat, 0) + 1);
                    ipThreats.computeIfAbsent(entry.ip, k -> new HashSet<>()).add(threat);
                }
            }
        }

        postScanChecks();
    }

    static int calculateRiskScore(LogEntry entry) {
        int score = 0;
        String url = entry.url      != null ? entry.url.toLowerCase()       : "";
        String ua  = entry.userAgent != null ? entry.userAgent.toLowerCase() : "";

        // SQL Injection
        if (url.contains("select") || url.contains("union") || url.contains("1=1") ||
            url.contains("drop")   || url.contains("'")     || url.contains("--")   ||
            url.contains("%27")    || url.contains("sleep(")) {
            score += 90;
            entry.detectedThreats.add("SQL_INJECTION");
        }

        // XSS
        if (url.contains("<script>")  || url.contains("javascript:") ||
            url.contains("onerror=")  || url.contains("alert(")      ||
            url.contains("%3cscript") || url.contains("onload=")) {
            score += 85;
            entry.detectedThreats.add("XSS");
        }

        // Directory Traversal
        if (url.contains("../")         || url.contains("..%2f")      ||
            url.contains("/etc/passwd") || url.contains("/etc/shadow")) {
            score += 85;
            entry.detectedThreats.add("DIRECTORY_TRAVERSAL");
        }

        // Sensitive Endpoint Access
        if (url.contains("/admin")     || url.contains("/config")     ||
            url.contains("/backup")    || url.contains("/.env")       ||
            url.contains("/.git")      || url.contains("/phpmyadmin") ||
            url.contains("/wp-config") || url.contains("/.htaccess")) {
            score += 25;
            entry.detectedThreats.add("SENSITIVE_ENDPOINT");
        }

        // Malicious Bot
        if (ua.contains("bot") || ua.contains("crawler") || ua.contains("spider")) {
            boolean trusted = ua.contains("googlebot") || ua.contains("bingbot") ||
                              ua.contains("slurp")     || ua.contains("duckduckbot");
            if (!trusted) { score += 20; entry.detectedThreats.add("MALICIOUS_BOT"); }
        }

        // Credential Stuffing
        if (ipSuccessAfterFail.getOrDefault(entry.ip, false) &&
                !entry.detectedThreats.contains("CREDENTIAL_STUFFING")) {
            score += 70;
            entry.detectedThreats.add("CREDENTIAL_STUFFING");
        }

        // LOW SIGNAL: Wildcard API enumeration (factory=* or machine=*)
        

        // LOW SIGNAL: Unusual HTTP methods
        if ("DELETE".equals(entry.method) || "PUT".equals(entry.method) ||
            "PATCH".equals(entry.method)  || "OPTIONS".equals(entry.method)) {
            score += 10;
            entry.detectedThreats.add("UNUSUAL_METHOD");
        }

        return score;
    }

    static void postScanChecks() {
        int totalRequests = ipRequests.values().stream().mapToInt(Integer::intValue).sum();
        int totalIPs      = ipRequests.size();
        int avgRequests   = totalIPs > 0 ? totalRequests / totalIPs : 5;

        for (String ip : ipRequests.keySet()) {
            int reqs  = ipRequests.get(ip);
            int score = 0;
            Set<String> threats = ipThreats.computeIfAbsent(ip, k -> new HashSet<>());

            // HIGH VOLUME — 2x above average
            if (reqs > avgRequests * 2) {
                score += 40;
                threats.add("HIGH_VOLUME");
                attackPatterns.put("HIGH_VOLUME", attackPatterns.getOrDefault("HIGH_VOLUME", 0) + 1);
            }

            // ELEVATED TRAFFIC — between avg and 2x avg (medium signal)
            if (reqs > avgRequests * 1.5 && reqs <= avgRequests * 2) {
                score += 15;
                threats.add("ELEVATED_TRAFFIC");
                attackPatterns.put("ELEVATED_TRAFFIC", attackPatterns.getOrDefault("ELEVATED_TRAFFIC", 0) + 1);
            }

            // BRUTE FORCE — 5+ failed login POSTs
            int loginCount = ipFailedLogins.getOrDefault(ip, 0);
            if (loginCount >= 5) {
                score += 80;
                threats.add("BRUTE_FORCE");
                attackPatterns.put("BRUTE_FORCE", attackPatterns.getOrDefault("BRUTE_FORCE", 0) + 1);
            }

            // LINEAR 404 SCORING — +8 per 404, capped at 60
            int notFound = ip404Count.getOrDefault(ip, 0);
            if (notFound > 0) {
                score += Math.min(notFound * 8, 60);
                String label = notFound >= 5 ? "404_FLOOD" : "404_ERRORS";
                threats.add(label);
                attackPatterns.put(label, attackPatterns.getOrDefault(label, 0) + 1);
            }

            int failedAuth = ipAuthErrors.getOrDefault(ip, 0);
            if (failedAuth >= 10) {
                score += 65;
                threats.add("AUTH_FLOOD");
                attackPatterns.put("AUTH_FLOOD", attackPatterns.getOrDefault("AUTH_FLOOD", 0) + 1);
            } else if (failedAuth >= 5) {
                score += 15 + (failedAuth - 3) * 8;
                threats.add("AUTH_ANOMALY");
                attackPatterns.put("AUTH_ANOMALY", attackPatterns.getOrDefault("AUTH_ANOMALY", 0) + 1);
            } 
            int wildcardCount = ipWildcardCount.getOrDefault(ip, 0);
            if (wildcardCount >= 20) {
            // Excessive wildcard use — enumeration attack
                score += 60;
                threats.add("WILDCARD_ENUMERATION");
                attackPatterns.put("WILDCARD_ENUMERATION",
                attackPatterns.getOrDefault("WILDCARD_ENUMERATION", 0) + 1);
            } else if (wildcardCount >= 15) {
            // Moderate wildcard use — suspicious but could be normal
                score += 20;
                threats.add("WILDCARD_ENUMERATION");
                attackPatterns.put("WILDCARD_ENUMERATION",
                attackPatterns.getOrDefault("WILDCARD_ENUMERATION", 0) + 1);
            }

            // RAPID ENDPOINT ACCESS — same URL hit 3+ times within 30 seconds
            // Score: +10 per URL that was rapid-hit, capped at 50
            Map<String, List<Long>> urlTimes = ipUrlTimestamps.getOrDefault(ip, new HashMap<>());
            int rapidURLs = 0;
            for (List<Long> times : urlTimes.values()) {
                if (times.size() < 5) continue;
                Collections.sort(times);
                for (int i = 0; i <= times.size() - 3; i++) {
                    if (times.get(i + 2) - times.get(i) <= 30) {
                        rapidURLs++;
                        break;
                    }
                }
            }
            if (rapidURLs > 0) {
                score += Math.min(rapidURLs * 10, 50);
                threats.add("RAPID_ENDPOINT_ACCESS");
                attackPatterns.put("RAPID_ENDPOINT_ACCESS",
                    attackPatterns.getOrDefault("RAPID_ENDPOINT_ACCESS", 0) + 1);
            }

            // BROAD URL SCANNING — 30+ unique URLs
            int uniqueURLcount = ipUniqueURLs.getOrDefault(ip, new HashSet<>()).size();
            if (uniqueURLcount >= 30) {
                score += 75;
                threats.add("URL_SCANNING");
                attackPatterns.put("URL_SCANNING", attackPatterns.getOrDefault("URL_SCANNING", 0) + 1);
            }

            if (score > 0)
                ipRiskScores.put(ip, ipRiskScores.getOrDefault(ip, 0) + score);
        }
    }

    static void generateMLReport() {
        System.out.println("\n" + "=".repeat(70));
        System.out.println("\uD83D\uDD0D WEB LOG SECURITY ANALYZER");
        System.out.println("=".repeat(70));

        long totalLogs     = ipRequests.values().stream().mapToInt(Integer::intValue).sum();
        long highRiskIPs   = ipRiskScores.values().stream().filter(r -> r >= 50).count();
        long mediumRiskIPs = ipRiskScores.values().stream().filter(r -> r >= 20 && r < 50).count();
        long lowRiskIPs    = ipRiskScores.values().stream().filter(r -> r > 0 && r < 20).count();

        System.out.printf("\uD83D\uDCCA TOTAL LOGS ANALYZED: %,d\n", totalLogs);
        System.out.printf("\uD83D\uDCE1 UNIQUE IPs DETECTED: %d\n", ipRequests.size());
        System.out.printf("\uD83D\uDEA8 HIGH RISK IPS   (50+)  : %d (%.1f%%)\n",
            highRiskIPs,   (highRiskIPs   * 100.0 / Math.max(ipRequests.size(), 1)));
        System.out.printf("\u26A0\uFE0F  MEDIUM RISK IPS (20-49): %d (%.1f%%)\n",
            mediumRiskIPs, (mediumRiskIPs * 100.0 / Math.max(ipRequests.size(), 1)));
        System.out.printf("\uD83D\uDD35 LOW RISK IPS    (1-19) : %d (%.1f%%)\n",
            lowRiskIPs,    (lowRiskIPs    * 100.0 / Math.max(ipRequests.size(), 1)));

        System.out.println("\n\uD83D\uDD25 TOP IPs BY RISK SCORE:");
        System.out.println("IP Address          | Requests | Risk | Status");
        System.out.println("-".repeat(50));

        ipRiskScores.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .forEach(e -> {
                String ip    = e.getKey();
                int requests = ipRequests.getOrDefault(ip, 0);
                int risk     = e.getValue();
                String status = risk >= 50 ? "\uD83D\uDD34 HIGH"
                              : risk >= 20 ? "\uD83D\uDFE1 MEDIUM"
                              :              "\uD83D\uDD35 LOW";
                System.out.printf("%-18s | %7d | %4d | %s\n", ip, requests, risk, status);
            });

        System.out.println("\n\uD83C\uDFAF TOP ATTACK PATTERNS:");
        attackPatterns.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(8)
            .forEach(e -> System.out.printf("  %-30s : %d occurrences\n", e.getKey(), e.getValue()));

        long flagged = ipRiskScores.values().stream().filter(r -> r > 0).count();
        System.out.printf("\n\uD83D\uDEE1\uFE0F  SUSPICIOUS IPs FLAGGED: %d\n", flagged);
        System.out.println("=".repeat(70));
    }

    static void exportDashboardData() throws IOException {
        try (PrintWriter out = new PrintWriter(new FileWriter("dashboard-data.json"))) {
            long totalLogs   = ipRequests.values().stream().mapToInt(Integer::intValue).sum();
            long highRiskIPs = ipRiskScores.values().stream().filter(r -> r >= 50).count();
            long flaggedCount = ipRiskScores.values().stream().filter(r -> r > 0).count();  

            out.println("{");
            out.println("  \"totalLogs\": "     + totalLogs             + ",");
            out.println("  \"uniqueIps\": "      + ipRequests.size()     + ",");
            out.println("  \"highRiskIps\": "    + highRiskIPs           + ",");
            out.println("  \"suspiciousLogs\": " + flaggedCount      + ",");

            out.println("  \"attackPatterns\": {");
            List<Map.Entry<String, Integer>> patternList = new ArrayList<>(attackPatterns.entrySet());
            for (int i = 0; i < patternList.size(); i++) {
                String comma = (i < patternList.size() - 1) ? "," : "";
                out.println("    \"" + patternList.get(i).getKey() + "\": "
                    + patternList.get(i).getValue() + comma);
            }
            out.println("  },");

            out.println("  \"ipData\": [");
            List<Map.Entry<String, Integer>> sorted = new ArrayList<>(ipRiskScores.entrySet());
            sorted.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));

            for (int i = 0; i < sorted.size(); i++) {
                String ip        = sorted.get(i).getKey();
                int    risk      = sorted.get(i).getValue();
                int    reqs      = ipRequests.getOrDefault(ip, 0);
                int    notFound  = ip404Count.getOrDefault(ip, 0);
                int    authErrs  = ipAuthErrors.getOrDefault(ip, 0);
                int    failLog   = ipFailedLogins.getOrDefault(ip, 0);
                int    uniqueURL = ipUniqueURLs.getOrDefault(ip, new HashSet<>()).size();
                String status    = risk >= 50 ? "HIGH" : risk >= 20 ? "MEDIUM" : "LOW";
                Set<String> thr  = ipThreats.getOrDefault(ip, new HashSet<>());
                String comma     = (i < sorted.size() - 1) ? "," : "";

                out.println("    {");
                out.println("      \"ip\": \""           + ip        + "\",");
                out.println("      \"requests\": "       + reqs      + ",");
                out.println("      \"risk\": "           + risk      + ",");
                out.println("      \"status\": \""       + status    + "\",");
                out.println("      \"notFoundErrors\": " + notFound  + ",");
                out.println("      \"authErrors\": "     + authErrs  + ",");
                out.println("      \"failedLogins\": "   + failLog   + ",");
                out.println("      \"uniqueURLs\": "     + uniqueURL + ",");
                out.println("      \"threats\": \""      + String.join(", ", thr) + "\"");
                out.println("    }" + comma);
            }
            out.println("  ]");
            out.println("}");
        }
    }
}
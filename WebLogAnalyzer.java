import java.io.*;
import java.util.*;
import java.util.regex.*;

public class WebLogAnalyzer {
    static class LogEntry {
        String ip, method, url, status, userAgent;
        int riskScore = 0;
        
        LogEntry(String line) {
            if (line == null || line.trim().isEmpty()) return;
            String[] parts = line.split(" ");
            if (parts.length < 6) return;
            
            ip = parts[0].trim();
            if (parts.length > 6) {
                url = parts[6].replaceAll("[\\[\\]\"]", "").trim();
            } else {
                url = "/";
            }
            if (parts.length > 5) {
                method = parts[5].replaceAll("[\\[\\]\"]", "").trim();
            } else {
                method = "GET";
            }
            if (parts.length > 8) {
                status = parts[8].trim();
            } else {
                status = "200";
            }
            if (parts.length > 9) {
                userAgent = String.join(" ", Arrays.copyOfRange(parts, 9, parts.length)).trim();
            }
        }
    }

    static Map<String, Integer> ipRequests = new HashMap<>();
    static Map<String, Integer> attackPatterns = new HashMap<>();
    static List<LogEntry> suspiciousLogs = new ArrayList<>();
    static Map<String, Integer> ipRiskScores = new HashMap<>();

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println("Usage: java WebLogAnalyzer web_activity.log");
            return;
        }
        analyzeLog(args[0]);
        generateMLReport();
    }
    
    static void analyzeLog(String filename) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader("samples/" + filename))) {
            String line;
            String currentIP = null;
            
            while ((line = br.readLine()) != null) {
                line = line.trim();
                
                if (line.contains(":") && line.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
                    currentIP = line.split(":")[0].trim();
                    continue;
                }
                
                if (line.isEmpty() || line.contains("TIME") || line.contains("METHOD")) continue;
                
                if (currentIP != null && line.length() > 20) {
                    LogEntry entry = new LogEntry(currentIP + " " + line);
                    if (entry.ip != null) {
                        ipRequests.put(entry.ip, ipRequests.getOrDefault(entry.ip, 0) + 1);
                        int score = calculateRiskScore(entry);
                        entry.riskScore = score;
                        
                        int currentRisk = ipRiskScores.getOrDefault(entry.ip, 0);
                        if (score > 30) {
                            if (score >= 90) {
                                ipRiskScores.put(entry.ip, 100);
                            } else {
                                ipRiskScores.put(entry.ip, currentRisk + 1);
                            }
                            suspiciousLogs.add(entry);
                            detectAttackPatterns(entry);
                        }
                    }
                }
            }
        }
    }    
    
    static int calculateRiskScore(LogEntry entry) {
        if (entry.ip == null || entry.url == null) return 0;
        
        int score = 0;
        int avgRequests = 5;
        Integer ipCount = ipRequests.get(entry.ip);
        if (ipCount != null && ipCount > avgRequests * 3) score += 40;
        
        if (entry.url.contains("SELECT") || entry.url.contains("1=1") || 
            entry.url.contains("UNION") || entry.url.contains("'")) score += 90;
        
        if (entry.url.contains("<script>") || entry.url.contains("javascript:") ||
            entry.url.contains("onerror=")) score += 85;
        
        if (entry.userAgent != null && entry.userAgent.contains("bot") && 
            (entry.userAgent.contains("Google") || entry.userAgent.contains("Bing"))) {
            score += 60;
        }
        
        if (entry.url.contains("/wp-admin") || entry.url.contains("/phpmyadmin") ||
            entry.url.contains("/admin")) score += 70;
        
        if (entry.status != null && entry.status.equals("404")) {
            Integer ipCount2 = ipRequests.get(entry.ip);
            if (ipCount2 != null && ipCount2 > 10) score += 50;
        }
        
        return Math.min(score, 100);
    }

    static void detectAttackPatterns(LogEntry entry) {
        String pattern = getAttackType(entry.riskScore, entry.url, entry.userAgent);
        attackPatterns.put(pattern, attackPatterns.getOrDefault(pattern, 0) + 1);
    }
    
    static String getAttackType(int score, String url, String ua) {
        if (score >= 90) return "CRITICAL";
        if (score >= 70) return "SCANNER";
        if (score >= 50) return "BRUTEFORCE";
        return "SUSPICIOUS";
    }
    
    static void generateMLReport() {
    System.out.println("\n" + "=".repeat(70));
    System.out.println("🔍 WEB LOG SECURITY ANALYZER");
    System.out.println("=".repeat(70));
    
    long totalLogs = ipRequests.values().stream().mapToInt(Integer::intValue).sum();
    
    long highRiskIPs = ipRiskScores.values().stream().filter(risk -> risk >= 50).count();
    long mediumRiskIPs = ipRiskScores.values().stream().filter(risk -> risk >= 20 && risk < 50).count();
    
    System.out.printf("📊 TOTAL LOGS ANALYZED: %,d\n", totalLogs);
    System.out.printf("🚨 HIGH RISK IPS (50+): %d (%.1f%%)\n", highRiskIPs, (highRiskIPs*100.0/ipRiskScores.size()));
    System.out.printf("⚠️  MEDIUM RISK IPS (20-49): %d (%.1f%%)\n", mediumRiskIPs, (mediumRiskIPs*100.0/ipRiskScores.size()));
    
    System.out.println("\n🔥 TOP IPS BY RISK FACTOR:");
    System.out.println("IP Address          | Requests | Risk | Status");
    System.out.println("-".repeat(45));

    ipRiskScores.entrySet().stream()
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .limit(10)
        .forEach(e -> {
            String ip = e.getKey();
            int requests = ipRequests.getOrDefault(ip, 0);
            int risk = e.getValue();
            
           String status;
            if (risk >= 50) {
                status = "HIGH";
            } else if (risk >= 30) {
                status = "MEDIUM";
            } else {
                status = "LOW";
            }

            
            System.out.printf("%-18s | %7d | %4d | %s\n", ip, requests, risk, status);
        });

    System.out.println("\n🎯 TOP ATTACK PATTERNS:");
    attackPatterns.entrySet().stream()
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .limit(5)
        .forEach(e -> System.out.printf("  %s: %d occurrences\n", e.getKey(), e.getValue()));
}

}

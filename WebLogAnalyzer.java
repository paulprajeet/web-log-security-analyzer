import java.io.*;
import java.util.*;
import java.util.regex.*;

public class WebLogAnalyzer {
    static class LogEntry {
    String ip, method, url, status, userAgent;
    int riskScore = 0;
    
    LogEntry(String line) {
        // Skip completely empty lines only
        if (line == null || line.trim().isEmpty()) return;
        
        String[] parts = line.split(" ");
        if (parts.length < 6) return;  // Need minimum fields
        
        // Extract IP (first field)
        ip = parts[0].trim();
        
        // Extract URL (usually 6th field)
        if (parts.length > 6) {
            url = parts[6].replaceAll("[\\[\\]\"]", "").trim();
        } else {
            url = "/";
        }
        
        // Extract method (usually 5th field)  
        if (parts.length > 5) {
            method = parts[5].replaceAll("[\\[\\]\"]", "").trim();
        } else {
            method = "GET";
        }
        
        // Extract status (usually 8th field)
        if (parts.length > 8) {
            status = parts[8].trim();
        } else {
            status = "200";
        }
        
        // Extract user agent (everything after status)
        if (parts.length > 9) {
            userAgent = String.join(" ", Arrays.copyOfRange(parts, 9, parts.length)).trim();
        }
    }
}

    static Map<String, Integer> ipRequests = new HashMap<>();
    static Map<String, Integer> attackPatterns = new HashMap<>();
    static List<LogEntry> suspiciousLogs = new ArrayList<>();
    
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
            
            // NEW IP BLOCK DETECTED (starts with IP:)
            if (line.contains(":") && line.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
                currentIP = line.split(":")[0].trim();
                continue;
            }
            
            // Skip empty lines and headers
            if (line.isEmpty() || line.contains("TIME") || line.contains("METHOD")) continue;
            
            if (currentIP != null && line.length() > 20) {
                LogEntry entry = new LogEntry(currentIP + " " + line);
                if (entry.ip != null) {
                    ipRequests.put(entry.ip, ipRequests.getOrDefault(entry.ip, 0) + 1);
                    int score = calculateRiskScore(entry);
                    entry.riskScore = score;
                    
                    if (score > 30) {
                        suspiciousLogs.add(entry);
                        detectAttackPatterns(entry);
                    }
                }
            }
        }
    }
}   
    static int calculateRiskScore(LogEntry entry) {
    // NULL SAFETY CHECKS
    if (entry.ip == null || entry.url == null) return 0;
    
    int score = 0;
    
    // ML Anomaly Detection
    int avgRequests = 5;
    Integer ipCount = ipRequests.get(entry.ip);
    if (ipCount != null && ipCount > avgRequests * 3) score += 40;
    
    // SQL Injection (SAFE)
    if (entry.url.contains("SELECT") || entry.url.contains("1=1") || 
        entry.url.contains("UNION") || entry.url.contains("'")) score += 90;
        
    // XSS Detection (SAFE)  
    if (entry.url.contains("<script>") || entry.url.contains("javascript:") ||
        entry.url.contains("onerror=")) score += 85;
        
    // Bad Bot Detection (SAFE)
    if (entry.userAgent != null && entry.userAgent.contains("bot") && 
        (entry.userAgent.contains("Google") || entry.userAgent.contains("Bing"))) {
        score += 60;
    }
    
    // Scanner patterns (SAFE)
    if (entry.url.contains("/wp-admin") || entry.url.contains("/phpmyadmin") ||
        entry.url.contains("/admin")) score += 70;
        
    // 404 brute force (SAFE)
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
    System.out.println("🤖 ML-POWERED WEB LOG SECURITY ANALYZER - DAY 3");
    System.out.println("=".repeat(70));
    
    long totalLogs = ipRequests.values().stream().mapToInt(Integer::intValue).sum();
    int highRisk = (int)suspiciousLogs.stream().filter(e -> e.riskScore >= 70).count();
    int mediumRisk = (int)suspiciousLogs.stream().filter(e -> e.riskScore >= 50 && e.riskScore < 70).count();
    
    System.out.printf("📊 TOTAL LOGS ANALYZED: %,d\n", totalLogs);
    System.out.printf("🚨 HIGH RISK ATTACKS (70+): %d (%.1f%%)\n", highRisk, (highRisk*100.0/totalLogs));
    System.out.printf("⚠️  MEDIUM RISK (50-69): %d (%.1f%%)\n", mediumRisk, (mediumRisk*100.0/totalLogs));
    
    // NEW: IP + Risk Factor Table
    System.out.println("\n🔥 TOP IPS BY RISK FACTOR:");
    System.out.println("IP Address          | Requests | Avg Risk | Status");
    System.out.println("-".repeat(45));
    
    // Group IPs by risk
    Map<String, Integer> ipTotalRisk = new HashMap<>();
    suspiciousLogs.forEach(e -> {
        ipTotalRisk.put(e.ip, ipTotalRisk.getOrDefault(e.ip, 0) + e.riskScore);
    });
    
    ipTotalRisk.entrySet().stream()
        .filter(e -> ipRequests.get(e.getKey()) > 5)  // Only show active IPs
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .limit(10)
        .forEach(e -> {
            String ip = e.getKey();
            int totalRisk = e.getValue();
            int avgRisk = totalRisk / ipRequests.getOrDefault(ip, 1);
            String status = avgRisk >= 70 ? "🚨 HIGH" : avgRisk >= 50 ? "⚠️ MEDIUM" : "✅ LOW";
            System.out.printf("%-18s | %7d | %7d | %s\n", ip, ipRequests.get(ip), avgRisk, status);
        });
    
    System.out.println("\n🎯 TOP ATTACK PATTERNS:");
    attackPatterns.entrySet().stream()
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .limit(5)
        .forEach(e -> System.out.printf("  %s: %d occurrences\n", e.getKey(), e.getValue()));
}

}
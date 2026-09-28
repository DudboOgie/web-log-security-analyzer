import sys
import re

def read_log_file(file_path):
    """
    Lit le fichier journal et retourne une liste de lignes.
    """
    with open(file_path, 'r') as file:
        return file.readlines()

def parse_log_line(line):
    """
    Analyse une ligne de log en utilisant .split().
    """
    parts = line.split(' ')
    
    ip = parts[0]
    timestamp = parts[3].strip('[') + " " + parts[4].strip(']')
    
    line_parts = line.split('"')
    request = line_parts[1] if len(line_parts) > 1 else ""
    user_agent = line_parts[5] if len(line_parts) > 5 else ""
    
    status_code = ""
    if len(line_parts) > 2:
        status_parts = line_parts[2].strip().split(' ')
        if status_parts:
            status_code = status_parts[0]
    
    return {
        'ip': ip,
        'timestamp': timestamp,
        'request': request,
        'status_code': status_code,
        'user_agent': user_agent
    }

def detect_xss_attacks(log_lines):
    """
    Détecte les requêtes XSS basées sur des chaînes simples.
    """
    xss_alerts = []
    for line in log_lines:
        parsed = parse_log_line(line)
        if parsed:
            request = parsed['request'].lower()
            if '<script>' in request or 'alert(' in request:
                xss_alerts.append(parsed)
    return xss_alerts

def detect_sql_injection(log_lines):
    """
    Détecte les tentatives d'injection SQL.
    """
    sql_alerts = []
    for line in log_lines:
        parsed = parse_log_line(line)
        if parsed:
            request = parsed['request'].upper()
            if 'UNION SELECT' in request or 'OR 1=1' in request or '--' in request:
                sql_alerts.append(parsed)
    return sql_alerts

def detect_xss_with_regex(log_lines):
    """
    Détecte les attaques XSS à l'aide d'une expression régulière (Regex).
    """
    xss_regex_alerts = []
    pattern = re.compile(r'<script>|alert\(', re.IGNORECASE)
    
    for line in log_lines:
        parsed = parse_log_line(line)
        if parsed:
            if pattern.search(parsed['request']):
                xss_regex_alerts.append(parsed)
    return xss_regex_alerts

def main():
    """
    Fonction principale qui orchestre tout le processus d'analyse.
    """
    if len(sys.argv) < 2:
        print("Usage: python log_analyzer.py <path_to_log>")
        return
    
    log_file = sys.argv[1]
    
    try:
        log_lines = read_log_file(log_file)
        print(f"Successfully read {len(log_lines)} lines")
        
        xss_results = detect_xss_attacks(log_lines)
        print(f"Alertes XSS détectées : {len(xss_results)}")
        
        sql_results = detect_sql_injection(log_lines)
        print(f"Alertes Injection SQL détectées : {len(sql_results)}")
        
        regex_results = detect_xss_with_regex(log_lines)
        print(f"Alertes XSS (Regex) : {len(regex_results)}")
        
    except FileNotFoundError:
        print(f"Le fichier {log_file} est introuvable.")

if __name__ == '__main__':
    main()

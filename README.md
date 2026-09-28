
# Web Log Security Analyzer (Python)

## Description du projet
Ce projet a été réalisé dans le cadre d'un parcours en cybersécurité. Il s'agit d'un script en Python conçu pour automatiser l'analyse de journaux de trafic web (fichiers de logs Apache) afin d'identifier des comportements malveillants potentiels (attaques XSS, injections SQL).

## Architecture et Rôle des Fonctions

Le script est structuré de manière modulaire autour de plusieurs fonctions clés :

1. **`read_log_file(file_path)`**
   * **Rôle** : Ouvre le fichier journal brut et charge l'intégralité de son contenu en mémoire sous forme de liste de lignes.
   * **Résultat** : Permet au programme d'accéder aux données textuelles du serveur web.

2. **`parse_log_line(line)`**
   * **Rôle** : Prend une ligne de log brute, utilise la méthode `.split()` pour l'isoler morceau par morceau (adresse IP, horodatage, requête HTTP, code de statut, User-Agent) et la transforme en dictionnaire structuré.
   * **Résultat** : Rend les données exploitables par du code Python.

3. **`detect_xss_attacks(log_lines)`**
   * **Rôle** : Parcourt les lignes analysées et cherche des motifs simples de chaînes de caractères typiques d'une attaque XSS (ex: `<script>` ou `alert(`) dans le champ de la requête.
   * **Résultat** : Isole et remonte les requêtes suspectes.

4. **`detect_sql_injection(log_lines)`**
   * **Rôle** : Analyse les requêtes HTTP pour détecter des tentatives d'injection SQL en recherchant des signatures comme `UNION SELECT`, `OR 1=1` ou `--`.
   * **Résultat** : Alerte sur les manipulations de bases de données malveillantes.

5. **`detect_xss_with_regex(log_lines)`**
   * **Rôle** : Utilise le module natif `re` de Python pour appliquer des expressions régulières (Regex) avancées afin de détecter des charges XSS de manière flexible et insensible à la casse.
   * **Résultat** : Améliore la robustesse de la détection.

6. **`main()`**
   * **Rôle** : Fonction principale qui orchestre tout le processus. Elle récupère le chemin du fichier journal directement depuis les arguments de la ligne de commande, appelle les fonctions de lecture et de détection, puis affiche les résultats.

---

## Utilisation

Pour exécuter l'analyseur de sécurité depuis votre terminal Linux :

```bash
python log_analyzer.py apache-access-log.txt

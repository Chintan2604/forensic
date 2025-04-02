#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import re
import stat
import tempfile
import argparse
import signal
import colorama
from colorama import Fore, Style
from datetime import datetime

# Initialisation de colorama
colorama.init(autoreset=True)

# Version du builder
VERSION = "1.0.0"

# Configuration du style Exegol
class ExegolStyle:
    # Préfixes pour les différents types de messages
    SUCCESS = f"{Fore.GREEN}[+]{Style.RESET_ALL} "
    ERROR = f"{Fore.RED}[-]{Style.RESET_ALL} "
    INFO = f"{Fore.BLUE}[*]{Style.RESET_ALL} "
    WARNING = f"{Fore.YELLOW}[!]{Style.RESET_ALL} "
    DEBUG = f"{Fore.CYAN}[D]{Style.RESET_ALL} "
    
    # Couleurs pour les messages
    SUCCESS_COLOR = Fore.GREEN
    ERROR_COLOR = Fore.RED
    INFO_COLOR = Fore.BLUE
    WARNING_COLOR = Fore.YELLOW
    DEBUG_COLOR = Fore.CYAN

# Patterns pour la détection des étapes
PATTERNS = {
    'success': {
        'pattern': r'(Successfully|Complete|done|finished|Built|Pull complete|resolve|Using cache|CACHED|#\d+ DONE)',
        'prefix': ExegolStyle.SUCCESS,
        'color': ExegolStyle.SUCCESS_COLOR,
        'icon': '✔'  # Checkmark
    },
    'error': {
        'pattern': r'(ERROR:|failed|\[error\]|Error while)',
        'prefix': ExegolStyle.ERROR,
        'color': ExegolStyle.ERROR_COLOR,
        'icon': '✘'  # Cross mark
    },
    'warning': {
        'pattern': r'(WARNING:|\[warning\])',
        'prefix': ExegolStyle.WARNING,
        'color': ExegolStyle.WARNING_COLOR,
        'icon': '⚠'  # Warning sign
    },
    'info': {
        'pattern': r'(#\d+ (?!DONE)|Step \d+/\d+|\[\d+/\d+\]|---> [a-f0-9]+)',
        'prefix': ExegolStyle.DEBUG,
        'color': ExegolStyle.DEBUG_COLOR,
        'icon': 'ℹ'  # Info
    },
    'running': {
        'pattern': r'(Downloading|pulling|Installing|Collecting|RUN|Building|COPY|ADD)',
        'prefix': ExegolStyle.INFO,
        'color': ExegolStyle.INFO_COLOR,
        'icon': '▶'  # Play button
    }
}

# Liste des outils à installer
TOOLS = [
    "Dépendances système",
    "Dépendances Python",
    "Volatility3",
    "Loki",
    "Oletools",
    "RegRipper",
    "ExifTool",
    "MobSF",
    "iLEAPP",
    "ALEAPP",
    "TestDisk",
    "YARA",
    "APFS-FUSE",
    "mac_apt",
    "LiME",
    "Plaso",
    "Bulk Extractor",
    "The Sleuth Kit",
    "hashdeep",
    "foremost",
    "binwalk",
    "pdf-parser",
    "h8mail",
    "pescanner",
    "FLOSS"
]

# Stats du build
class BuildStats:
    start_time = None
    end_time = None
    success_count = 0
    error_count = 0
    warning_count = 0
    current_stage = None
    tools_status = {tool: {'status': 'pending', 'line': 0} for tool in TOOLS}
    
    @classmethod
    def update_tool_status(cls, tool_name, status):
        if tool_name in cls.tools_status:
            cls.tools_status[tool_name]['status'] = status

    @classmethod
    def start(cls):
        cls.start_time = datetime.now()

    @classmethod
    def stop(cls):
        cls.end_time = datetime.now()

    @classmethod
    def get_duration(cls):
        if cls.start_time and cls.end_time:
            return cls.end_time - cls.start_time
        return None

def get_timestamp():
    return time.strftime("%H:%M:%S")

def print_status(message, status='running', details=None):
    timestamp = get_timestamp()
    
    # Récupérer le style pour le statut
    if status in PATTERNS:
        prefix = PATTERNS[status]['prefix']
        color = PATTERNS[status]['color']
    else:
        prefix = ExegolStyle.INFO
        color = ExegolStyle.INFO_COLOR

    # Afficher le message avec le préfixe Exegol
    print(f"{prefix}{color}{message}{Style.RESET_ALL}")
    
    # Afficher les détails si présents
    if details:
        print(f"     {ExegolStyle.DEBUG}{details}")

def print_tools_status():
    # Effacer les lignes précédentes
    for tool in TOOLS:
        if BuildStats.tools_status[tool]['line'] > 0:
            print(f"\033[{BuildStats.tools_status[tool]['line']}A\033[K", end='')
    
    # Afficher le statut de chaque outil
    current_line = 0
    for tool in TOOLS:
        status = BuildStats.tools_status[tool]['status']
        if status == 'pending':
            color = Style.RESET_ALL
            icon = ' '
        elif status == 'installing':
            color = Style.RESET_ALL
            icon = '▶'
        elif status == 'success':
            color = Fore.BLUE
            icon = '✔'
        elif status == 'error':
            color = Fore.RED
            icon = '✘'
        
        print(f"{ExegolStyle.INFO}{color}[{icon}] Installation de {tool}{Style.RESET_ALL}")
        current_line += 1
        BuildStats.tools_status[tool]['line'] = current_line
    
    # Replacer le curseur à la position initiale
    print(f"\033[{len(TOOLS)}A", end='')

def analyze_line(line):
    """Analyse une ligne de sortie et retourne le statut approprié et la ligne formatée"""
    line = line.strip()
    
    # Ignorer les lignes vides
    if not line:
        return None, None

    # Vérifier chaque type de pattern dans l'ordre de priorité
    for status, config in PATTERNS.items():
        if re.search(config['pattern'], line, re.IGNORECASE):
            # Format style Exegol : [+/-/!/*] message
            return status, line
    
    # Si aucun pattern ne correspond, traiter comme info
    return 'info', line

def create_askpass_script():
    # Créer un script temporaire qui ne fait rien (pas besoin de mot de passe)
    fd, path = tempfile.mkstemp(prefix='askpass_', suffix='.sh')
    with os.fdopen(fd, 'w') as tmp:
        tmp.write('#!/bin/sh\nexit 0\n')
    
    # Rendre le script exécutable
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'Forensic Toolkit Builder v{VERSION}')
    parser.add_argument('--no-cache', action='store_true', help='Désactive le cache Docker')
    parser.add_argument('--pull', action='store_true', help='Force le pull des images de base')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    parser.add_argument('--dry-run', action='store_true', help='Vérifie la configuration sans construire l\'image')
    return parser.parse_args()

def signal_handler(signum, frame):
    print(f"\n{ExegolStyle.WARNING}Signal reçu ({signum}), arrêt du build...")
    sys.exit(1)

def monitor_build(args):
    print(f"\n{ExegolStyle.INFO}Démarrage du build de l'image forensic v{VERSION}\n")
    BuildStats.start()

    # Initialiser l'affichage des outils
    print_tools_status()
    current_tool = None

    try:
        # Créer le script askpass
        askpass_script = create_askpass_script()

        # Configurer l'environnement pour sudo
        env = os.environ.copy()
        env['SUDO_ASKPASS'] = askpass_script

        # Préparer la commande
        cmd = ['sudo', '-A', 'docker-compose', 'build']
        if args.dry_run:
            print(f"\n{ExegolStyle.INFO}Mode dry-run : vérification de la configuration sans construction de l'image\n")
            cmd.append('--dry-run')
        if args.no_cache:
            cmd.append('--no-cache')
        if args.pull:
            cmd.append('--pull')

        # Lancer le build
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
            env=env
        )

        # Suivre la sortie en temps réel
        for line in process.stdout:
            status, message = analyze_line(line)
            if status:
                if status == 'success':
                    BuildStats.success_count += 1
                elif status == 'error':
                    BuildStats.error_count += 1
                elif status == 'warning':
                    BuildStats.warning_count += 1

                # Détecter l'outil en cours d'installation
                for tool in TOOLS:
                    if tool.lower() in message.lower():
                        if current_tool != tool:
                            current_tool = tool
                            BuildStats.update_tool_status(tool, 'installing')
                            print_tools_status()
                    
                    # Vérifier si l'installation est terminée
                    if current_tool == tool and status == 'success':
                        BuildStats.update_tool_status(tool, 'success')
                        print_tools_status()
                        current_tool = None
                    elif current_tool == tool and status == 'error':
                        BuildStats.update_tool_status(tool, 'error')
                        print_tools_status()
                        current_tool = None

                if args.verbose:
                    # Déplacer le curseur après la liste des outils
                    print(f"\033[{len(TOOLS)}B", end='')
                    print_status(message, status)
                    # Replacer le curseur
                    print(f"\033[{len(TOOLS)}A", end='')

        # Attendre la fin du processus
        process.wait()
        BuildStats.stop()

        # Supprimer le script askpass
        try:
            os.unlink(askpass_script)
        except:
            pass

        # Afficher les statistiques
        duration = BuildStats.get_duration()
        print(f"\n{ExegolStyle.INFO}Statistiques du build:")
        print(f"  ⏱ Durée: {duration.total_seconds():.1f}s")
        print(f"  {PATTERNS['success']['icon']} Succès: {BuildStats.success_count}")
        print(f"  {PATTERNS['warning']['icon']} Avertissements: {BuildStats.warning_count}")
        print(f"  {PATTERNS['error']['icon']} Erreurs: {BuildStats.error_count}")

        # Vérifier le code de retour
        if process.returncode == 0:
            print(f"\n{ExegolStyle.SUCCESS}Build terminé avec succès")
        else:
            print(f"\n{ExegolStyle.ERROR}Erreur pendant le build")
            sys.exit(1)

    except KeyboardInterrupt:
        BuildStats.stop()
        print(f"\n{ExegolStyle.WARNING}Build interrompu par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        BuildStats.stop()
        print(f"\n{ExegolStyle.ERROR}Erreur inattendue")
        print(f"{ExegolStyle.ERROR}Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Gestion des signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Parse des arguments
    args = parse_arguments()

    # Démarrage du monitoring
    monitor_build(args)

# 🔍 Forensic Toolkit - Votre Laboratoire d'Investigation Numérique

[![État du projet](https://img.shields.io/badge/État-En%20Développement-yellow.svg)]()
[![Contributions](https://img.shields.io/badge/Contributions-Bienvenues-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 🎯 À propos

Bienvenue dans ce laboratoire d'investigation numérique basé sur Docker ! Ce projet est conçu pour fournir un environnement complet et préconfiguré pour l'analyse forensique de :

- 💾 Disques durs et supports de stockage
- 🧠 Dumps mémoire
- 📱 Appareils mobiles
- 📊 Logs système
- 🔐 Malwares et fichiers suspects

## 🚧 État du Projet

Ce projet est en **développement actif** et s'enrichit continuellement. Notre objectif est de créer une ressource complète pour la communauté forensique, des débutants aux experts.

### 📈 Évolutions à venir

- Documentation détaillée pour chaque outil
- Guides pas-à-pas pour débutants
- Tutoriels avancés pour les analystes expérimentés
- Cas pratiques et scénarios d'investigation
- Intégration d'outils supplémentaires

## 🎓 Pour qui ?

- 🔰 Débutants en forensique numérique
- 🏆 Participants aux CTF
- 🛡️ Analystes en CERT/CSIRT
- 👨‍💻 Professionnels de la cybersécurité
- 🎯 Passionnés d'investigation numérique

## 🛠️ Caractéristiques

### Investigation Système
- Analyse de dumps mémoire
- Investigation de systèmes de fichiers
- Récupération de données
- Analyse de registres Windows

### Investigation Mobile
- Analyse d'appareils Android
- Investigation iOS
- Extraction de données

### Analyse de Malwares
- Scan de fichiers suspects
- Détection d'IOCs
- Analyse statique et dynamique

## 🚀 Démarrage Rapide

```bash
# Cloner le repository
git clone [URL_DU_REPO]

# Construire l'image
docker-compose build

# Démarrer l'environnement
docker-compose up -d

# Accéder à l'environnement
docker-compose exec forensics bash

# Forensics Toolkit Docker

Ce conteneur Docker inclut une suite complète d'outils forensiques préinstallés sur une base Debian, optimisé avec un build multi-stage pour une image plus légère.

## Outils inclus

### Analyse Mémoire et Système
- Volatility 3 avec plugins communautaires
  ```bash
  vol3 -f /data/memory.dump windows.pslist
  ```
- Loki (Scanner IOC et Malware)
  ```bash
  python3 /opt/loki/loki.py -p /data/
  ```
- LiME (Linux Memory Extractor)
  ```bash
  cd /opt/lime/src && make
  sudo insmod lime.ko "path=/data/memory.lime format=lime"
  ```
- YARA (Analyse de malware)
  ```bash
  yara /opt/rules/malware.yar /data/suspect_file
  ```

### Analyse Mobile
- ALEAPP (Android Logs Events And Protobuf Parser)
  ```bash
  cd /opt/ALEAPP
  python3 aleapp.py -i /data/android_data -o /data/output
  ```
- iLEAPP (iOS Logs Events And Protobuf Parser)
  ```bash
  cd /opt/iLEAPP
  python3 ileapp.py -i /data/ios_data -o /data/output
  ```
- MobSF (Mobile Security Framework)
  ```bash
  cd /opt/Mobile-Security-Framework-MobSF
  python3 manage.py runserver
  ```

### Analyse Documents et Métadonnées
- Oletools v0.60.1 (Analyse documents Office)
  ```bash
  olevba /data/document.doc
  ```
- ExifTool 13.25 (Analyse métadonnées)
  ```bash
  exiftool /data/image.jpg
  ```
- RegRipper3.0 (Analyse registre Windows)
  ```bash
  cd /opt/regripper
  perl rip.pl -r /data/NTUSER.DAT -f ntuser
  ```
- hashdeep (Hachage récursif et audit)
  ```bash
  hashdeep -r /data/evidence > hashes.txt
  ```

### Récupération et Analyse de Données
- TestDisk/PhotoRec (Récupération de partitions et fichiers)
  ```bash
  # Analyse et réparation de partitions
  testdisk /data/disk.img
  
  # Récupération de fichiers effacés
  photorec /data/disk.img
  ```
- Steghide (Stéganographie)
  ```bash
  steghide extract -sf /data/image.jpg
  ```
- The Sleuth Kit (Analyse forensique de systèmes de fichiers)
  ```bash
  mmls /data/disk.img
  fls -r /data/disk.img
  ```
- APFS-FUSE (Montage de systèmes de fichiers APFS)
  ```bash
  apfs-fuse /data/disk.img /mnt/apfs
  ```
- mac_apt (Mac Artifact Parsing Tool)
  ```bash
  python3 /opt/mac_apt/mac_apt.py -i /data/macos.dmg -o /data/output
  ```

## Utilisation

1. Construire l'image :
```bash
docker-compose build
```

2. Démarrer le conteneur :
```bash
docker-compose up -d
```

3. Accéder au conteneur :
```bash
docker-compose exec forensics bash
```

## Partage de données

### Méthode 1 : Via le volume /data

1. Placez vos fichiers dans le répertoire `./data` sur votre machine hôte
2. Les fichiers seront automatiquement disponibles dans `/data` dans le conteneur

```bash
# Sur l'hôte
cp memdump.raw ./data/

# Dans le conteneur
ls /data
volatility3 -f /data/memdump.raw windows.info
```

### Méthode 2 : Via le volume /host/tmp

- Le répertoire `/tmp` de votre machine hôte est monté dans `/host/tmp`
- Utile pour les fichiers temporaires ou les transferts rapides

```bash
# Sur l'hôte
cp memdump.raw /tmp/

# Dans le conteneur
ls /host/tmp
volatility3 -f /host/tmp/memdump.raw windows.info
```

### Méthode 3 : Copie directe avec docker cp

```bash
# Depuis l'hôte vers le conteneur
docker cp memdump.raw forensic:/data/

# Depuis le conteneur vers l'hôte
docker cp forensic:/data/resultats.txt ./
```

### Volumes configurés

- `/data`: Répertoire partagé entre l'hôte et le conteneur (persistant)
- `/host/tmp`: Accès au répertoire /tmp de l'hôte (temporaire)

## Sécurité

- Exécution avec un utilisateur non-root `forensic`
- Capacités SYS_PTRACE pour l'analyse mémoire
- Configuration seccomp non confinée

## Structure

- Tous les outils sont installés dans `/opt`
- Le répertoire de travail par défaut est `/data`
- Les dépendances Python sont installées globalement

## Prérequis

### Pour LiME (Linux Memory Extractor)
Sur la machine hôte Linux où vous souhaitez capturer la mémoire :
```bash
# Installation des headers du kernel
sudo apt-get install linux-headers-$(uname -r)

# Compilation du module pour votre kernel
cd /opt/LiME/src
make

# Capture de la mémoire (nécessite les droits root)
sudo insmod lime.ko "path=/data/memory.lime format=lime"
```

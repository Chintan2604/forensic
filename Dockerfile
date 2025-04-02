# syntax=docker/dockerfile:1.4

# Build stage
FROM debian:bullseye-slim AS builder

# Métadonnées de l'image
LABEL maintainer="ForensicToolkit" \
      description="Boîte à outils forensique avec Volatility3, ALEAPP, MobSF, etc." \
      version="1.0"

# Arguments de build
ARG DEBIAN_FRONTEND=noninteractive
ARG EXIFTOOL_VERSION=13.25

# Installation des dépendances communes
RUN set -ex \
    && mkdir -p /var/lib/apt/lists/partial \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        python3.9 python3-pip python3-tk python3-setuptools python3-dev \
        steghide build-essential linux-headers-generic \
        curl git sudo wget unzip cmake \
        libssl-dev zlib1g-dev libbz2-dev libffi-dev \
        autoconf automake libtool pkg-config \
        e2fslibs-dev libncurses5-dev libncursesw5-dev \
        ntfs-3g-dev libjpeg-dev uuid-dev qtbase5-dev \
        qttools5-dev-tools dh-autoreconf \
        gcc libjansson-dev libmagic-dev flex bison \
        fuse libfuse3-dev libattr1-dev \
        cargo rustc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /opt

# Installation des dépendances Python communes
RUN pip3 install --no-cache-dir \
    wheel \
    setuptools \
    distlib

# Installation de Volatility3
WORKDIR /opt/volatility3
RUN set -ex && \
    git clone --depth=1 https://github.com/volatilityfoundation/volatility3.git . && \
    pip3 install --no-cache-dir . && \
    mkdir -p plugins && \
    git clone --depth=1 https://github.com/volatilityfoundation/community3.git plugins/community && \
    git clone --depth=1 https://github.com/superponible/volatility-plugins.git plugins/extra

# Installation de Loki
WORKDIR /opt/loki
RUN set -ex && \
    git clone --depth=1 https://github.com/Neo23x0/Loki.git . && \
    pip3 install --no-cache-dir -r requirements.txt

# Installation d'Oletools
WORKDIR /opt/oletools
RUN set -ex && \
    git clone --depth=1 https://github.com/decalage2/oletools.git . && \
    pip3 install --no-cache-dir .

# Installation de RegRipper
WORKDIR /opt/regripper
RUN git clone --depth=1 https://github.com/keydet89/RegRipper3.0.git .

# Installation d'ExifTool
WORKDIR /opt/exiftool
RUN set -ex && \
    wget https://exiftool.org/Image-ExifTool-${EXIFTOOL_VERSION}.tar.gz && \
    tar -xzf Image-ExifTool-${EXIFTOOL_VERSION}.tar.gz --strip-components=1 && \
    rm Image-ExifTool-${EXIFTOOL_VERSION}.tar.gz

# Installation de MobSF
WORKDIR /opt/mobsf
RUN git clone --depth=1 https://github.com/MobSF/Mobile-Security-Framework-MobSF.git .

# Installation de iLEAPP
WORKDIR /opt/ileapp
RUN set -ex && \
    git clone --depth=1 https://github.com/abrignoni/iLEAPP.git . && \
    pip3 install --no-cache-dir -r requirements.txt

# Installation de ALEAPP
WORKDIR /opt/aleapp
RUN set -ex && \
    git clone --depth=1 https://github.com/abrignoni/ALEAPP.git . && \
    pip3 install --no-cache-dir -r requirements.txt

# Installation de TestDisk/PhotoRec
WORKDIR /opt/testdisk
RUN set -ex && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        automake \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    git clone --depth=1 https://github.com/cgsecurity/testdisk.git . && \
    mkdir -p config && \
    cp /usr/share/misc/config.guess config/ && \
    cp /usr/share/misc/config.sub config/ && \
    autoreconf --install -W all -I config

# Installation de YARA
WORKDIR /opt/yara
RUN set -ex && \
    git clone --depth=1 https://github.com/VirusTotal/yara.git . && \
    ./bootstrap.sh && \
    ./configure --enable-cuckoo --enable-magic --enable-dotnet && \
    make -j$(nproc) && \
    make install && \
    make check

# Installation d'APFS-FUSE
WORKDIR /opt/apfs-fuse
RUN set -ex && \
    git clone --depth=1 https://github.com/sgan81/apfs-fuse.git . && \
    git submodule init && \
    git submodule update && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make -j$(nproc)

# Installation de mac_apt
WORKDIR /opt/mac_apt
RUN set -ex && \
    # Installation des dépendances système pour mac_apt
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-dev \
        libfuse-dev \
        zlib1g-dev \
        libbz2-dev \
        libssl-dev \
        build-essential && \
    # Clone et installation de mac_apt
    git clone --depth=1 https://github.com/ydkhatri/mac_apt.git . && \
    # Installation des dépendances Python
    pip3 install --no-cache-dir \
        anytree \
        biplist \
        "construct==2.9.45" \
        xlsxwriter \
        plistutils \
        kaitaistruct \
        lz4 \
        "pytsk3==20170802" \
        "libvmdk-python==20181227" \
        pycryptodome \
        cryptography \
        "pybindgen==0.21.0" \
        pillow \
        pyliblzfse \
        nska_deserialize \
        pyaff4>=0.31 && \
    # Installation de libewf-legacy
    pip3 install --no-cache-dir https://github.com/libyal/libewf-legacy/releases/download/20140808/libewf-20140808.tar.gz && \
    # Nettoyage
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Installation de LiME
WORKDIR /opt/lime
RUN set -ex && \
    # Installation des outils de build
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential && \
    # Clone de LiME
    git clone https://github.com/504ensicsLabs/LiME.git . && \
    # Nettoyage
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Installation de The Sleuth Kit
WORKDIR /opt/sleuthkit
RUN set -ex && \
    git clone --depth=1 https://github.com/sleuthkit/sleuthkit.git . && \
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) && \
    make install

# Installation de hashdeep
WORKDIR /opt/hashdeep
RUN set -ex && \
    git clone --depth=1 https://github.com/jessek/hashdeep.git . && \
    ./bootstrap.sh && \
    ./configure && \
    make -j$(nproc) && \
    make install

# Nettoyage final
WORKDIR /opt
RUN rm -rf /root/.cache /tmp/* /var/tmp/*

# Final stage
FROM debian:bullseye-slim

# Installation des dépendances Python
RUN set -ex \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        python3.9 python3-pip python3-tk \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Création des répertoires
RUN mkdir -p /data /host/tmp && \
    echo "root:forensic" | chpasswd

# Copie des outils
COPY --from=builder /opt /opt
COPY --from=builder /usr/local/lib/python3.9/dist-packages /usr/local/lib/python3.9/dist-packages

# Configuration finale
WORKDIR /data

# Variables d'environnement
ENV PATH="/opt/ExifTool:/opt/oletools:${PATH}"

# Points de montage
VOLUME ["/data", "/host/tmp"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3.9 -c "import volatility3; print('OK')" || exit 1

CMD ["bash"]

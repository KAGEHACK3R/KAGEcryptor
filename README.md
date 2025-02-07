# KAGEcryptor

**KAGEcryptor** est un outil de chiffrement et déchiffrement avancé qui propose plusieurs algorithmes (Caesar, Vigenère, XOR et AES) via une interface graphique moderne développée avec PyQt5. Il permet de chiffrer et déchiffrer du texte ainsi que des fichiers (images, documents, etc.), en intégrant des fonctionnalités telles que :

- **Chiffrement de tous les caractères** : lettres, chiffres, symboles et caractères spéciaux.
- **Support du glisser-déposer** pour sélectionner les fichiers.
- **Multi-threading** pour le traitement des fichiers volumineux, avec barre de progression.
- **Thèmes personnalisables** (clair et sombre) et sauvegarde des préférences utilisateur.
- **Option d'auto-copie** du résultat dans le presse-papier.

> **Attention** :  
> Ce programme est avant tout un outil pédagogique. Même si AES est intégré (en mode ECB pour la simplicité), il n'est pas destiné à des applications de sécurité en production.

## Fonctionnalités

- **Algorithmes multiples**  
  Choisissez entre :
  - **Caesar** : décalage de tous les caractères (Unicode).
  - **Vigenère** : chiffrement par clé textuelle.
  - **XOR** : chiffrement par opération XOR avec une clé.
  - **AES** : chiffrement avancé avec dérivation de clé par SHA256 (nécessite PyCryptodome).

- **Interface graphique moderne**  
  Conçue avec PyQt5, l'interface comprend :
  - Un onglet **Texte** pour chiffrer/déchiffrer des messages.
  - Un onglet **Fichiers/Images** pour traiter des fichiers avec support du glisser-déposer et une barre de progression.

- **Multi-threading**  
  Les opérations sur fichiers s'exécutent en arrière-plan pour garder l'interface réactive.

- **Thèmes et préférences**  
  Choisissez un thème (clair/sombre) via le menu, et vos préférences (algorithme, clé, option d'auto-copie) sont sauvegardées automatiquement.

## Prérequis

- **Python 3.6 ou supérieur**
- **PyQt5**  
- **PyCryptodome** (pour utiliser l'algorithme AES)

## Installation

1. **Cloner le dépôt** (ou télécharger directement les fichiers sources) :

    ```bash
    git clone https://github.com/votre_nom_utilisateur/KAGEcryptor.git
    cd KAGEcryptor
    ```

2. **Créer un environnement virtuel** (optionnel mais recommandé) :

    ```bash
    python3 -m venv env
    source env/bin/activate       # Sur Windows : env\Scripts\activate
    ```

3. **Installer les dépendances** :

    Vous pouvez installer les dépendances via un fichier `requirements.txt`. Par exemple, créez un fichier `requirements.txt` avec le contenu suivant :

    ```
    PyQt5>=5.15.0
    pycryptodome>=3.9.0
    ```

    Puis lancez :

    ```bash
    pip install -r requirements.txt
    ```

## Utilisation

Pour lancer **KAGEcryptor**, exécutez simplement :

```bash
python kagecryptor.py

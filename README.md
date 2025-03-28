# Détecteur de Security Smells dans les Cookbooks Chef

Un outil d'analyse statique en Ruby pour détecter les failles de sécurité dans les cookbooks Chef, avec un accent sur les versions obsolètes de logiciels et les configurations non sécurisées.

## Fonctionnalités

- Détection des versions obsolètes de paquets dans les recettes Chef
- Identification des failles de sécurité potentielles dans le code d'infrastructure
- Règle RuboCop personnalisée pour vérifier les paquets obsolètes
- Prend en charge les paquets courants comme nginx, MySQL et Python

## Installation

1. Assurez-vous d'avoir Ruby installé (version 2.7+ recommandée)
2. Installez les gems nécessaires :
   ```bash
   gem install rubocop

##Utilisation
1. Assurez vous que tout les fichiers sont dans le meme repertoire
2. Installer "cookstyle" avec la commande suivante :
   ```bash
   gem install cookstyle
3. Executer la commande suivante :
   ```bash
   cookstyle cookbook_outdated_software.rb  

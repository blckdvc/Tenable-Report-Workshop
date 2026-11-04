# Atelier de rapports Tenable

Application locale pour transformer un export CSV de Tenable Security Center en rapports de remédiation en français, habillés aux couleurs du client.

L'application tourne sur votre poste et s'ouvre dans votre navigateur. Elle n'écoute que sur 127.0.0.1. Les exports des clients ne quittent votre machine que dans deux cas, tous deux à votre initiative : une interrogation de Security Center (l'export vient alors de lui) et l'envoi d'un rapport par courriel via le serveur SMTP que vous avez configuré.

## Démarrer

Prérequis : Python 3.9 ou plus récent ([python.org](https://www.python.org/downloads/)). Sous Windows, cochez « Add Python to PATH » pendant l'installation.

| Système | Lancement |
|---|---|
| Windows | Double-cliquez sur `lancer.bat` |
| macOS | Double-cliquez sur `lancer.command` (au premier lancement : clic droit, puis Ouvrir) |
| Linux | `./lancer.sh` |

Au premier lancement, le script installe les bibliothèques dans un dossier `.venv`. Cela prend une à deux minutes et nécessite Internet ; les lancements suivants sont immédiats. L'application s'ouvre ensuite dans le navigateur, à l'adresse http://127.0.0.1:8765. Pour l'arrêter, fermez la fenêtre du terminal.

Mise à jour d'une installation existante : la récupération via l'API demande la bibliothèque `requests`. Exécutez une fois `.venv/bin/python -m pip install -r requirements.txt` (Windows : `.venv\Scripts\python.exe`).

Poste sans Internet : sur une machine connectée, avec le même système et la même version de Python, exécutez `pip download -r requirements.txt -d paquets`, copiez le dossier `paquets`, puis sur le poste isolé :

```
python -m venv .venv
.venv/bin/python -m pip install --no-index --find-links paquets -r requirements.txt
```

Sous Windows, remplacez `.venv/bin/python` par `.venv\Scripts\python.exe`.

## Utilisation

1. **Choisissez le profil client** en haut à droite, ou créez-en un avec « Gérer ».
2. **Onglet Générer.** Déposez l'export CSV, choisissez le modèle, puis cliquez sur « Générer le rapport ». Les rapports PDF s'ouvrent dans un nouvel onglet. Tous les rapports sont enregistrés dans le dossier `rapports/`.
3. **Onglet Habillage.** Titre, sous-titre, client, mention de diffusion (avec une case pour l'afficher aussi, en badge, dans l'en-tête des pages intérieures ; elle quitte alors le pied de page), filigrane (texte en diagonale sur les pages des PDF, par exemple « Diffusion restreinte » ou « Confidentiel », avec une case pour l'exclure de la page de couverture ; absent des fichiers Excel), pied de page, couleur principale et logo. La couverture affichée à gauche se met à jour en direct. Dès qu'un filigrane ou une mention sur les pages intérieures est défini (modèles PDF seulement), des onglets sous l'aperçu montrent deux pages intérieures fictives (synthèse et plan d'action).
4. **Onglet Périmètre.** Sévérités retenues, nombre de solutions du plan d'action, machines à inclure ou à exclure (adresse IP, réseau CIDR ou nom avec jokers).
5. **Onglet Règles.** Consultez, testez et modifiez les règles qui traduisent les intitulés Tenable en actions.
6. **Onglet Configuration.** Connexion et requête Security Center, serveur SMTP et message par défaut (voir plus bas).

L'habillage et le périmètre sont propres à chaque profil client. Les règles sont communes à tous les profils.

### Récupérer les données directement depuis Security Center (API)

En alternative au fichier CSV, l'application peut interroger Security Center et reconstituer l'export elle-même, avec la même structure que l'export de l'interface. Le reste du traitement est identique.

1. Onglet **Configuration**, section « Security Center », carte « Connexion » : adresse du serveur et clés d'API (Users, puis API Keys, de préférence un compte en lecture seule). Le bouton « Tester la connexion » vérifie les clés. Pour une PKI interne, indiquez le certificat de l'autorité (fichier PEM) ; ne désactivez la vérification que pour un test.
2. Même section, carte « Requête d'export » (propre à chaque profil client) : dépôts, liste d'actifs ou requête enregistrée, et au besoin des filtres supplémentaires au format JSON. Le bouton « Afficher les dépôts, listes et requêtes disponibles » permet de les choisir d'un clic. Les sévérités viennent de l'onglet Périmètre. « Voir la requête envoyée à l'API » montre le corps JSON exact de l'appel `POST /rest/analysis`.
3. Onglet **Générer**, étape 1 : choisissez « Security Center (API) », puis « Récupérer depuis Security Center ». Le lien « Modifier la requête » mène à la configuration. L'aperçu s'affiche comme pour un fichier.

Chaque récupération est conservée dans `exports_security_center/` (un CSV horodaté par profil). Ces fichiers servent de point de départ pour les comparaisons : déposez celui du mois dernier comme « export précédent », et récupérez l'export récent via l'API.

Les clés sont enregistrées dans `config.json`, accessible à votre utilisateur seul. Vous pouvez plutôt les fournir par les variables d'environnement `TENABLE_SC_URL`, `TENABLE_SC_ACCESS_KEY` et `TENABLE_SC_SECRET_KEY`, qui l'emportent. Ne diffusez pas `config.json`.

### Tenable Vulnerability Management (CSV ou API)

Un CSV de Tenable Vulnerability Management (export des vulnérabilités, colonnes `asset.*` et `definition.*`) se dépose comme un CSV de Security Center : le format est reconnu automatiquement. Il ne contient ni ACR, ni AES, ni date de dernière observation, et une machine est identifiée par sa première adresse IPv4 (le même poste peut exister sous plusieurs identifiants d'asset).

Pour récupérer les données par l'API, choisissez le produit du profil dans **Configuration > Produit Tenable**, puis renseignez **Vulnerability Management** (adresse, clés d'API, ou variables `TENABLE_VM_URL`, `TENABLE_VM_ACCESS_KEY`, `TENABLE_VM_SECRET_KEY`). La requête du profil permet de limiter à une plage d'adresses et d'ajouter l'ACR et l'AES (second export, celui des assets). Les vulnérabilités ouvertes (open et reopened) sont lues par l'export asynchrone de l'API ; en ligne de commande, `--api` (ou `--securitycenter`) utilise le produit du profil. Le code lit les deux modèles de champs connus (`plugin.*` ou `definition.*`) ; le client a été éprouvé sur un faux serveur, pas sur un locataire réel : en cas de champ non reconnu, le message d'erreur liste ceux reçus.

### Choisir le périmètre : listes d'actifs (Security Center) ou tags (Vulnerability Management)

Avec une récupération par l'API, l'étape 1 de l'onglet **Générer** affiche une ligne « Cible du rapport » et un bouton **Choisir le périmètre**. Selon le produit du profil, il ouvre :

- **Security Center** : la liste des listes d'actifs (statiques ou dynamiques) avec leur nombre de machines. Cochez-en une ou plusieurs : les machines de toutes les listes cochées sont réunies (OU).
- **Vulnerability Management** : les tags, regroupés par catégorie. Plusieurs valeurs d'une même catégorie s'additionnent (OU) ; des catégories différentes se cumulent (ET). Exemple : `Site = Paris, Lyon` et `Criticité = Haute` donne les machines à la fois de Paris ou de Lyon et de criticité haute.

Un champ de filtre aide à retrouver un élément dans une longue liste, et le nombre de machines de la sélection est affiché avant de lancer l'export (pour Security Center : les machines qui portent au moins une vulnérabilité). Deux boutons : **Utiliser pour cette génération** (le profil n'est pas modifié) ou **Enregistrer dans le profil** (la sélection devient le défaut de ce client). Les filtres « machines à inclure / exclure » de l'onglet Périmètre continuent de s'appliquer par-dessus. Avec une requête enregistrée Security Center, la sélection n'a pas d'effet (la requête remplace les filtres).

La sélection est reprise en **couverture** : le champ « Périmètre » indique les listes ou les tags retenus (par exemple « Listes d'actifs : Serveurs Paris, DMZ »), et une ligne « Volumétrie » donne le nombre de machines et de vulnérabilités. Elle figure aussi dans l'onglet Paramètres du plan Excel. Pour une comparaison, la couverture rappelle le périmètre de chaque export s'il diffère, et l'application avertit quand les deux exports n'ont pas le même périmètre.

En ligne de commande, le périmètre enregistré dans le profil s'applique (`--api`). Deux points à vérifier sur un environnement réel : la combinaison de plusieurs listes d'actifs (filtre `asset` en union) et les filtres de tags de l'export (`tag.<catégorie>`) n'ont été éprouvés que sur un faux serveur. « Voir la requête envoyée à l'API » montre le corps exact envoyé ; si Vulnerability Management refuse les filtres de tags, l'application s'arrête avec un message plutôt que d'ignorer le périmètre.

### Envoyer un rapport par courriel (SMTP)

1. Onglet **Configuration**, section « Courriel », carte « Serveur SMTP » : serveur, port, chiffrement (STARTTLS, SSL/TLS ou aucun pour un relais interne), identifiants éventuels et adresse d'expédition. « Tester la connexion » ouvre une session et s'authentifie sans envoyer de message. Le mot de passe peut venir de `SMTP_PASSWORD`.
2. Même section, carte « Message par défaut » (propre au profil) : destinataires habituels, objet et texte. Variables : `{titre}`, `{client}`, `{date}`, `{fichier}`.
3. L'envoi est toujours optionnel. Dans **Générer**, étape 3, « Générer le rapport » ne produit que le fichier ; « Générer et envoyer par courriel » (visible une fois le serveur SMTP configuré) l'envoie aussi aux destinataires du profil. Si l'envoi échoue, le rapport est conservé et un lien « Réessayer » ouvre le formulaire d'envoi, de même que le lien « Envoyer » de la liste des rapports (destinataires modifiables). Le rapport part en pièce jointe (25 Mo maximum). Rien n'est envoyé sans l'un de ces choix explicites.

### Exporter les données depuis Security Center (méthode manuelle)

1. Ouvrez Analysis > Vulnerabilities.
2. Choisissez la vue « Vulnerability List ».
3. Appliquez vos filtres.
4. Cliquez sur Export, puis « Export as CSV ».

Colonnes nécessaires : `Plugin`, `Plugin Name`, `Severity`, `IP Address`. Colonnes conseillées : `DNS Name`, `NetBIOS Name`, `Family`, `VPR`, et `Solution` pour les intitulés sans règle.

## Modèles de rapport

| Modèle | Format | Contenu |
|---|---|---|
| Plan de remédiation complet | PDF | Synthèse graphique, plan d'action, détail par solution avec les machines concernées, guide par machine, annexe |
| Synthèse exécutive | PDF | 3 pages pour la direction : indicateurs, graphiques, 10 actions prioritaires, recommandations |
| Fiches par machine | PDF | Sommaire puis une fiche autonome par machine : actions à cocher, vulnérabilités corrigées, cadre de suivi de l'intervention |
| Comparaison de deux exports | PDF | Évolution du score de risque, vulnérabilités corrigées, nouvelles et persistantes, avancement par solution et par machine |
| Exposition PHP2Shell | PDF | Rapport thématique sur les failles PHP CVE-2026-109618 et CVE-2026-109619 : situation de la menace, machines concernées classées par priorité (AES, ACR, service joignable), plan d'action, mesures provisoires, vérification de compromission, fiabilité de la détection, couverture des 43 plugins Nessus, sources |
| Plan d'action Excel | XLSX | Suivi des solutions (responsable, échéance, statut), statut par machine, détail des vulnérabilités, indicateurs d'avancement recalculés automatiquement |

Pour la comparaison, chargez d'abord l'export précédent, puis l'export récent. Les deux sont analysés avec le même périmètre et les mêmes règles. Une vulnérabilité n'est comptée comme corrigée que si sa machine figure dans les deux exports.

## Règles de traduction

Les règles transforment les intitulés Tenable en actions regroupées. Elles sont stockées dans le dossier `regles/` : `base.csv` (identifiant, clé de regroupement, famille et motif, communs à toutes les langues) et `textes_<langue>.csv` (titre, action et commentaire de chaque langue). Elles couvrent notamment :

- les systèmes Linux et Unix ;
- Windows ;
- les éditeurs qui publient des avis : Cisco, Fortinet, Palo Alto, Juniper, F5, Check Point, Citrix, SAP, IBM ;
- les systèmes industriels ;
- les configurations courantes : TLS, SSH, SMB, SNMP, etc. ;
- des règles génériques, par exemple « Produit < version » qui donne « Installer Produit en version X ou ultérieure ».

L'onglet Règles permet de :

- tester un ou plusieurs intitulés, y compris avec des modifications non encore enregistrées ;
- reprendre en un clic les intitulés de l'export chargé qui n'ont pas de règle ;
- créer une règle pré-remplie à partir d'un intitulé non reconnu ;
- modifier, réordonner ou supprimer des règles ;
- importer ou exporter le fichier, pour l'éditer dans Excel (séparateur point-virgule).

La première règle qui correspond l'emporte. Chaque enregistrement conserve l'ancien fichier sous le nom `regles_fr.csv.bak`.

Champs utilisables dans le titre et l'action d'une règle :

| Champ | Contenu |
|---|---|
| `{produit}`, `{kb}`, `{os}`, `{ms}`, `{famille}` | Valeurs extraites de l'intitulé par les groupes nommés du motif |
| `{paquets}`, `{avis}`, `{notes}`, `{bulletins}`, `{cves}` | Listes cumulées sur toutes les vulnérabilités de la solution |
| `{cible}` | « en version X ou ultérieure », d'après les intitulés « Produit < X » |
| `{precision}` | « (version X ou ultérieure) » si une version est citée, sinon vide |
| `{branches}` | Versions correctives des autres branches citées dans l'intitulé |
| `{ref_avis}` | « (avis : …) » si l'intitulé cite des références d'avis éditeur |
| `{mois}` | Mois de publication le plus récent, en français |
| `{redemarrage}` | Phrase de redémarrage quand le noyau est concerné |

Le classement reprend par défaut la pondération de Security Center : Critique 40, Élevée 10, Moyenne 3, Faible 1. Le « % du risque » est calculé par l'outil, il n'est pas lu dans l'API. L'onglet Périmètre propose trois pondérations, avec une note dépliable qui détaille le calcul : **par sévérité** (défaut) ; **par VPR** (chaque vulnérabilité pèse son VPR, de 0,1 à 10, ou la médiane de sa sévérité : 9,5 · 8,0 · 5,5 · 2,0 s'il manque) ; **par VPR et ACR** (VPR × ACR / 10 : l'importance de la machine s'ajoute, avec la valeur par défaut de Tenable, 5, si l'ACR manque). Le « % du risque » d'une solution est la part de son poids dans le poids total du périmètre retenu. La pondération modifie le « % du risque » et l'ordre des solutions, pas le score par machine ni la comparaison de deux exports. Un export VM en CSV n'a pas d'ACR : la pondération par VPR et ACR y donne le même classement que par VPR. Les versions cibles sont déduites des intitulés Tenable : faites relire le plan d'action par l'équipe technique avant diffusion.

## Génération en ligne de commande

Pour automatiser, sans ouvrir l'interface, utilisez le Python de `.venv` :

```
python generer.py export.csv --modele synthese --profil nom-du-profil
python generer.py ancien.csv recent.csv --modele comparaison --sortie evolution.pdf
python generer.py --securitycenter --profil nom-du-profil --mail defaut
python generer.py ancien.csv --securitycenter --modele comparaison --profil nom-du-profil
```

`--securitycenter` récupère l'export via l'API avec la requête du profil (pour une comparaison, il remplace l'export récent). `--mail` envoie le rapport aux adresses données, séparées par des virgules, ou aux destinataires du profil avec `--mail defaut`. Ces options se prêtent à une tâche planifiée (cron, planificateur Windows).

Modèles disponibles : `complet`, `synthese`, `fiches`, `comparaison`, `plan_excel`. Le profil est le nom du fichier dans `profils/`, sans l'extension `.json`.

## Contenu du dossier

| Élément | Rôle |
|---|---|
| `app.py` | Serveur local et interface |
| `generer.py` | Génération en ligne de commande |
| `moteur/` | Analyse des exports, règles, graphiques et modèles de rapport (`moteur/modeles/`), client Security Center (`securitycenter.py`), envoi SMTP (`courriel.py`) et configuration (`config.py`) |
| `config.json` | Connexion Security Center et serveur SMTP (créé à l'enregistrement, droits restreints) |
| `exports_security_center/` | Exports récupérés via l'API, conservés pour les comparaisons |
| `web/` | Interface (HTML, CSS, JavaScript ; aucune ressource externe) |
| `regles/` | Règles : `base.csv` (regroupement, commun) et `textes_<langue>.csv` (textes par langue) |
| `profils/` | Profils clients : habillage, périmètre et logo |
| `rapports/` | Rapports générés |
| `polices/` | Polices Inter et DejaVu, libres de droits (licences jointes) |

### Ajouter un modèle de rapport

1. Créez un fichier dans `moteur/modeles/` avec une fonction `generer(analyse, habillage, sortie)`. Pour un modèle à deux exports, la signature est `generer(avant, apres, habillage, sortie)`.
2. Déclarez ce fichier dans `moteur/modeles/__init__.py`.

Les blocs de mise en page communs (couverture, tableaux, pastilles de sévérité, indicateurs) se trouvent dans `moteur/commun.py`.

## ACR et AES

Si l'export contient les colonnes `ACR` (criticité de la machine, 1 à 10) et `AES` (exposition, 0 à 1 000), ou si les données viennent de l'API Security Center (champs `acrScore` et `assetExposureScore`), elles sont affichées par machine dans les rapports PDF (plan complet, fiches) et dans le classeur Excel. L'AES est la note d'une machine ; le **Cyber Exposure Score (CES)** est la note d'exposition d'un ensemble de machines, sur la même échelle (0 à 1 000) : les rapports l'estiment par la moyenne des AES des machines analysées (une machine, une voix). Les définitions de VPR, ACR, AES et CES figurent en annexe des rapports et dans la feuille « Définitions » du classeur. Sans ces colonnes, rien ne change.

### Modèle « Exposition PHP2Shell »

Il isole dans l'export les constats qui citent CVE-2026-109618 ou CVE-2026-109619, ainsi que les 43 plugins Nessus publiés pour ces failles (liste dans `moteur/modeles/php2shell.py`). Aucun filtre n'est appliqué : toutes les machines concernées sont listées, quels que soient leur AES et leur ACR (affichés et utilisés pour le tri seulement), et le filtre de sévérité du profil est ignoré pour ce modèle (y compris pour la récupération par l'API Security Center). Chaque machine reçoit un niveau de preuve (confirmée, sans correctif éditeur, à confirmer) et une priorité : 1 (immédiate) pour une faille confirmée ou sans correctif éditeur, 2 (à vérifier) pour un constat à confirmer, déduit de la bannière d'un scan non authentifié. Le point de situation, les mesures provisoires et la liste de vérification de compromission sont rédigés à la date du 25 octobre 2026 à partir des avis de PHP et d'analyses publiées (annexe C) ; relisez-les avant de diffuser un rapport plus tardif. Le rapport signale aussi les cas où l'absence de constat ne prouve rien (export antérieur aux plugins, scan non authentifié ou par agent, PHP embarqué).

## Langues (français, anglais, espagnol, italien)

Le sélecteur à côté de la gestion des profils (drapeau) change la langue de l'interface **et** des rapports : la langue est enregistrée dans le profil, chaque client peut donc avoir la sienne. Les textes par défaut du profil (titre, pied de page, message du courriel) suivent la langue tant qu'ils n'ont pas été personnalisés.

- Interface : catalogues dans `web/langues/parts/*_<langue>.json`.
- Rapports et messages : catalogues dans `moteur/langues/*.json` (clé = texte français).
- Règles de remédiation : le regroupement (motifs, clés) est commun à toutes les langues (`regles/base.csv`) ; les textes sont dans `regles/textes_<langue>.csv`. L'anglais est la langue de référence : un texte absent dans une langue est repris de l'anglais, puis du français. L'onglet Règles édite les textes de la langue active ; modifier un motif ou une clé s'applique à toutes les langues. Au premier lancement, les anciens fichiers `regles_<langue>.csv` sont convertis automatiquement (vos modifications sont conservées) puis renommés en `.migre`.
- En ligne de commande : `python generer.py export.csv --langue en` (par défaut, la langue du profil).

Pour ajouter une langue : l'ajouter dans `moteur/i18n.py` (LANGUES, MOIS) et `web/i18n.js` (LANGUES, drapeau), puis fournir les catalogues et le fichier de règles.

## Exemples de rapports

Dans l'onglet Générer, le bouton « Voir un exemple » de chaque modèle ouvre le rapport page par page (vignettes à gauche, clic sur la page pour l'agrandir, flèches du clavier pour naviguer ; feuilles Excel pour le plan d'action Excel). L'exemple est produit par le vrai moteur à partir de **données fictives**, avec l'habillage (logo, couleurs, filigrane, mention) et la langue du profil actif : il donne donc un rendu fidèle de ce que vous obtiendrez. Les images demandent la bibliothèque `pypdfium2` (`pip install -r requirements.txt`) ; sans elle, le PDF d'exemple reste consultable.

## Thème Atelier ou Tenable

Le bouton **Thème**, en haut à droite, bascule l'apparence de l'application **et** des rapports (PDF et plan d'action Excel). Le réglage appartient à l'application (`config.json`, section `interface`), pas au profil.

- **Atelier** (défaut) : la couleur principale et le logo du profil client pilotent les rapports.
- **Tenable** : charte graphique Tenable. Police Aeonik (Light pour les grands titres, Regular pour le texte, Medium pour les titres, Semibold au plus), Soft Black et gris neutres, coins droits, aucune ombre, aucun dégradé. La couleur principale du profil est remplacée par la charte ; le logo du profil est conservé, sinon le logo Tenable est utilisé. La couverture est **blanche** par défaut ; une couverture **sombre** (Soft Black) est possible dans l'onglet Habillage, et le dernier mot du titre est surligné par la bande Hilighter, seul emploi du jaune dans un rapport (texte Soft Black sur la bande). Les couleurs de sévérité des graphiques et des pastilles restent des couleurs de données.

La police Aeonik est commerciale et n'est pas fournie avec le projet : déposez `Aeonik-Light.ttf`, `Aeonik-Regular.ttf`, `Aeonik-Medium.ttf` et `Aeonik-SemiBold.ttf` dans `polices/` pour l'utiliser. Sans ces fichiers, le thème Tenable utilise Inter.

En ligne de commande, `--theme atelier` ou `--theme tenable` prend le pas sur le réglage de l'application pour un rapport. Dans le plan d'action Excel, la police est Aeonik : si elle n'est pas installée sur le poste qui ouvre le classeur, Excel la remplace.

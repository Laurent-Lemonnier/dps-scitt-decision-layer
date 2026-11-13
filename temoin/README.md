# Témoin externe de ts.isoluce.net

`temoin.py` observe le journal de transparence SCITT https://ts.isoluce.net (RFC 9943, reçus RFC 9942, arbre de
Merkle RFC 9162) depuis l'extérieur de l'infrastructure qui l'héberge : il tourne toutes les heures dans GitHub
Actions (`.github/workflows/temoin-ts-isoluce.yml`). Il est écrit d'après le texte des RFC et ne partage aucun code
avec le service. Dépendances : Python 3, `cbor2`, `cryptography`.

## Ce qu'il fait

1. Il lit la tête signée (`/checkpoint.cose`, `/checkpoint.json`) et vérifie sa signature Ed25519 avec la clé
   **épinglée** `service-public.pem` (SHA-256 du fichier `ede4331bd17019c144df0f3778345dbf39bde69009140647a3e1822994b88915`,
   kid RFC 9679 `g3JYRtHgACp0biv12cMhoDDEGxDjRRDIv9UoWb0kjDA`). La version JSON doit dire la même chose que la version COSE.
2. Il compare cette tête à la dernière qu'il a vue, dans `temoin/tetes.jsonl` (branche `temoin` du dépôt) :
   - aucune tête vue : il recalcule la racine à partir de toutes les empreintes de feuilles (`/entries`) ;
   - le journal a grandi : il vérifie la preuve de cohérence (`/consistency`, RFC 9162 §2.1.4.2) entre l'ancienne
     racine, **prise dans son propre fichier**, et la nouvelle racine signée ;
   - même taille : la racine doit être identique, sinon c'est une bifurcation (FORK) ;
   - taille plus petite : le journal a rétréci.
3. Si tout est vérifié et que la tête est nouvelle, il ajoute une ligne : taille, racine, `issued_at`, SHA-256 du
   checkpoint COSE, taille de départ de la preuve, méthode, heure du constat (UTC), identifiant d'exécution GitHub.
   Le job enregistre ce seul fichier (commit de `github-actions[bot]` sur la branche `temoin`).

En cas d'échec, rien n'est écrit, le job passe au rouge et les réponses du service sont gardées 90 jours dans
l'artefact `preuves` de l'exécution. Codes de sortie : 1 service injoignable ou réponse illisible, 2 tête signée
invalide, 3 preuve de cohérence invalide, 4 racine divergente (FORK), 5 journal rétréci.

## Ce qu'il ne fait pas

- Il ne cosigne pas : il n'a pas de clé. Ce qui fait foi, c'est l'historique git de la branche `temoin` et les
  journaux d'exécution de GitHub Actions, que l'opérateur du service ne contrôle pas.
- Il ne vérifie pas le contenu des déclarations enregistrées, seulement les empreintes de feuilles et l'arbre.
- Il ne protège pas contre une vue différente servie à d'autres lecteurs : il compare ce qu'il voit à ce qu'il a
  vu, pas à ce que d'autres voient. Plusieurs témoins, ou la comparaison des lignes publiées ici avec les têtes
  que vous obtenez vous-même, couvrent ce cas.
- Il n'observe le journal qu'à chaque exécution : GitHub peut retarder ou sauter une exécution planifiée.

## Rejouer soi-même

```sh
git clone https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer.git && cd dps-scitt-decision-layer
python3 -m venv /tmp/v && /tmp/v/bin/pip install cbor2 cryptography
# chaque tête enregistrée par le témoin doit être un préfixe du journal actuel :
git show origin/temoin:temoin/tetes.jsonl > /tmp/tetes.jsonl
/tmp/v/bin/python temoin/temoin.py --tetes /tmp/tetes.jsonl --rejouer
# ou un témoin à vous, qui part de zéro (recalcul complet), puis suit le journal :
/tmp/v/bin/python temoin/temoin.py --tetes ma-copie.jsonl
```

Vérifier la clé épinglée sans faire confiance à ce dépôt : `sha256sum temoin/service-public.pem`, et comparer la clé
à celle que publie le service (`https://ts.isoluce.net/jwks`, `/.well-known/scitt-keys`).

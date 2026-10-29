# Rejeu indépendant du corpus de Gilda (draft-gilda-audit-agent-audit-record-02) — 29/10/2026

## Résultat

`gilda_verify_independent.py` est un vérificateur écrit à partir du texte du brouillon (sections 4 et 5) et des clés
de test publiées dans le MANIFEST du corpus. Il n'importe rien du paquet `agent-evidence-vectors` et ne partage aucun
code avec son rail de référence. Passé sur le corpus `vectors-agent-audit-record` de la version 0.28.0 (141 membres :
59 accept, 81 reject, 1 indeterminate) :

- **141/141 membres concordent** avec le MANIFEST sur le verdict, les codes de refus (intersection non vide), le tier
  dérivé, `withinLimit` et les vérifications d'ensemble (CS7, CS8, CS17, SQ4, SQ5).
- **Le premier code de refus concorde sur 81/81 membres reject**, bien que le brouillon ne définisse pas de codes
  (ce sont les noms publiés par le corpus) et que l'ordre des règles soit le nôtre, pris du §4.6.
- **Non tenté** : la validation des ancres (transparency-log, opentimestamps) des enregistrements retenus (§4.7.2),
  donc `datedAt` et les contrôles de fourchette qui ont besoin d'une heure d'ancre : R3, R7, R11
  (`entry-received-after-anchor`, `entry-anchor-late`). Les 13 autres membres R concordent sur ce qui ne demande pas
  d'ancre (digest d'enveloppe, `received`/`receivedAt`, présence d'une ancre du conservateur, `receivedAt` contre
  `issuedAt`, élément de racine de délégation R13/R14/R15).

Commande : `python gilda_verify_independent.py --corpus <…>/corpora/vectors-agent-audit-record --report judge-20261029.json`
Rapport : `judge-20261029.json` (une ligne par membre : attendu, obtenu, codes, tier, notes).

## Rail de référence du paquet (contrôle préalable)

`agent-evidence-vectors --corpus vectors-agent-audit-record` (rail livré) : « every member behaves as MANIFEST.json
declares », sortie dans `run-20261029.txt`. Ce n'est pas une vérification indépendante ; c'est le rejeu ci-dessus qui l'est.

## Ce que la lecture du texte a montré

- Le brouillon est suffisamment précis pour qu'un vérificateur écrit à partir du texte reproduise 141 verdicts sans
  consulter le code de référence ; les seuls points pris hors du texte sont la constante « arbre vide » (SHA-256 d'un
  objet tree git vide, 6ef19b41…) et la tolérance d'écart de 300 s (toutes deux dans le MANIFEST).
- Règle d'ensemble CS7/CS17 (révision périmée) : la lecture qui concorde est « un permit qui a lu une révision plus
  ancienne qu'un enregistrement qui tenait déjà un permit non réglé, et qui l'omet de son propre `held` », sans
  condition sur la date d'émission du permit tenu (son enregistrement d'origine n'est pas dans l'ensemble).
- Le paquet livre 41 corpus. Pour le raccordement DPS, lire ensuite `vectors-approval-binding`, `vectors-agent-decision`
  et `vectors-authority-at-dispatch`.

## Reste à faire pour une conformité complète

Validation des ancres : inclusion transparency-log vers les têtes d'arbre du MANIFEST (`anchorTrust`), preuves
OpenTimestamps vers les en-têtes de blocs épinglés (bibliothèque `opentimestamps` à installer), jetons RFC 3161 (aucun
dans le corpus actuel). Puis `datedAt` et les codes R3, R7, R11.

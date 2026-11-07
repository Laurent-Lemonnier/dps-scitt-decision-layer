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

## Rejeu du 31/10/2026 : -03, corpus 0.31.0, ancres validées

Le vérificateur a été étendu, toujours à partir du texte (-03 et, pour les règles que le brouillon ne porte pas, le
README publié du corpus), sans rien importer du paquet :

- **Ancres (§4.7.2), hors ligne, contre ce que le MANIFEST épingle comme tenu indépendamment** (`anchorTrust`) :
  transparency-log = TransItem RFC 9162 de type `inclusion_proof_v2` (0x0106), feuille `SHA-256(0x00 || envelopeDigest)`,
  racine recalculée par §2.1.3.2 vers une tête d'arbre du journal de test (deux têtes partagent la taille 3 : on essaie
  chacune) ; opentimestamps = sérialisation OpenTimestamps lue (magie, version, sha256, append/prepend/sha256/fork/
  attestation), rejouée le long de chaque attestation Bitcoin vers la racine de Merkle de l'en-tête épinglé à la hauteur
  nommée, heure = champ time de l'en-tête ; attestation pendante = rien ; rfc3161 = non tenté (aucun dans le corpus,
  aucun chemin de certification tenu).
- **Datation (§4.7.1) complète** : `datedAt` (ancre validée la plus ancienne, toute origine ; entre deux ancres
  opentimestamps on compare les hauteurs), heure de rétention (origine `retainer`), `entry-received-after-anchor`,
  `entry-anchor-late` avec les 7 200 s à la place de la tolérance quand l'heure est celle d'une ancre opentimestamps,
  `receipt: asserted-consistent`, racine de délégation. Les codes de l'entrée s'accumulent sans arrêter la datation
  (R9, X12, X13) ; une entrée dont la forme est illisible n'est pas datée (X11).
- **Règles du -03** : `issued-before-sealed` (IS1, IS2) ; URI de prédicat v2 avec `principal-standing-source` (§8) ;
  constante « arbre vide » **telle que le texte la donne** (SHA-256 de la chaîne vide, e3b0c442…) ; X16 (membre retenu
  sans entrée) = `retained-unreadable`.
- **Règles du README du corpus, absentes du texte** : codes fins X1–X10 (`value-not-representable`, `not-parseable`,
  `timestamp-malformed`, `statement-type-unexpected`, `predicate-type-mismatch`, `envelope-unreadable`, `statement-shape`,
  `subject-request-mismatch`), `operation-key-invalid` (X7), entrée `held` à trois membres (X6), `supersedes` (CS23,
  CS24), `asset` CAIP-19 / `unit` jamais les deux (CS34–CS37), registres liés par `supersedes` (CS18–CS25), réclamation
  clé = principal + clé d'agent + clé d'opération, fin par `none`/`occurred` (CS26–CS33), une dénomination par registre
  (CS38–CS40), `set-record-malformed` (X18).

Résultats (`run-20261031.txt`, `judge-20261031-0.31.0.json`, `judge-20261031-0.28.0.json`) :

- **0.31.0 : 184/184** concordent (verdict, codes, tier, `withinLimit`, ensembles, et pour les 22 membres retenus tout le
  bloc de datation : codes, `datedAt`, `entry`, `receipt`, racine) ; premier code de refus 101/101. R3, R7, R10, R11, R12,
  R16 sont des résultats : R3 daté 11:04:20 + `entry-received-after-anchor`, R7 daté 11:14:12 + `entry-anchor-late`, R11
  daté 09:04:29 (bloc 880000) à 7 201 s, R10 dans la marge, R12 daté au bloc de la preuve mise à niveau (880016), R16 par
  l'arbre du conservateur. 0 ancre non tentée.
- **0.28.0 : 141/141**, premier code 81/81 : rien n'a bougé sur ce qui concordait déjà (régression nulle).

Ensemble enregistré `hs51-set2` (`vectors-recorded`, run réel du 22/10/2026) : sa seule liaison, `log/checkpoint.stamp.ots`
sur `log/checkpoint.json` (SHA-256 afd5d289…), rejouée sans logiciel OpenTimestamps (`../umarise/verify_anchor.py`,
route 2) contre 27 en-têtes mainnet 972540–972566 pris chez blockstream.info et mempool.space (hash de bloc identiques
sur les 27), preuve de travail et chaînage vérifiés, checkpoint 972540 : **valide**, deux attestations Bitcoin
recalculent (972551, 972552), bloc le plus bas 972551, heure d'en-tête 2026-10-22T01:33:25Z (déclaration du mineur),
16 confirmations dans la vue tenue. Ça montre que les octets du checkpoint existaient avant ce bloc ; rien sur le
contenu du journal ni sur le règlement. Le contrôle propre du paquet (`recorded check`) répond verified/pinned
(sommes et en-tête de preuve seulement). Dossier : `recorded-hs51-set2/`.

À signaler à l'auteur : (1) CS18–CS40 et les codes X sont définis par le README/MANIFEST, pas par le -03 ; (2) la
constante « arbre vide » diffère entre le texte (e3b0c442…) et le MANIFEST (6ef19b41…, arbre git vide), sans vecteur
qui tranche (E3 porte la constante sha1 et échoue dans les deux lectures) ; (3) hypothèse hors texte : les ancres sont
lues sur le digest recalculé de l'enveloppe, pas sur la valeur déclarée (X12 daté et noté).

## Rejeu du 07/11/2026 : -03, corpus 0.35.0, membres x402 consumption

Le premier passage du 07/11 (`run-20261107.txt`) donnait 184/193 à la version 0.35.0 : les neuf membres en désaccord
étaient CS41 à CS49, un paiement x402 réglé sur la chaîne à côté d'un permit « upto », que le vérificateur lisait tous
`consumption-malformed`. Lecture du texte avant toute modification :

- **Le -03 ne porte pas ces membres.** Le §5.9 dit que `consumption` « MUST carry each of these members and no other
  (vector CS9) » : `limitDigest`, `unit`, `limit`, `consumed`, `reserved`, `requested`, `held`, `stateRevision` ; une
  entrée `held` porte « that permit's operationKey, requestDigest and amount ». Ni `payee`, ni `settled`, ni x402, ni
  aucun des quatre codes n'y figurent (`consumption-key-reused` est aussi un nom du corpus). Le §5.9 du -02 et celui du
  -03 ne diffèrent que par la phrase sur CS7/CS17 ; ce n'est donc pas un écart -02/-03. À la lettre du -03, lire CS43 à
  CS49 `consumption-malformed` était la lecture juste ; le chemin de code n'avait simplement jamais été exercé par un
  vecteur publié (aucun dans 0.31.0).
- **Les membres viennent du README du corpus** (0.35.0, « Consumption state and the operation key: CS1 to CS49 »), qui
  écrit CS41–CS49 comme « rows written for revision 04 » — aucun -04 n'est publié au 07/11 (404 sur ietf.org). Le
  vérificateur les lit donc à partir de ce README seul, comme il le fait déjà pour CS18–CS40 et les codes X, sans
  ouvrir le code du lecteur de référence : `consumption.payee` et `payee` sur chaque entrée `held` = SHA-256 de
  l'identifiant de compte CAIP-10 du bénéficiaire ; un retry paie le bénéficiaire de l'entrée tenue (CS41), signé à
  nouveau vers un autre bénéficiaire dans le même appel c'est `consumption-key-reused` (CS42) ; `consumption.settled`
  porte exactement `amount`, `asset`, `payee`, `source`, `transaction`, les termes réglés lus sur la chaîne par la
  transaction rendue par le serveur (`source` = `chain`), à côté des termes approuvés `requested`, `asset`, `payee` ; un
  « upto » réglé sous son maximum est valide (CS43), au-dessus `consumption-settled-exceeds` (CS44), autre actif ou autre
  bénéficiaire `consumption-settled-differs` (CS45, CS46), termes lus dans la charge signée
  `consumption-value-invalid` (CS47) ; `consumed` prend le montant réglé : un enregistrement postérieur du registre qui ne
  tient plus l'appel compte au moins le `consumed` lu par l'enregistrement qui règle plus le montant réglé (CS48), moins
  c'est `consumption-set-settled-uncounted` (CS49), plus est permis.

Ce qui a changé dans `gilda_verify_independent.py` (paragraphe daté du 07/11/2026 dans sa docstring) :

- `payee` et `settled` admis dans `consumption`, `payee` admis dans une entrée `held` (X6 reste à trois membres + payee) ;
  un `payee` est un digest de 64 hex, sinon `consumption-value-invalid` (l'identifiant CAIP-10 n'est pas dans
  l'enregistrement, seule la forme est contrôlée ; vérifié à la main que les digests de P et Q des vecteurs sont bien
  SHA-256 de `eip155:84532:<adresse EIP-55>`).
- `settled` : forme exacte (`consumption-malformed`), valeurs (`amount` entier ≥ 0, `asset` de forme CAIP-19, `payee`
  digest, `transaction` chaîne non vide, `source` ≠ `chain` → `consumption-value-invalid`), puis `amount` > `requested` →
  `consumption-settled-exceeds`, `asset` ≠ `consumption.asset` ou `payee` ≠ `consumption.payee` →
  `consumption-settled-differs` (absent compte comme différent).
- Retry (clé propre tenue) dont l'entrée tenue nomme un bénéficiaire : `consumption.payee` doit être le même, sinon
  `consumption-key-reused`.
- Contrôle d'ensemble par registre : tout enregistrement postérieur qui ne tient plus la clé de l'enregistrement
  réglant compte `consumed` ≥ son `consumed` + `settled.amount`, sinon `consumption-set-settled-uncounted`.
- `withinLimit` inchangé (la réserve est `requested` : CS43 à 42 sur 50 USDC) ; rien ne lie `settled` à
  `effect.observed`, le README ne le fait pas.

Lectures prises là où le README laisse un choix, aucune tranchée par un vecteur : validité des valeurs avant les
comparaisons (un `settled` lu dans la charge signée n'est pas un règlement, on n'en dérive ni exceeds ni differs) ;
toute valeur de `source` autre que `chain` lue comme `signed-payload` ; absence de `payee` ou d'`asset` approuvé
comptée comme différence ; entrée tenue sans `payee` comparée comme avant (clé, digest, montant).

Résultats (`run-20261107b.txt`, `judge-20261107-0.35.0.json`) :

- **0.35.0 : 193/193** (85 accept, 1 indeterminate, 107 reject ; corpusDigest 47fab839…), premier code de refus
  106/106 ; les neuf membres CS41–CS49 concordent, CS48 ensemble valide, CS49 ensemble
  `consumption-set-settled-uncounted`. Harnais du paquet : « every member behaves as MANIFEST.json declares ».
- **Régression 0.31.0 : 184/184**, premier code 101/101 ; **0.28.0 : 141/141**, 81/81 ; approval-binding 23/23 à
  0.31.0 et les 12 tests d'agrégation inchangés.
- **Désaccord honnête restant : aucun au niveau des membres.** Au niveau du texte : CS41–CS49 ne sont pas dans le -03 ;
  un vérificateur de la lettre du -03 les refuse (`consumption-malformed`), comme le premier passage. À ajouter au point
  (1) de la liste pour l'auteur ci-dessus : CS41–CS49 aussi, écrits pour un -04 non publié.
- L'épingle de CI passe à 0.35.0 dans le même commit (`interop/requirements-gilda.txt`, commentaire de `run.sh`) :
  les deux vérificateurs concordent en entier avec cette release ; 0.31.0 et 0.28.0 restent des rejeux de régression.

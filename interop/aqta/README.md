# Rejeu indépendant des vecteurs Seal (Aqta, draft-chueayen-attestation-receipts-05) — 29/10/2026, rejoué le 07/11/2026

## Rejeu du 07/11/2026 (commit `5c38c71` du 29/10/2026)

Cinq commits depuis le pin `9c28d49` : `CHANGELOG.md`, `spec/ATTESTATION-v1.md` §4 et `spec/GRANT-v1.md` ; aucun
vecteur modifié. Le §4 dit désormais que les identifiants de `policy_applied` peuvent contenir tout caractère Unicode et
que l'ordre par unité de code UTF-16 est la règle normative (l'ambiguïté du point 1 ci-dessous, corrigée par l'auteure
avec crédit à ce rapport). GRANT-v1 gagne un membre optionnel `approver_policy_sha256` (SHA-256 des octets canoniques de
la politique d'approbateur, §7.2), « prompted by the approval-record interoperability example built against ACTION-v1
section 8.3 » ; le profil GRANT-v1 n'est pas couvert par ce vérificateur. Vérificateur inchangé : ATTESTATION-v1
**33/33**, ACTION-v1 **34/34** (`run-attestation-20261107.txt`, `run-action-20261107.txt`, identiques ligne à ligne aux
sorties du 29/10). Pin déplacé à `5c38c71`.

## Résultat

`aqta_verify_independent.py` est un vérificateur écrit à partir des seuls textes `spec/ATTESTATION-v1.md` (§4–§7) et
`spec/ACTION-v1.md` (§4–§7) du dépôt `Aqta-ai/attestation-spec` (clone du 29/10/2026, release 1.4.0). Il ne partage
aucun code avec les vérificateurs de référence (Python et TypeScript). Clés épinglées : celles publiées dans
`test-vectors/README.md` et `test-vectors/action/README.md`.

| Profil | Vecteurs | Concordance | Sortie |
|---|---|---|---|
| ATTESTATION-v1 | 10 valides + 23 adverses | **33/33** | `run-attestation-20261029.txt` |
| ACTION-v1 | 11 valides + 23 adverses | **34/34** | `run-action-20261029.txt` |

C'est la « verifier conformance » telle que `CONFORMANCE.md` la définit (chaque `valid/` → valide, chaque `invalid/` →
invalide, sans jamais lever d'exception). Non couverts : les suites `chain/`, `complete/`, `transparency/`, `witnessed/`,
`acceptance/`, `bytes/` (autres profils du dépôt).

## Ce que la lecture du texte a montré

1. **Ambiguïté ATTESTATION-v1 §4** : la table décrit `policy_applied` comme « Sorted JSON array of ASCII policy
   identifiers » et ajoute « the restriction to ASCII is what keeps them so », mais n'énonce aucun MUST sur l'ASCII, et
   le vecteur `valid/007-non-ascii-policy` contient des noms non ASCII et doit être accepté. Un lecteur qui prend la
   phrase du §4 comme une exigence rejette ce vecteur (c'est ce qu'a fait la première version de ce vérificateur).
   À signaler à l'auteur : soit retirer « ASCII » du §4, soit faire du vecteur un cas invalide.
2. ACTION-v1 est entièrement reproductible depuis le texte : pas de nombre, tri UTF-16, UTF-8 littéral, motifs
   « valeur entière » à chiffres ASCII. Les 23 cas adverses ont tous été distingués par les règles écrites.
3. Le `cost_prevented_eur` d'ATTESTATION-v1 exige la sérialisation ECMA-262 des non-entiers (vecteur 008, `0.000015`) ;
   implémentée ici sans bibliothèque.

## Lien avec le DPS

Le §8 du brouillon (« Approval Bound to Exact Values ») énumère les propriétés d'une approbation humaine et dit ne pas
définir son format. L'étape `outcome` signée de l'action binding DPS 0.3.0 les satisfait : liaison au digest montré,
usage unique (`request_limit`), approbateur distinct du proposant, clé dans la politique de confiance. Il manque le
digest de la politique qui désigne l'approbateur, que le §8.2 demande « in a future approval record ». Prochaine étape :
un exemple où l'étape outcome joue le rôle de l'« approval record » du §8.3, référencée par le digest de ses octets
canoniques depuis un action record.

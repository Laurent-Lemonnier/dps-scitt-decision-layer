# Rejeu indépendant des vecteurs Seal (Aqta, draft-chueayen-attestation-receipts-05) — 29/10/2026

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
